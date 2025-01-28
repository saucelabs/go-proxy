// Copyright 2015 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package martian

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saucelabs/forwarder/internal/martian/log"
	"github.com/saucelabs/forwarder/internal/martian/martiantest"
	"github.com/saucelabs/forwarder/internal/martian/mitm"
	"github.com/saucelabs/forwarder/internal/martian/proxyutil"
	"go.uber.org/multierr"
)

var (
	withTLS     = flag.Bool("tls", false, "run proxy using TLS listener")
	withHandler = flag.Bool("handler", false, "run proxy using http.Handler")
)

type testHelper struct {
	Listener net.Listener
	Proxy    func(*Proxy)
}

func (h *testHelper) proxyConn(t *testing.T) (conn net.Conn, cancel func()) {
	t.Helper()
	c, cancel := h.proxyClient(t)
	return c.dial(t), cancel
}

func (h *testHelper) proxyClient(t *testing.T) (client client, cancel func()) {
	t.Helper()

	l, c := h.listenerAndClient(t)
	p := h.proxy(t)
	go h.serve(p, l)

	return c, func() { l.Close(); p.Shutdown(context.Background()) }
}

func (h *testHelper) listenerAndClient(t *testing.T) (net.Listener, client) {
	t.Helper()

	if h.Listener != nil {
		return h.Listener, client{Addr: h.Listener.Addr().String()}
	}

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	if !*withTLS {
		return l, client{Addr: l.Addr().String()}
	}

	s, c := h.certs(t)
	l = tls.NewListener(l, s)
	return l, client{Addr: l.Addr().String(), TLS: c}
}

func (h *testHelper) certs(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	ca, mc := certs(t)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	return mc.TLS(context.Background()), &tls.Config{ServerName: "example.com", RootCAs: roots}
}

func (h *testHelper) proxy(t *testing.T) *Proxy {
	t.Helper()

	p := new(Proxy)
	if h.Proxy != nil {
		h.Proxy(p)
	}
	return p
}

func (h *testHelper) serve(p *Proxy, l net.Listener) {
	if *withHandler {
		s := http.Server{
			Handler:           p.Handler(),
			ReadTimeout:       p.ReadTimeout,
			ReadHeaderTimeout: p.ReadHeaderTimeout,
			WriteTimeout:      p.WriteTimeout,
		}
		s.Serve(l)
	}

	p.Serve(l)
}

func certs(t *testing.T) (*x509.Certificate, *mitm.Config) {
	t.Helper()

	ca, priv, err := mitm.NewAuthority("martian.proxy", "Martian Authority", 2*time.Hour)
	if err != nil {
		t.Fatalf("mitm.NewAuthority(): got %v, want no error", err)
	}
	mc, err := mitm.NewConfig(ca, priv)
	if err != nil {
		t.Fatalf("mitm.NewConfig(): got %v, want no error", err)
	}
	return ca, mc
}

type client struct {
	Addr string
	TLS  *tls.Config
}

func (c *client) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", c.Addr)
	if err != nil {
		t.Fatalf("net.Dial(): got %v, want no error", err)
	}
	if c.TLS != nil {
		conn = tls.Client(conn, c.TLS)
	}
	return conn
}

type tempError struct{}

func (e *tempError) Error() string   { return "temporary" }
func (e *tempError) Timeout() bool   { return true }
func (e *tempError) Temporary() bool { return true }

type timeoutListener struct {
	net.Listener
	errCount int
	err      error
}

func newTimeoutListener(l net.Listener, errCount int) net.Listener {
	return &timeoutListener{
		Listener: l,
		errCount: errCount,
		err:      &tempError{},
	}
}

func (l *timeoutListener) Accept() (net.Conn, error) {
	if l.errCount > 0 {
		l.errCount--
		return nil, l.err
	}

	return l.Listener.Accept()
}

func TestIntegrationTemporaryTimeout(t *testing.T) {
	t.Parallel()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	h := testHelper{
		// A listener that will return a temporary error on Accept() three times.
		Listener: newTimeoutListener(l, 3),
		Proxy: func(p *Proxy) {
			p.RoundTripper = martiantest.NewTransport()
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	req.Header.Set("Connection", "close")

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}
}

func TestIntegrationHTTP(t *testing.T) {
	t.Parallel()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = martiantest.NewTransport()
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
			tm := martiantest.NewModifier()
			tm.ResponseFunc(func(res *http.Response) {
				res.Header.Set("Martian-Test", "true")
			})
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}

	if got, want := res.Header.Get("Martian-Test"), "true"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Martian-Test", got, want)
	}
}

func TestIntegrationHTTP100Continue(t *testing.T) {
	t.Parallel()

	if *withHandler {
		t.Skip("skipping in handler mode")
	}

	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ReadTimeout = 2 * time.Second
			p.WriteTimeout = 2 * time.Second
			p.AllowHTTP = true
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	go func() {
		conn, err := sl.Accept()
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		log.Infof(context.TODO(), "proxy_test: accepted connection: %s", conn.RemoteAddr())

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to read request: %v", err)
			return
		}

		if req.Header.Get("Expect") == "100-continue" {
			log.Infof(context.TODO(), "proxy_test: received 100-continue request")

			conn.Write([]byte("HTTP/1.1 100 Continue\r\n\r\n"))

			log.Infof(context.TODO(), "proxy_test: sent 100-continue response")
		} else {
			log.Infof(context.TODO(), "proxy_test: received non 100-continue request")

			res := proxyutil.NewResponse(417, nil, req)
			res.Header.Set("Connection", "close")
			res.Write(conn)
			return
		}

		res := proxyutil.NewResponse(200, req.Body, req)
		res.Header.Set("Connection", "close")
		res.Write(conn)

		log.Infof(context.TODO(), "proxy_test: sent 200 response")
	}()

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	host := sl.Addr().String()
	raw := fmt.Sprintf("POST http://%s/ HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Content-Length: 12\r\n"+
		"Expect: 100-continue\r\n\r\n", host, host)

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("conn.Write(headers): got %v, want no error", err)
	}

	go func() {
		<-time.After(time.Second)
		conn.Write([]byte("body content"))
	}()

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}

	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(): got %v, want no error", err)
	}

	if want := []byte("body content"); !bytes.Equal(got, want) {
		t.Errorf("res.Body: got %q, want %q", got, want)
	}

	if !tm.RequestModified() {
		t.Error("tm.RequestModified(): got false, want true")
	}
	if !tm.ResponseModified() {
		t.Error("tm.ResponseModified(): got false, want true")
	}
}

func TestIntegrationHTTP101SwitchingProtocols(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
			p.RequestModifier = tm
			p.ResponseModifier = tm
			p.AllowHTTP = true
		},
	}

	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	go func() {
		conn, err := sl.Accept()
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		log.Infof(context.TODO(), "proxy_test: accepted connection: %s", conn.RemoteAddr())

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to read request: %v", err)
			return
		}

		if reqUpType := upgradeType(req.Header); reqUpType != "" {
			log.Infof(context.TODO(), "proxy_test: received upgrade request")

			res := proxyutil.NewResponse(101, nil, req)
			res.Header.Set("Connection", "upgrade")
			res.Header.Set("Upgrade", reqUpType)

			res.Write(conn)
			log.Infof(context.TODO(), "proxy_test: sent 101 response")

			if _, err := io.Copy(conn, conn); err != nil {
				log.Errorf(context.TODO(), "proxy_test: failed to copy connection: %v", err)
			}
		} else {
			log.Infof(context.TODO(), "proxy_test: received non upgrade request")

			res := proxyutil.NewResponse(417, nil, req)
			res.Header.Set("Connection", "close")
			res.Write(conn)
			return
		}

		log.Infof(context.TODO(), "proxy_test: closed connection")
	}()

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	host := sl.Addr().String()

	req, err := http.NewRequest(http.MethodPost, "http://"+host, http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "binary")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 101; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
	if got, want := res.Header.Get("Connection"), "Upgrade"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Connection", got, want)
	}
	if got, want := res.Header.Get("Upgrade"), "binary"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Upgrade", got, want)
	}

	want := []byte("body content")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("io.ReadAll(): got %v, want no error", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("conn: got %q, want %q", got, want)
	}
}

func TestIntegrationHTTP304NotModified(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
			p.RequestModifier = tm
			p.ResponseModifier = tm
			p.AllowHTTP = true
		},
	}

	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	go func() {
		conn, err := sl.Accept()
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		log.Infof(context.TODO(), "proxy_test: accepted connection: %s", conn.RemoteAddr())

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to read request: %v", err)
			return
		}

		res := proxyutil.NewResponse(304, http.NoBody, req)
		res.Header.Set("Content-Length", "13")
		res.Write(conn)
		log.Infof(context.TODO(), "proxy_test: sent 304 response")

		log.Infof(context.TODO(), "proxy_test: closed connection")
	}()

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	host := sl.Addr().String()

	req, err := http.NewRequest(http.MethodGet, "http://"+host, http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 304; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
	if _, err := conn.Read(nil); err != nil {
		t.Fatalf("conn.Read(): got %v, want no error", err)
	}
}

func TestIntegrationUnexpectedUpstreamFailure(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ReadTimeout = 1000 * time.Second
			p.WriteTimeout = 1000 * time.Second
			p.AllowHTTP = true
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	go func() {
		time.Sleep(1 * time.Second)
		conn, err := sl.Accept()
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to accept connection: %v", err)
			return
		}
		defer conn.Close()

		log.Infof(context.TODO(), "proxy_test: accepted connection: %s\n", conn.RemoteAddr())

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			log.Errorf(context.TODO(), "proxy_test: failed to read request: %v", err)
			return
		}

		res := &http.Response{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       io.NopCloser(bytes.NewBufferString("body content")),
			// Content length is set as 13 but response
			// stops after sending 12 bytes
			ContentLength: 13,
			Request:       req,
			Header:        make(http.Header, 0),
		}
		res.Write(conn)
		conn.Close()

		log.Infof(context.TODO(), "proxy_test: sent 200 response\n")
	}()

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	host := sl.Addr().String()
	raw := fmt.Sprintf("POST http://%s/ HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"\r\n", host, host)
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("conn.Write(headers): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}

	got, err := io.ReadAll(res.Body)
	// if below error is unhandled in proxy, the test will timeout.
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("io.ReadAll(): got %v, want %v", err, io.ErrUnexpectedEOF)
	}

	if want := []byte("body content"); !bytes.Equal(got, want) {
		t.Errorf("res.Body: got %q, want %q", got, want)
	}

	if !tm.RequestModified() {
		t.Error("tm.RequestModified(): got false, want true")
	}
	if !tm.ResponseModified() {
		t.Error("tm.ResponseModified(): got false, want true")
	}
}

func TestIntegrationHTTPUpstreamProxy(t *testing.T) {
	t.Parallel()

	ul, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	upstream := testHelper{
		Listener: ul,
		Proxy: func(p *Proxy) {
			utr := martiantest.NewTransport()
			utr.Respond(299)
			p.RoundTripper = utr
			p.ReadTimeout = 600 * time.Millisecond
			p.WriteTimeout = 600 * time.Millisecond
		},
	}

	uc, ucancel := upstream.proxyClient(t)
	defer ucancel()

	proxy := testHelper{
		Proxy: func(p *Proxy) {
			p.AllowHTTP = true
			p.ProxyURL = http.ProxyURL(&url.URL{Host: uc.Addr})
			p.ReadTimeout = 600 * time.Millisecond
			p.WriteTimeout = 600 * time.Millisecond
		},
	}

	conn, cancel := proxy.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from upstream proxy.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 299; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
}

func TestIntegrationHTTPUpstreamProxyError(t *testing.T) {
	t.Parallel()

	reserr := errors.New("response error")
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ProxyURL = http.ProxyURL(&url.URL{Host: "localhost:0"})
			p.ReadTimeout = 600 * time.Millisecond
			p.WriteTimeout = 600 * time.Millisecond
			tm := martiantest.NewModifier()
			tm.ResponseError(reserr)
			p.ResponseModifier = tm
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// Response from proxy, assuming upstream proxy failed to CONNECT.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 502; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
	if got, want := res.Header["Warning"][1], reserr.Error(); !strings.Contains(got, want) {
		t.Errorf("res.Header.get(%q): got %q, want to contain %q", "Warning", got, want)
	}
}

func TestIntegrationTLSHandshakeErrorCallback(t *testing.T) {
	t.Parallel()

	// Test TLS server.
	_, mc := certs(t)
	var herr error
	mc.SetHandshakeErrorCallback(func(_ *http.Request, err error) { herr = errors.New("handshake error") })

	tl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("tls.Listen(): got %v, want no error", err)
	}
	tl = tls.NewListener(tl, mc.TLS(context.Background()))

	go http.Serve(tl, http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(http.StatusOK)
		}))

	tm := martiantest.NewModifier()

	// Force the CONNECT request to dial the local TLS server.
	tm.RequestFunc(func(req *http.Request) {
		req.URL.Host = tl.Addr().String()
	})

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.MITMConfig = mc
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	//
	// Rewritten to CONNECT to host:port in CONNECT request modifier.
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// CONNECT response after establishing tunnel.
	if _, err := http.ReadResponse(bufio.NewReader(conn), req); err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	tlsconn := tls.Client(conn, &tls.Config{
		ServerName: "example.com",
		// Client has no cert so it will get "x509: certificate signed by unknown authority" from the
		// handshake and send "remote error: bad certificate" to the server.
		RootCAs: x509.NewCertPool(),
	})
	defer tlsconn.Close()

	req, err = http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	req.Header.Set("Connection", "close")

	if got, want := req.Write(tlsconn), "x509: certificate signed by unknown authority"; !strings.Contains(got.Error(), want) {
		t.Fatalf("Got incorrect error from Client Handshake(), got: %v, want: %v", got, want)
	}

	// TODO: herr is not being asserted against. It should be pushed on to a channel
	// of err, and the assertion should pull off of it and assert. That design resulted in the test
	// hanging for unknown reasons.
	t.Skip("skipping assertion of handshake error callback error due to mysterious deadlock")
	if got, want := herr, "remote error: bad certificate"; !strings.Contains(got.Error(), want) {
		t.Fatalf("Got incorrect error from Server Handshake(), got: %v, want: %v", got, want)
	}
}

func TestIntegrationConnect(t *testing.T) { //nolint:tparallel // Subtests share tm.
	t.Parallel()

	// Test TLS server.
	ca, mc := certs(t)

	tl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("tls.Listen(): got %v, want no error", err)
	}
	tl = tls.NewListener(tl, mc.TLS(context.Background()))

	go http.Serve(tl, http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(299)
		}))

	tm := martiantest.NewModifier()

	// Force the CONNECT request to dial the local TLS server.
	tm.RequestFunc(func(req *http.Request) {
		req.URL.Host = tl.Addr().String()
	})

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	c, cancel := h.proxyClient(t)
	defer cancel()

	t.Run("ok", func(t *testing.T) {
		conn := c.dial(t)
		defer conn.Close()
		res := connect(t, conn)

		if got, want := res.StatusCode, 200; got != want {
			t.Fatalf("res.StatusCode: got %d, want %d", got, want)
		}
		if res.ContentLength != -1 {
			t.Fatalf("res.ContentLength: got %d, want -1", res.ContentLength)
		}

		if !tm.RequestModified() {
			t.Error("tm.RequestModified(): got false, want true")
		}
		if !tm.ResponseModified() {
			t.Error("tm.ResponseModified(): got false, want true")
		}

		roots := x509.NewCertPool()
		roots.AddCert(ca)

		tlsconn := tls.Client(conn, &tls.Config{
			ServerName: "example.com",
			RootCAs:    roots,
		})
		defer tlsconn.Close()

		req, err := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
		if err != nil {
			t.Fatalf("http.NewRequest(): got %v, want no error", err)
		}
		req.Header.Set("Connection", "close")

		// GET / HTTP/1.1
		// Host: example.com
		// Connection: close
		if err := req.Write(tlsconn); err != nil {
			t.Fatalf("req.Write(): got %v, want no error", err)
		}

		res, err = http.ReadResponse(bufio.NewReader(tlsconn), req)
		if err != nil {
			t.Fatalf("http.ReadResponse(): got %v, want no error", err)
		}
		defer res.Body.Close()

		if got, want := res.StatusCode, 299; got != want {
			t.Fatalf("res.StatusCode: got %d, want %d", got, want)
		}
	})

	t.Run("reqerr", func(t *testing.T) {
		tm.Reset()

		reqerr := errors.New("request error")
		tm.RequestError(reqerr)

		conn := c.dial(t)
		defer conn.Close()
		res := connect(t, conn)

		if got, want := res.StatusCode, 502; got != want {
			t.Fatalf("res.StatusCode: got %d, want %d", got, want)
		}

		if !tm.RequestModified() {
			t.Error("tm.RequestModified(): got false, want true")
		}
		if !tm.ResponseModified() {
			t.Error("tm.ResponseModified(): got false, want true")
		}

		if got, want := res.Header.Get("Warning"), reqerr.Error(); !strings.Contains(got, want) {
			t.Errorf("res.Header.Get(%q): got %q, want to contain %q", "Warning", got, want)
		}
	})

	t.Run("reserr", func(t *testing.T) {
		tm.Reset()

		reserr := errors.New("response error")
		tm.ResponseError(reserr)

		conn := c.dial(t)
		defer conn.Close()
		res := connect(t, conn)

		if got, want := res.StatusCode, 502; got != want {
			t.Fatalf("res.StatusCode: got %d, want %d", got, want)
		}

		if !tm.RequestModified() {
			t.Error("tm.RequestModified(): got false, want true")
		}
		if !tm.ResponseModified() {
			t.Error("tm.ResponseModified(): got false, want true")
		}

		if got, want := res.Header.Get("Warning"), reserr.Error(); !strings.Contains(got, want) {
			t.Errorf("res.Header.Get(%q): got %q, want to contain %q", "Warning", got, want)
		}
	})
}

func connect(t *testing.T, conn net.Conn) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	//
	// Rewritten to CONNECT to host:port in CONNECT request modifier.
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// CONNECT response after establishing tunnel.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	return res
}

func TestIntegrationConnectUpstreamProxy(t *testing.T) {
	t.Parallel()

	if *withHandler {
		t.Skip("skipping in handler mode")
	}

	ul, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	ca, mc := certs(t)

	upstream := testHelper{
		Listener: ul,
		Proxy: func(p *Proxy) {
			utr := martiantest.NewTransport()
			utr.Respond(299)
			p.RoundTripper = utr

			utm := martiantest.NewModifier()
			utm.RequestFunc(func(req *http.Request) {
				if req.Method == http.MethodConnect && req.ContentLength != -1 {
					t.Errorf("req.ContentLength: got %d, want -1", req.ContentLength)
				}
			})
			p.RequestModifier = utm

			p.MITMConfig = mc
		},
	}
	uc, ucancel := upstream.proxyClient(t)
	defer ucancel()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ProxyURL = http.ProxyURL(&url.URL{Scheme: "http", Host: uc.Addr})
		},
	}
	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// Response from upstream proxy starting MITM.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
	if res.ContentLength != -1 {
		t.Errorf("res.ContentLength: got %d, want -1", res.ContentLength)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	tlsconn := tls.Client(conn, &tls.Config{
		// Validate the hostname.
		ServerName: "example.com",
		// The certificate will have been MITM'd, verify using the MITM CA
		// certificate.
		RootCAs: roots,
	})
	defer tlsconn.Close()

	req, err = http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	//
	// GET / HTTP/1.1
	// Host: example.com
	if err := req.Write(tlsconn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// Response from MITM in upstream proxy.
	res, err = http.ReadResponse(bufio.NewReader(tlsconn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 299; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
}

type pipeConn struct {
	*io.PipeReader
	*io.PipeWriter
}

func (conn pipeConn) CloseWrite() error {
	return conn.PipeWriter.Close()
}

func (conn pipeConn) Close() error {
	return multierr.Combine(
		conn.PipeReader.Close(),
		conn.PipeWriter.Close(),
	)
}

func TestIntegrationConnectFunc(t *testing.T) {
	t.Parallel()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ConnectFunc = func(req *http.Request) (*http.Response, io.ReadWriteCloser, error) {
				if req.ContentLength != -1 {
					t.Errorf("req.ContentLength: got %d, want -1", req.ContentLength)
				}

				pr, pw := io.Pipe()
				return newConnectResponse(req), pipeConn{pr, pw}, nil
			}
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:80", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:80 HTTP/1.1
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from skipped round trip.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}
	if res.ContentLength != -1 {
		t.Errorf("res.ContentLength: got %d, want -1", res.ContentLength)
	}

	if _, err := conn.Write([]byte("12345")); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}
	buf := make([]byte, 5)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("conn.Read(): got %v, want no error", err)
	}
	if string(buf) != "12345" {
		t.Errorf("conn.Read(): got %q, want %q", buf, "12345")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close(): got %v, want no error", err)
	}
}

func TestIntegrationConnectTerminateTLS(t *testing.T) {
	t.Parallel()

	// Test TLS server.
	ca, mc := certs(t)

	// Set the TLS config to terminate TLS.
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	rt := http.DefaultTransport.(*http.Transport).Clone()
	rt.TLSClientConfig = &tls.Config{
		ServerName: "example.com",
		RootCAs:    roots,
	}

	tl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("tls.Listen(): got %v, want no error", err)
	}
	tl = tls.NewListener(tl, mc.TLS(context.Background()))

	go http.Serve(tl, http.HandlerFunc(
		func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(299)
		}))

	tm := martiantest.NewModifier()

	// Force the CONNECT request to dial the local TLS server.
	tm.RequestFunc(func(req *http.Request) {
		req.URL.Host = tl.Addr().String()
	})

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = rt
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	req.Header.Set("X-Martian-Terminate-Tls", "true")

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	// X-Martian-Terminate-Tls: true
	//
	// Rewritten to CONNECT to host:port in CONNECT request modifier.
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// CONNECT response after establishing tunnel.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}

	if !tm.RequestModified() {
		t.Error("tm.RequestModified(): got false, want true")
	}
	if !tm.ResponseModified() {
		t.Error("tm.ResponseModified(): got false, want true")
	}

	req, err = http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}
	req.Header.Set("Connection", "close")

	// GET / HTTP/1.1
	// Host: example.com
	// Connection: close
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	res, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 299; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
}

func TestIntegrationMITM(t *testing.T) {
	t.Parallel()

	if *withHandler {
		t.Skip("skipping in handler mode")
	}

	tr := martiantest.NewTransport()
	tr.Func(func(req *http.Request) (*http.Response, error) {
		res := proxyutil.NewResponse(200, nil, req)
		res.Header.Set("Request-Scheme", req.URL.Scheme)

		return res, nil
	})

	ca, mc := certs(t)

	tm := martiantest.NewModifier()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = tr
			p.ReadTimeout = 600 * time.Millisecond
			p.WriteTimeout = 600 * time.Millisecond
			p.MITMConfig = mc
			p.RequestModifier = tm
			p.ResponseModifier = tm
		},
	}

	c, cancel := h.proxyClient(t)
	t.Cleanup(cancel)

	testRoundTrip := func(t *testing.T, conn net.Conn) {
		t.Helper()

		roots := x509.NewCertPool()
		roots.AddCert(ca)

		tlsconn := tls.Client(conn, &tls.Config{
			ServerName: "example.com",
			RootCAs:    roots,
		})
		defer tlsconn.Close()

		req, err := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
		if err != nil {
			t.Fatalf("http.NewRequest(): got %v, want no error", err)
		}

		// GET / HTTP/1.1
		// Host: example.com
		if err := req.Write(tlsconn); err != nil {
			t.Fatalf("req.Write(): got %v, want no error", err)
		}

		// Response from MITM proxy.
		res, err := http.ReadResponse(bufio.NewReader(tlsconn), req)
		if err != nil {
			t.Fatalf("http.ReadResponse(): got %v, want no error", err)
		}
		defer res.Body.Close()

		if got, want := res.StatusCode, 200; got != want {
			t.Errorf("res.StatusCode: got %d, want %d", got, want)
		}
		if got, want := res.Header.Get("Request-Scheme"), "https"; got != want {
			t.Errorf("res.Header.Get(%q): got %q, want %q", "Request-Scheme", got, want)
		}
	}

	t.Run("http11", func(t *testing.T) {
		t.Parallel()

		conn := c.dial(t)
		defer conn.Close()

		req, err := http.NewRequest(http.MethodConnect, "//example.com:443", http.NoBody)
		if err != nil {
			t.Fatalf("http.NewRequest(): got %v, want no error", err)
		}

		// CONNECT example.com:443 HTTP/1.1
		// Host: example.com
		if err := req.Write(conn); err != nil {
			t.Fatalf("req.Write(): got %v, want no error", err)
		}

		// Response MITM'd from proxy.
		res, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatalf("http.ReadResponse(): got %v, want no error", err)
		}
		if got, want := res.StatusCode, 200; got != want {
			t.Errorf("res.StatusCode: got %d, want %d", got, want)
		}
		if res.ContentLength != -1 {
			t.Errorf("res.ContentLength: got %d, want -1", res.ContentLength)
		}

		testRoundTrip(t, conn)
	})

	t.Run("http10", func(t *testing.T) {
		t.Parallel()

		conn := c.dial(t)
		defer conn.Close()

		// CONNECT example.com:443 HTTP/1.0
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.0\r\nContent-Length: 0\r\n\r\n", "example.com:443")

		// Response from skipped round trip.
		res, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("http.ReadResponse(): got %v, want no error", err)
		}
		defer res.Body.Close()

		if got, want := res.StatusCode, 200; got != want {
			t.Errorf("res.StatusCode: got %d, want %d", got, want)
		}

		testRoundTrip(t, conn)
	})
}

func TestIntegrationTransparentHTTP(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = martiantest.NewTransport()
			p.RequestModifier = tm
			p.ResponseModifier = tm
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET / HTTP/1.1
	// Host: www.example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}

	if !tm.RequestModified() {
		t.Error("tm.RequestModified(): got false, want true")
	}
	if !tm.ResponseModified() {
		t.Error("tm.ResponseModified(): got false, want true")
	}
}

func TestIntegrationTransparentMITM(t *testing.T) {
	t.Parallel()

	if *withHandler {
		t.Skip("skipping in handler mode")
	}

	ca, mc := certs(t)

	// Start TLS listener with config that will generate certificates based on
	// SNI from connection.
	//
	// BUG: tls.Listen will not accept a tls.Config where Certificates is empty,
	// even though it is supported by tls.Server when GetCertificate is not nil.
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}
	l = tls.NewListener(l, mc.TLS(context.Background()))

	tr := martiantest.NewTransport()
	tr.Func(func(req *http.Request) (*http.Response, error) {
		res := proxyutil.NewResponse(200, nil, req)
		res.Header.Set("Request-Scheme", req.URL.Scheme)

		return res, nil
	})

	tm := martiantest.NewModifier()
	h := testHelper{
		Listener: l,
		Proxy: func(p *Proxy) {
			p.RequestModifier = tm
			p.ResponseModifier = tm
			p.RoundTripper = tr
		},
	}

	_, cancel := h.proxyClient(t)
	defer cancel()

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	tlsconn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		// Verify the hostname is example.com.
		ServerName: "example.com",
		// The certificate will have been generated during MITM, so we need to
		// verify it with the generated CA certificate.
		RootCAs: roots,
	})
	if err != nil {
		t.Fatalf("tls.Dial(): got %v, want no error", err)
	}
	defer tlsconn.Close()

	req, err := http.NewRequest(http.MethodGet, "https://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// Write Encrypted request directly, no CONNECT.
	// GET / HTTP/1.1
	// Host: example.com
	if err := req.Write(tlsconn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	res, err := http.ReadResponse(bufio.NewReader(tlsconn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Fatalf("res.StatusCode: got %d, want %d", got, want)
	}
	if got, want := res.Header.Get("Request-Scheme"), "https"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Request-Scheme", got, want)
	}

	if !tm.RequestModified() {
		t.Errorf("tm.RequestModified(): got false, want true")
	}
	if !tm.ResponseModified() {
		t.Errorf("tm.ResponseModified(): got false, want true")
	}
}

func TestIntegrationUDPMasque(t *testing.T) {
	const bufSize = 64

	// UDP echo server.
	udpEchoServer := func(conn net.PacketConn) error {
		buf := make([]byte, bufSize)
		for {
			n, caddr, err := conn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					err = nil
				}
				return fmt.Errorf("conn.ReadFrom(): got %v, want no error", err)
			}

			t.Logf("Recv %s: %s\n", caddr, string(buf[:n]))

			if _, err := conn.WriteTo(buf[:n], caddr); err != nil {
				return fmt.Errorf("conn.WriteTo(): got %v, want no error", err)
			}
		}
	}

	uc, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(): got %v, want no error", err)
	}
	defer uc.Close()

	go udpEchoServer(uc)

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.AllowHTTP = true
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()

	// GET /.well-known/masque/udp/<host>/<port> HTTP/1.1
	udpMasqueURL := "/.well-known/masque/udp/127.0.0.1/" + strconv.Itoa(uc.LocalAddr().(*net.UDPAddr).Port)
	req, err := http.NewRequest(http.MethodGet, udpMasqueURL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "connect-udp")

	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	br := bufio.NewReader(conn)

	res, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 101 {
		t.Fatalf("res.StatusCode: got %d, want 101", res.StatusCode)
	}
	if got, want := res.Header.Get("Connection"), "Upgrade"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Connection", got, want)
	}
	if got, want := res.Header.Get("Upgrade"), "connect-udp"; got != want {
		t.Errorf("res.Header.Get(%q): got %q, want %q", "Upgrade", got, want)
	}

	assertUDPEcho := func(msg string) {
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("conn.Write(): got %v, want no error", err)
		}

		buf := make([]byte, bufSize)
		n, err := br.Read(buf)
		if err != nil {
			t.Fatalf("conn.Read(): got %v, want no error", err)
		}
		t.Logf("Recv: %s\n", string(buf[:n]))

		if string(buf[:n]) != msg {
			t.Errorf("conn.Read(): got %q, want %q", buf[:n], msg)
		}
	}

	assertUDPEcho("hello")
	assertUDPEcho("world")
	conn.(*net.TCPConn).CloseWrite()

}

func TestIntegrationFailedRoundTrip(t *testing.T) {
	t.Parallel()

	tr := martiantest.NewTransport()
	trerr := errors.New("round trip error")
	tr.RespondError(trerr)

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = tr
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from failed round trip.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 502; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}

	if got, want := res.Header.Get("Warning"), trerr.Error(); !strings.Contains(got, want) {
		t.Errorf("res.Header.Get(%q): got %q, want to contain %q", "Warning", got, want)
	}
}

func TestIntegrationSkipRoundTrip(t *testing.T) {
	t.Parallel()

	// Transport will be skipped, no 500.
	tr := martiantest.NewTransport()
	tr.Respond(500)
	tm := martiantest.NewModifier()
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.TestingSkipRoundTrip = true
			p.RoundTripper = tr
			p.RequestModifier = tm
			p.ResponseModifier = tm
			p.ReadTimeout = 200 * time.Millisecond
			p.WriteTimeout = 200 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from skipped round trip.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	defer res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}
}

func TestIntegrationShutdown(t *testing.T) {
	t.Parallel()

	if *withHandler {
		t.Skip("skipping in handler mode")
	}

	tr := martiantest.NewTransport()
	tr.Respond(200)

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.RoundTripper = tr
		},
	}
	l, c := h.listenerAndClient(t)
	p := h.proxy(t)
	go h.serve(p, l)

	conn := c.dial(t)
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Wait for response...
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("conn.Read(): got %v, want no error", err)
	}

	// Shutdown the proxy with timeout.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done := make(chan struct{})
		go func() {
			if err := p.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("p.Shutdown(): got %v, want %v", err, context.DeadlineExceeded)
			}
			close(done)
		}()
		<-done
	}

	// Close the connection, and shutdown the proxy again.
	conn.Close()
	{
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if p.Shutdown(ctx) != nil {
			t.Error("p.Shutdown(): got error, want no error")
		}
	}
}

func TestHTTPThroughConnectWithMITM(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	tm.RequestFunc(func(req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodConnect {
			t.Errorf("unexpected method on request handler: %v", req.Method)
		}
	})

	_, mc := certs(t)
	h := testHelper{
		Proxy: func(p *Proxy) {
			p.TestingSkipRoundTrip = true
			p.RequestModifier = tm
			p.MITMConfig = mc
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:80", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:80 HTTP/1.1
	// Host: example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// Response skipped round trip.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}

	req, err = http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from skipped round trip.
	res, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}

	req, err = http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// GET http://example.com/ HTTP/1.1
	// Host: example.com
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("req.WriteProxy(): got %v, want no error", err)
	}

	// Response from skipped round trip.
	res, err = http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}
}

func TestTLSHandshakeTimeoutWithMITM(t *testing.T) {
	t.Parallel()

	tm := martiantest.NewModifier()
	tm.RequestFunc(func(req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodConnect {
			t.Errorf("unexpected method on request handler: %v", req.Method)
		}
	})

	_, mc := certs(t)

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.MITMTLSHandshakeTimeout = 200 * time.Millisecond
			p.TestingSkipRoundTrip = true
			p.RequestModifier = tm
			p.MITMConfig = mc
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//example.com:80", http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:80 HTTP/1.1
	// Host: example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}

	// Response skipped round trip.
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	res.Body.Close()

	if got, want := res.StatusCode, 200; got != want {
		t.Errorf("res.StatusCode: got %d, want %d", got, want)
	}

	if _, err := conn.Write([]byte{22}); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}

	time.Sleep(300 * time.Millisecond)
	if _, err := conn.Read(make([]byte, 1)); !isClosedConnError(err) {
		t.Fatalf("conn.Read(): got %v, want ClosedConnError", err)
	}
}

func TestServerClosesConnection(t *testing.T) {
	t.Parallel()

	dstl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create http listener: %v", err)
	}
	defer dstl.Close()

	go func() {
		t.Logf("Waiting for server side connection")
		conn, err := dstl.Accept()
		if err != nil {
			t.Errorf("Got error while accepting connection on destination listener: %v", err)
			return
		}
		t.Logf("Accepted server side connection")

		buf := make([]byte, 16384)
		if _, err := conn.Read(buf); err != nil {
			t.Errorf("Error reading: %v", err)
			return
		}

		_, err = conn.Write([]byte("HTTP/1.1 301 MOVED PERMANENTLY\r\n" +
			"Server:  \r\n" +
			"Date:  \r\n" +
			"Referer:  \r\n" +
			"Location: http://www.foo.com/\r\n" +
			"Content-type: text/html\r\n" +
			"Connection: close\r\n\r\n"))
		if err != nil {
			t.Errorf("Got error while writing to connection on destination listener: %v", err)
			return
		}
		conn.Close()
	}()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}

	_, mc := certs(t)
	h := testHelper{
		Listener: newTimeoutListener(l, 3),
		Proxy: func(p *Proxy) {
			p.MITMConfig = mc
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	req, err := http.NewRequest(http.MethodConnect, "//"+dstl.Addr().String(), http.NoBody)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	// CONNECT example.com:443 HTTP/1.1
	// Host: example.com
	if err := req.Write(conn); err != nil {
		t.Fatalf("req.Write(): got %v, want no error", err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	res.Body.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\n" +
		"User-Agent: curl/7.35.0\r\n" +
		fmt.Sprintf("Host: %s\r\n", dstl.Addr()) +
		"Accept: */*\r\n\r\n"))
	if err != nil {
		t.Fatalf("Error while writing GET request: %v", err)
	}

	res, err = http.ReadResponse(bufio.NewReader(io.TeeReader(conn, os.Stderr)), req)
	if err != nil {
		t.Fatalf("http.ReadResponse(): got %v, want no error", err)
	}
	_, err = io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("error while ReadAll: %v", err)
	}
	res.Body.Close()
}

// TestRacyClose checks that creating a proxy, serving from it, and closing
// it in rapid succession doesn't result in race warnings.
// See https://github.com/google/martian/issues/286.
func TestRacyClose(t *testing.T) {
	t.Parallel()

	openAndConnect := func() {
		h := testHelper{}
		conn, cancel := h.proxyConn(t)
		conn.Close()
		cancel()
	}

	// Repeat a bunch of times to make failures more repeatable.
	for range 100 {
		openAndConnect()
	}
}

func TestIdleTimeout(t *testing.T) {
	t.Parallel()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.IdleTimeout = 100 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer conn.Close()
	defer cancel()

	time.Sleep(200 * time.Millisecond)
	if _, err := conn.Read(make([]byte, 1)); !isClosedConnError(err) {
		t.Fatalf("conn.Read(): got %v, want io.EOF", err)
	}
}

func TestTLSHandshakeTimeout(t *testing.T) {
	t.Parallel()

	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen(): got %v, want no error", err)
	}
	_, mc := certs(t)
	l = tls.NewListener(l, mc.TLS(context.Background()))

	h := testHelper{
		Listener: l,
		Proxy: func(p *Proxy) {
			p.TLSHandshakeTimeout = 100 * time.Millisecond
		},
	}

	c, cancel := h.proxyClient(t)
	defer cancel()

	conn, err := net.Dial("tcp", c.Addr)
	if err != nil {
		t.Fatalf("net.Dial(): got %v, want no error", err)
	}

	time.Sleep(200 * time.Millisecond)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("conn.Read(): got %v, want io.EOF", err)
	}
}

func TestReadHeaderTimeout(t *testing.T) {
	t.Parallel()

	h := testHelper{
		Proxy: func(p *Proxy) {
			p.ReadHeaderTimeout = 100 * time.Millisecond
		},
	}

	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := conn.Write([]byte("Host: example.com\r\n\r\n")); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}
	if _, err := conn.Read(make([]byte, 1)); !isClosedConnError(err) {
		t.Fatalf("conn.Read(): got %v, want io.EOF", err)
	}
}

func TestReadHeaderConnectionReset(t *testing.T) {
	t.Parallel()

	h := testHelper{}
	conn, cancel := h.proxyConn(t)
	defer cancel()
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
		t.Fatalf("conn.Write(): got %v, want no error", err)
	}
	cw, _ := asCloseWriter(conn)
	cw.CloseWrite()
	if _, err := conn.Read(make([]byte, 1)); !isClosedConnError(err) {
		t.Fatalf("conn.Read(): got %v, want io.EOF", err)
	}
}
