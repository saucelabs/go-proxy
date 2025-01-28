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
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saucelabs/forwarder/internal/martian/log"
	"github.com/saucelabs/forwarder/internal/martian/mitm"
	"github.com/saucelabs/forwarder/internal/martian/proxyutil"
	"go.uber.org/multierr"
	"golang.org/x/net/http/httpguts"
)

// Proxy is an HTTP proxy with support for TLS MITM and customizable behavior.
type Proxy struct {
	RequestModifier
	ResponseModifier
	Trace *ProxyTrace

	// RoundTripper specifies the round tripper to use for requests.
	RoundTripper http.RoundTripper

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If not set and the RoundTripper is an *http.Transport, the Transport's DialContext is used.
	DialContext func(context.Context, string, string) (net.Conn, error)

	// ProxyURL specifies the upstream proxy to use for requests.
	// If not set and the RoundTripper is an *http.Transport, the Transport's ProxyURL is used.
	ProxyURL func(*http.Request) (*url.URL, error)

	// AllowHTTP disables automatic HTTP to HTTPS upgrades when the listener is TLS.
	AllowHTTP bool

	// RequestIDHeader specifies a special header name that the proxy will use to identify requests.
	// If the header is present in the request, the proxy will associate the value with the request in the logs.
	// If empty, no action is taken, and the proxy will generate a new request ID.
	RequestIDHeader string

	// ConnectFunc specifies a function to dial network connections for CONNECT requests.
	// Implementations can return ErrConnectFallback to indicate that the CONNECT request should be handled by martian.
	ConnectFunc ConnectFunc

	// ConnectTimeout specifies the maximum amount of time to connect to upstream before cancelling request.
	ConnectTimeout time.Duration

	// MITMConfig is config to use for MITMing of CONNECT requests.
	MITMConfig *mitm.Config

	// MITMFilter specifies a function to determine whether a CONNECT request should be MITMed.
	MITMFilter func(*http.Request) bool

	// MITMTLSHandshakeTimeout specifies the maximum amount of time to wait for a TLS handshake for a MITMed connection.
	// Zero means no timeout.
	MITMTLSHandshakeTimeout time.Duration

	// WithoutWarning disables the warning header added to requests and responses when modifier errors occur.
	WithoutWarning bool

	// ErrorResponse specifies a custom error HTTP response to send when a proxying error occurs.
	ErrorResponse func(req *http.Request, err error) *http.Response

	// IdleTimeout is the maximum amount of time to wait for the
	// next request. If IdleTimeout is zero, the value of ReadTimeout is used.
	// If both are zero, there is no timeout.
	IdleTimeout time.Duration

	// TLSHandshakeTimeout is the maximum amount of time to wait for a TLS handshake.
	// The proxy will try to cast accepted connections to tls.Conn and perform a handshake.
	// If TLSHandshakeTimeout is zero, no timeout is set.
	TLSHandshakeTimeout time.Duration

	// ReadTimeout is the maximum duration for reading the entire
	// request, including the body. A zero or negative value means
	// there will be no timeout.
	//
	// Because ReadTimeout does not let Handlers make per-request
	// decisions on each request body's acceptable deadline or
	// upload rate, most users will prefer to use
	// ReadHeaderTimeout. It is valid to use them both.
	ReadTimeout time.Duration

	// ReadHeaderTimeout is the amount of time allowed to read
	// request headers. The connection's read deadline is reset
	// after reading the headers and the Handler can decide what
	// is considered too slow for the body. If ReadHeaderTimeout
	// is zero, the value of ReadTimeout is used. If both are
	// zero, there is no timeout.
	ReadHeaderTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read. Like ReadTimeout, it does not
	// let Handlers make decisions on a per-request basis.
	// A zero or negative value means there will be no timeout.
	WriteTimeout time.Duration

	// BaseContext is the base context for all requests.
	BaseContext context.Context //nolint:containedctx // It's intended to be used as a base context.

	// TestingSkipRoundTrip skips the round trip for requests and returns a 200 OK response.
	TestingSkipRoundTrip bool

	initOnce sync.Once

	rt        http.RoundTripper
	conns     map[net.Conn]struct{}
	connsWg   atomic.Int32
	connsMu   sync.Mutex // protects connsWg.Add/Wait and conns from concurrent access
	closeCh   chan bool
	closeOnce sync.Once
}

func (p *Proxy) init() {
	p.initOnce.Do(func() {
		if p.RoundTripper == nil {
			p.rt = &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
			}
		} else {
			p.rt = p.RoundTripper
		}

		if t, ok := p.rt.(*http.Transport); ok {
			// TODO(adamtanner): This forces the http.Transport to not upgrade requests
			// to HTTP/2 in Go 1.6+. Remove this once Martian can support HTTP/2.
			t.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)

			if p.DialContext == nil {
				p.DialContext = t.DialContext
			} else {
				t.DialContext = p.DialContext
			}
			if p.ProxyURL == nil {
				p.ProxyURL = t.Proxy
			} else {
				t.Proxy = p.ProxyURL
			}
			t.OnProxyConnectResponse = OnProxyConnectResponse

			p.rt = t
		}

		if p.DialContext == nil {
			p.DialContext = (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext
		}

		if p.BaseContext == nil {
			p.BaseContext = context.Background()
		}

		p.conns = make(map[net.Conn]struct{})
		p.connsWg.Store(0)
		p.closeCh = make(chan bool)
	})
}

// Shutdown sets the proxy to the closing state so it stops receiving new connections,
// finishes processing any inflight requests, and closes existing connections without
// reading anymore requests from them.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.init()

	log.Infof(context.TODO(), "shutting down proxy, draining connections")

	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	p.closeOnce.Do(func() {
		close(p.closeCh)
	})

	const shutdownPollIntervalMax = 500 * time.Millisecond

	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		// Add 10% jitter.
		interval := pollIntervalBase + time.Duration(rand.IntN(int(pollIntervalBase/10))) //nolint:gosec // It's good enough for jitter.
		// Double and clamp for next time.
		pollIntervalBase *= 2
		if pollIntervalBase > shutdownPollIntervalMax {
			pollIntervalBase = shutdownPollIntervalMax
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if n := p.connsWg.Load(); n == 0 {
			log.Infof(context.TODO(), "all connections closed")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

// Close closes the proxy and all connections it has accepted.
func (p *Proxy) Close() error {
	p.init()

	p.connsMu.Lock()
	defer p.connsMu.Unlock()

	p.closeOnce.Do(func() {
		close(p.closeCh)
	})

	var err error
	for conn := range p.conns {
		if e := conn.Close(); e != nil {
			err = multierr.Append(err, e)
		}
	}

	return err
}

// closing returns whether the proxy is in the closing state.
func (p *Proxy) closing() bool {
	select {
	case <-p.closeCh:
		return true
	default:
		return false
	}
}

// Serve accepts connections from the listener and handles the requests.
func (p *Proxy) Serve(l net.Listener) error {
	defer l.Close()

	p.init()

	var delay time.Duration
	for {
		if p.closing() {
			return nil
		}

		conn, err := l.Accept()
		if err != nil {
			var nerr net.Error
			if ok := errors.As(err, &nerr); ok && nerr.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}

				log.Debugf(context.TODO(), "temporary error on accept: %v", err)
				time.Sleep(delay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				log.Debugf(context.TODO(), "listener closed, returning")
				return err
			}

			log.Errorf(context.TODO(), "failed to accept: %v", err)
			return err
		}
		delay = 0
		log.Debugf(context.TODO(), "accepted connection from %s", conn.RemoteAddr())

		go p.handleLoop(conn)
	}
}

func (p *Proxy) handleLoop(conn net.Conn) {
	start := time.Now()

	p.connsMu.Lock()
	p.conns[conn] = struct{}{}
	p.connsWg.Add(1)
	p.connsMu.Unlock()

	defer func() {
		p.connsMu.Lock()
		delete(p.conns, conn)
		p.connsMu.Unlock()
	}()
	defer p.connsWg.Add(-1)
	defer conn.Close()
	if p.closing() {
		return
	}

	pc := newProxyConn(p, conn)

	if err := pc.maybeHandshakeTLS(); err != nil {
		log.Errorf(context.TODO(), "failed to do TLS handshake: %v", err)
		return
	}

	const maxConsecutiveErrors = 5
	errorsN := 0
	for {
		if err := pc.handle(); err != nil {
			if errors.Is(err, errClose) || isCloseable(err) {
				log.Debugf(context.TODO(), "closing connection from %s duration=%s", conn.RemoteAddr(), time.Since(start))
				return
			}

			errorsN++
			if errorsN >= maxConsecutiveErrors {
				log.Errorf(context.TODO(), "closing connection from %s after %d consecutive errors: %v duration=%s",
					conn.RemoteAddr(), errorsN, err, time.Since(start))
				return
			}
		} else {
			errorsN = 0
		}
	}
}

func (p *Proxy) idleTimeout() time.Duration {
	if p.IdleTimeout > 0 {
		return p.IdleTimeout
	}
	return p.ReadTimeout
}

func (p *Proxy) readHeaderTimeout() time.Duration {
	if p.ReadHeaderTimeout > 0 {
		return p.ReadHeaderTimeout
	}
	return p.ReadTimeout
}

func (p *Proxy) modifyRequest(req *http.Request) error {
	if p.RequestModifier == nil {
		return nil
	}
	return p.RequestModifier.ModifyRequest(req)
}

func (p *Proxy) modifyResponse(res *http.Response) error {
	if p.ResponseModifier == nil {
		return nil
	}
	return p.ResponseModifier.ModifyResponse(res)
}

func (p *Proxy) shouldMITM(req *http.Request) bool {
	if p.MITMConfig == nil {
		return false
	}

	if p.MITMFilter != nil {
		return p.MITMFilter(req)
	}

	return true
}

func (p *Proxy) fixRequestScheme(req *http.Request) {
	if req.URL.Scheme == "" {
		if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
			req.URL.Scheme = proto
		} else if req.TLS != nil {
			req.URL.Scheme = "https"
		} else {
			req.URL.Scheme = "http"
		}
	}

	if req.URL.Scheme == "http" {
		if req.TLS != nil && !p.AllowHTTP {
			log.Infof(req.Context(), "forcing HTTPS inside secure session")
			req.URL.Scheme = "https"
		}
	}
}

func (p *Proxy) roundTrip(req *http.Request) (*http.Response, error) {
	if p.TestingSkipRoundTrip {
		log.Debugf(req.Context(), "skipping round trip")
		return proxyutil.NewResponse(200, http.NoBody, req), nil
	}

	if isUDPMasque(req) {
		return p.roundTripUDPMasque(req)
	}

	res, err := p.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if isHeaderOnlySpec(res) && res.StatusCode != http.StatusSwitchingProtocols && res.Body != http.NoBody {
		log.Infof(req.Context(), "unexpected body in header-only response: %d, closing body", res.StatusCode)
		res.Body.Close()
		res.Body = http.NoBody
	}

	return res, err
}

func (p *Proxy) errorResponse(req *http.Request, err error) *http.Response {
	var res *http.Response
	if p.ErrorResponse != nil {
		res = p.ErrorResponse(req, err)
	} else {
		res = proxyutil.NewResponse(502, http.NoBody, req)
	}

	if !p.WithoutWarning {
		proxyutil.Warning(res.Header, err)
	}

	return res
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

type panicReader struct{}

func (panicReader) Read(p []byte) (int, error) {
	panic("unexpected read")
}

var panicBody = io.NopCloser(panicReader{})
