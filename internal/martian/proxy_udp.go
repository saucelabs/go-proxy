// Copyright 2022-2024 Sauce Labs Inc., all rights reserved.
//
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
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

const udpMasqueURLPathPrefix = "/.well-known/masque/udp/"

// isUDPMasque checks if the request is a UDP Masque request as specified in
// https://www.rfc-editor.org/rfc/rfc9298.html#section-2.
//
// For example:
//   - https://example.org/.well-known/masque/udp/{target_host}/{target_port}/
//   - https://proxy.example.org:4443/masque?h={target_host}&p={target_port}
//   - https://proxy.example.org:4443/masque{?target_host,target_port}
//
// For simplicity, we only support the first format.
func isUDPMasque(req *http.Request) bool {
	return strings.HasPrefix(req.URL.Path, "/.well-known/masque/udp/")
}

func udpMasqueHostPort(req *http.Request) (host, port string) {
	var ok bool
	host, port, ok = strings.Cut(req.URL.Path[len(udpMasqueURLPathPrefix):], "/")
	if !ok {
		host, port = "", ""
	}
	return
}

// validateUDPMasque makes sure the request is a valid UDP Masque request as specified in
// https://www.rfc-editor.org/rfc/rfc9298.html#name-http-11-request.
//
// Requirements:
//   - The method SHALL be "GET".
//   - The request SHALL include a single Host header field containing the origin of the UDP proxy.
//   - The request SHALL include a Connection header field with value "Upgrade" (note that this requirement is case-insensitive as per Section 7.6.1 of [HTTP]).
//   - The request SHALL include an Upgrade header field with value "connect-udp".
func validateUDPMasque(req *http.Request) error {
	host, port := udpMasqueHostPort(req)
	if host == "" || port == "" {
		return errors.New("missing target host or port")
	}
	if req.Method != http.MethodGet {
		return errors.New("invalid method")
	}
	if req.Header.Get("Connection") != "Upgrade" {
		return errors.New("missing Connection: Upgrade header")
	}
	if req.Header.Get("Upgrade") != "connect-udp" {
		return errors.New("missing Upgrade: connect-udp header")
	}
	return nil
}

func (p *Proxy) roundTripUDPMasque(req *http.Request) (*http.Response, error) {
	if err := validateUDPMasque(req); err != nil {
		return nil, fmt.Errorf("invalid UDP Masque request: %w", err)
	}

	host, port := udpMasqueHostPort(req)
	conn, err := p.DialContext(req.Context(), "udp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}

	resp := newConnectResponseStatus(req, http.StatusSwitchingProtocols)
	resp.Header.Set("Connection", "Upgrade")
	resp.Header.Set("Upgrade", "connect-udp")
	resp.Body = conn
	return resp, nil
}
