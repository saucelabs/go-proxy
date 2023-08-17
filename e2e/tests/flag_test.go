// Copyright 2023 Sauce Labs Inc. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build e2e

package tests

import (
	"net"
	"net/http"
	"testing"
)

func TestFlagProxyLocalhost(t *testing.T) {
	hosts := []string{
		"localhost",
		"127.0.0.1",
	}

	t.Run("allow", func(t *testing.T) {
		for _, h := range hosts {
			newClient(t, "http://"+net.JoinHostPort(h, "10000")).GET("/version").ExpectStatus(http.StatusOK)
		}
	})
	t.Run("deny", func(t *testing.T) {
		for _, h := range hosts {
			newClient(t, "http://"+net.JoinHostPort(h, "10000")).GET("/version").ExpectStatus(http.StatusForbidden)
		}
	})
}

func TestFlagHeader(t *testing.T) {
	c := newClient(t, httpbin)

	c.GET("/header/test-add/test-value").
		ExpectStatus(http.StatusOK)

	c.GET("/header/test-empty/", setHeader("test-empty", "not-empty")).
		ExpectStatus(http.StatusOK)

	c.GET("/header/test-rm/value-1", setHeader("test-rm", "value-1")).
		ExpectStatus(http.StatusNotFound)

	c.GET("/header/rm-prefix/value-2", setHeader("rm-prefix", "value-2")).
		ExpectStatus(http.StatusNotFound)
}

func TestFlagResponseHeader(t *testing.T) {
	c := newClient(t, httpbin)

	c.GET("/status/200").ExpectStatus(http.StatusOK).
		ExpectHeader("test-resp-add", "test-resp-value")

	c.GET("/header/test-resp-empty/not-empty", setHeader("test-resp-empty", "not-empty")).
		ExpectStatus(http.StatusOK).
		ExpectHeader("test-resp-empty", "")

	c.GET("/header/test-resp-rm/value-3", setHeader("test-resp-rm", "value-3")).
		ExpectStatus(http.StatusOK).ExpectHeader("test-resp-rm", "")

	c.GET("/header/resp-rm-prefix/value-4", setHeader("resp-rm-prefix", "value-4")).
		ExpectStatus(http.StatusOK).ExpectHeader("resp-rm-prefix", "")
}

func setHeader(key, value string) func(r *http.Request) {
	return func(r *http.Request) {
		r.Header.Set(key, value)
	}
}

var httpbinDNS = serviceScheme("HTTPBIN_PROTOCOL") + "://httpbin.local:8080"

func TestFlagDNSServer(t *testing.T) {
	t.Run("default httpbin address", func(t *testing.T) {
		newClient(t, httpbin).GET("/status/200").ExpectStatus(http.StatusBadGateway)
	})

	t.Run("custom httpbin address", func(t *testing.T) {
		newClient(t, httpbinDNS).GET("/status/200").ExpectStatus(http.StatusOK)
	})
}

func TestFlagInsecure(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		newClient(t, httpbin).GET("/status/200").ExpectStatus(http.StatusOK)
	})
	t.Run("false", func(t *testing.T) {
		for _, scheme := range []string{"http", "https"} {
			newClient(t, scheme+"://httpbin:8080").GET("/status/200").ExpectStatus(http.StatusBadGateway)
		}
	})
}

func TestFlagMITM(t *testing.T) {
	newClient(t, httpbin).GET("/status/200").ExpectStatus(http.StatusOK).
		ExpectHeader("test-resp-add", "test-resp-value")
}

func TestFlagDenyDomain(t *testing.T) {
	newClient(t, "https://www.google.com").GET("/").ExpectStatus(http.StatusForbidden)
	newClient(t, httpbin).GET("/status/200").ExpectStatus(http.StatusOK)
}
