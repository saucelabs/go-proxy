// Copyright 2022-2024 Sauce Labs Inc., all rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func TestUDPOverHTTP(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	req, err := http.NewRequest(http.MethodGet, "http://localhost:3128/.well-known/masque/udp/localhost/5005", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "connect-udp")
	req.ContentLength = -1

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for i := 0; i < 10; i++ {
			pw.Write([]byte("hello"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	buf := make([]byte, 1000)
	for i := 0; i < 10; i++ {
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(buf[:n]))
	}
}
