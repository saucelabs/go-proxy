// Copyright 2021 The forwarder Authors. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package forwarder

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func deepCopy(dst, src interface{}) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		panic(err)
	}
	if err := gob.NewDecoder(&buf).Decode(dst); err != nil {
		panic(err)
	}
}

// normalizeURLScheme ensures that the URL starts with the scheme.
func normalizeURLScheme(uri string) string {
	uri = strings.TrimSpace(uri)
	uri = strings.TrimPrefix(uri, "://")
	if strings.Contains(uri, "://") {
		return uri
	}

	scheme := "http"
	if strings.HasSuffix(uri, ":443") {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, uri)
}

func addProxyBasicAuthHeader(req *http.Request, u *url.Userinfo) {
	if u == nil || u.Username() == "" {
		return
	}
	req.Header.Set("Proxy-Authorization", "Basic "+userInfoBase64(u))
}

func addBasicAuthHeader(req *http.Request, u *url.Userinfo) {
	if u == nil || u.Username() == "" {
		return
	}
	req.Header.Set("Authorization", "Basic "+userInfoBase64(u))
}
