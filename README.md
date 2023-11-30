# Forwarder Proxy [![Build Status](https://github.com/saucelabs/forwarder/actions/workflows/go.yml/badge.svg)](https://github.com/saucelabs/forwarder/actions/workflows/go.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/saucelabs/forwarder)](https://goreportcard.com/report/github.com/saucelabs/forwarder) [![GitHub release](https://img.shields.io/github/release/saucelabs/forwarder.svg)](https://github.com/saucelabs/forwarder/releases) ![GitHub all releases](https://img.shields.io/github/downloads/saucelabs/forwarder/total)

Forwarder is a production-ready, MITM and PAC capable HTTP proxy.
It's used as a core component of Sauce Labs' [Sauce Connect Proxy](https://docs.saucelabs.com/secure-connections/sauce-connect/).
It is a forward proxy, which means it proxies traffic from clients to servers (e.g. browsers to websites), and supports `CONNECT` requests.
It can proxy:

* HTTP/HTTPS/HTTP2 requests
* WebSockets (both HTTP and HTTPS)
* Server Sent Events (SSE)
* TCP traffic (e.g. SMTP, IMAP, etc.)

## Features

* Supports upstream HTTP(S) and SOCKS5 proxies
* Supports PAC files for upstream proxy configuration
* Supports MITM for HTTPS traffic with automatic certificate generation
* Supports custom DNS servers
* Supports augmenting requests and responses with headers
* Supports basic authentication, for websites and proxies

## Additional resources

* Forwarder Proxy documentation: https://forwarder-proxy.io
* Forwarder Proxy CLI reference:
  - [forwarder run](https://forwarder-proxy.io/cli/forwarder_run) - Start HTTP (forward) proxy server
  - [forwarder pac eval](https://forwarder-proxy.io/cli/forwarder_pac_eval) - Evaluate a PAC file for given URL (or URLs)
  - [forwarder pac server](https://forwarder-proxy.io/cli/forwarder_pac_server) - Start HTTP server that serves a PAC file
  - [forwarder ready](https://forwarder-proxy.io/cli/forwarder_ready) - Readiness probe for the Forwarder
