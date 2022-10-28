# Copyright 2021 The forwarder Authors. All rights reserved.
# Use of this source code is governed by a MIT
# license that can be found in the LICENSE file.

all: dev

export GOBIN := $(PWD)/bin
export PATH  := $(GOBIN):$(PATH)

include .version

.PHONY: install-dependencies
install-dependencies:
	@rm -Rf bin && mkdir -p $(GOBIN)
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/goreleaser/goreleaser@$(GORELEASER_VERSION)
	go install golang.org/x/tools/cmd/godoc@latest
	go install golang.org/x/tools/cmd/stringer@latest

.PHONY: clean
clean:
	@rm -Rf bin dist *.coverprofile *.dev *.race *.test *.log
	@go clean -cache -modcache -testcache ./... ||:

.PHONY: dev
dev: forwarder.race
	@./forwarder.race run

forwarder.race: .check-go-version $(shell go list -f '{{range .GoFiles}}{{ $$.Dir }}/{{ . }} {{end}}' ./...)
	@go build -o ./forwarder.race -race ./cmd/forwarder

.PHONY: .check-go-version
.check-go-version:
	@[[ "`go version`" =~ $(GO_VERSION) ]] || echo "[WARNING] Required Go version $(GO_VERSION) found `go version | grep -o -E '1\.[0-9\.]+'`"

.PHONY: fmt
fmt:
	@golangci-lint run -c .golangci-fmt.yml --fix ./...

.PHONY: lint
lint:
	@LOG_LEVEL=error golangci-lint run

.PHONY: test
test:
	@go test -timeout 120s -short -v -race -cover -coverprofile=coverage.out ./...

.PHONY: bench
bench:
	@go test -bench=. -run=XXX ./pkg/proxy # If you hit too many open files: ulimit -Sn 10000

.PHONY: integration-test
integration-test:
	@FORWARDER_TEST_MODE=integration go test -timeout 120s -v -race -cover -coverprofile=coverage.out ./...

.PHONY: coverage
coverage:
	@go tool cover -func=coverage.out

.PHONY: doc
doc:
	@echo "Open http://localhost:6060/pkg/github.com/saucelabs/forwarder/ in your browser\n"
	@godoc -http :6060
