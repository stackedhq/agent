.PHONY: build clean

VERSION ?= dev
LDFLAGS := -s -w -X github.com/stackedapp/stacked/agent/internal/heartbeat.Version=$(VERSION)

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/stacked-agent-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/stacked-agent-linux-arm64 ./cmd/agent

build-local:
	go build -ldflags="$(LDFLAGS)" -o dist/stacked-agent ./cmd/agent

clean:
	rm -rf dist/
