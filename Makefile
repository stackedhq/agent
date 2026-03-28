.PHONY: build clean

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/stacked-agent-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/stacked-agent-linux-arm64 ./cmd/agent

build-local:
	go build -o dist/stacked-agent ./cmd/agent

clean:
	rm -rf dist/
