# 构建与开发入口（Makefile）
# Windows 下若无 make，可直接执行注释中的 go 命令。

BINARY_DIR := bin
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X proxygw/internal/version.Version=$(VERSION) \
           -X proxygw/internal/version.Commit=$(COMMIT) \
           -X proxygw/internal/version.BuildTime=$(BUILD_TIME)

.PHONY: all build server client test race vet fmt tidy clean docker acceptance

all: build

build: server client

server:
	mkdir -p $(BINARY_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/proxygw-server ./cmd/proxygw-server

client:
	mkdir -p $(BINARY_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/proxygw-client ./cmd/proxygw-client

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

acceptance:
	pwsh -File scripts/acceptance.ps1

docker:
	docker build -f deploy/Dockerfile.server -t proxygw-server:$(VERSION) .
	docker build -f deploy/Dockerfile.client -t proxygw-client:$(VERSION) .

clean:
	rm -rf $(BINARY_DIR)
