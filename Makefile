# Makefile

MODULE_PATH := github.com/edgarpsda/devsecops-kit
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo development)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X $(MODULE_PATH)/cli/cmd.version=$(VERSION) -X $(MODULE_PATH)/cli/cmd.commit=$(COMMIT) -X $(MODULE_PATH)/cli/cmd.date=$(DATE)

BINARY_NAME := devsecops

.PHONY: build
build:
	go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/devsecops

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go vet ./...

# Cross-compilation examples for releases
.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-linux-amd64 ./cmd/devsecops

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/devsecops
