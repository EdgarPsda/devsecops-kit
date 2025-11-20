# Makefile

MODULE_PATH := github.com/edgarpsda/devsecops-kit
VERSION ?= 0.1.0

BINARY_NAME := devsecops

.PHONY: build
build:
	go build -ldflags "-X $(MODULE_PATH)/cli/cmd.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/devsecops

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	go vet ./...

# Cross-compilation examples for releases
.PHONY: build-linux-amd64
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X $(MODULE_PATH)/cli/cmd.version=$(VERSION)" -o $(BINARY_NAME)-linux-amd64 ./cmd/devsecops

.PHONY: build-darwin-arm64
build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X $(MODULE_PATH)/cli/cmd.version=$(VERSION)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/devsecops
