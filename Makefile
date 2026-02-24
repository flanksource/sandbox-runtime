GO ?= go
APP_NAME ?= srt
BIN_DIR ?= bin
MAIN_PKG ?= ./cmd/srt

.PHONY: all build dist run test fmt fmt-check vet tidy vendor-sync seccomp check clean

all: test build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(APP_NAME) $(MAIN_PKG)

dist: build
	@mkdir -p dist/bin dist/third_party
	@cp $(BIN_DIR)/$(APP_NAME) dist/bin/$(APP_NAME)
	@cp -R third_party/seccomp dist/third_party/

run:
	$(GO) run $(MAIN_PKG) $(ARGS)

test:
	$(GO) test ./...

fmt:
	gofmt -w ./cmd ./internal

fmt-check:
	@test -z "$$(gofmt -l ./cmd ./internal)" || (echo "gofmt changes required" && gofmt -l ./cmd ./internal && exit 1)

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

vendor-sync:
	./scripts/sync-go-vendor.sh

seccomp:
	./scripts/build-seccomp-binaries.sh

check: fmt-check vet test

clean:
	$(GO) clean
	@rm -f coverage.out
	@if command -v trash >/dev/null 2>&1; then trash $(BIN_DIR) >/dev/null 2>&1 || true; fi
