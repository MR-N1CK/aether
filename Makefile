BINARY_NAME := aether
YARA_BINARY_NAME := aether-yara
YARA_DEV_BINARY_NAME := aether-yara-dev
YARA_STATIC_BINARY_NAME := aether-yara-static
BIN_DIR := bin
DIST_DIR := dist
VERSION ?= 1.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)$(if $(shell git status --porcelain 2>/dev/null),-dirty)

# Reproducible timestamp derivation from SOURCE_DATE_EPOCH if present
BUILD_DATE := $(shell if [ -n "$$SOURCE_DATE_EPOCH" ]; then \
    date -u -d "@$$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
    date -u -r "$$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null; \
else \
    date -u +%Y-%m-%dT%H:%M:%SZ; \
fi)

DEV_RPATH ?= 0

USER_HOME := $(if $(SUDO_USER),$(shell getent passwd $(SUDO_USER) | cut -d: -f6),$(HOME))
EXTRA_PKG_CONFIG := $(wildcard $(USER_HOME)/.local/lib/*/pkgconfig) $(wildcard $(USER_HOME)/.local/lib/pkgconfig) $(wildcard /home/*/.local/lib/*/pkgconfig) $(wildcard /home/*/.local/lib/pkgconfig)

export PKG_CONFIG_PATH := /usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$(shell echo $(EXTRA_PKG_CONFIG) | tr ' ' ':'):$(PKG_CONFIG_PATH)
export LD_LIBRARY_PATH := /usr/local/lib:/usr/local/lib64:/usr/lib/x86_64-linux-gnu:$(HOME)/.local/lib:$(HOME)/.local/lib/x86_64-linux-gnu:$(LD_LIBRARY_PATH)

LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT)' \
	-X 'main.buildDate=$(BUILD_DATE)'

ifeq ($(DEV_RPATH),1)
	YARA_TARGET_BIN := $(BIN_DIR)/$(YARA_DEV_BINARY_NAME)
	YARA_RPATH_FLAGS := -Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64 -Wl,-rpath,$(HOME)/.local/lib -Wl,-rpath,$(HOME)/.local/lib/x86_64-linux-gnu
	YARA_EXTRA_LDFLAGS := -X 'main.devRpath=1'
else
	YARA_TARGET_BIN := $(BIN_DIR)/$(YARA_BINARY_NAME)
	YARA_RPATH_FLAGS := -Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64
	YARA_EXTRA_LDFLAGS :=
endif

.PHONY: all build build-static build-pure build-yara-static build-cross test test-yara test-fixtures test-packaging benchmark lint clean package package-clean release-verify release help

all: build

help:
	@echo "Aether Build & Packaging Targets:"
	@echo "  build             - Compile Aether binary (detects YARA-X library or falls back to pure Go)"
	@echo "  build-pure        - Compile pure Go static binary (CGO_ENABLED=0)"
	@echo "  build-yara-static - Compile static YARA-X binary (CGO_ENABLED=1, tags yara, linux/amd64)"
	@echo "  build-cross       - Compile pure Go static binaries for linux/amd64 and linux/arm64"
	@echo "  package           - Assemble 7 distributable software packages + release-manifest.json + SHA256SUMS"
	@echo "  package-clean     - Remove dist/ packaging directory"
	@echo "  release-verify    - Execute pre-release quality gate test suites offline"
	@echo "  release           - Verify quality gates and assemble release packages in dist/"
	@echo "  install           - Install compiled aether binary to /usr/local/bin or ~/.local/bin"
	@echo "  test              - Run all unit tests"
	@echo "  test-yara         - Run unit tests with YARA-X engine tag"
	@echo "  test-packaging    - Run packaging verification test suite"
	@echo "  test-fixtures     - Run golden-fixture offline scan test suite"
	@echo "  benchmark         - Execute detection accuracy & validation benchmark suite"
	@echo "  lint              - Run linter (go vet / golangci-lint)"
	@echo "  clean             - Remove compiled binaries and artifacts"

build:
	@mkdir -p $(BIN_DIR)
	@if pkg-config --exists yara_x_capi 2>/dev/null || [ -f /usr/local/lib/libyara_x_capi.a ] || [ -f /usr/lib/libyara_x_capi.a ] || [ -f $(USER_HOME)/.local/lib/x86_64-linux-gnu/libyara_x_capi.a ]; then \
		echo "Building unified Aether binary with static YARA-X and embedded rules..."; \
		CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lyara_x_capi -lstdc++ -Wl,-Bdynamic -lpthread -ldl -lm" go build -tags yara -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME); \
	else \
		echo "Building pure Go Aether binary (libyara_x_capi.a not found)..."; \
		CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME); \
	fi
	@echo "Binary compiled: $(BIN_DIR)/$(BINARY_NAME)"

build-pure:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Pure Go static binary compiled: $(BIN_DIR)/$(BINARY_NAME)"

build-yara-static:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lyara_x_capi -lstdc++ -Wl,-Bdynamic -lpthread -ldl -lm" go build -tags yara -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Static YARA-X binary compiled: $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME)"

build-cross:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/aether-linux-amd64 ./cmd/$(BINARY_NAME)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/aether-linux-arm64 ./cmd/$(BINARY_NAME)
	@echo "Cross-compiled Pure-Go binaries: $(BIN_DIR)/aether-linux-amd64, $(BIN_DIR)/aether-linux-arm64"

package:
	@bash scripts/package.sh

package-clean:
	rm -rf $(DIST_DIR)
	@echo "Cleaned dist/ directory."

release-verify:
	@bash scripts/verify-release.sh

release: release-verify package
	@echo "Release build and packaging completed successfully in $(DIST_DIR)/"

install: build
	@echo "Installing Aether..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		install -m 0755 $(BIN_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME); \
		echo "Aether successfully installed to /usr/local/bin/$(BINARY_NAME)"; \
	else \
		mkdir -p $(HOME)/.local/bin; \
		install -m 0755 $(BIN_DIR)/$(BINARY_NAME) $(HOME)/.local/bin/$(BINARY_NAME); \
		echo "Aether successfully installed to $(HOME)/.local/bin/$(BINARY_NAME)"; \
		echo "Ensure $(HOME)/.local/bin is in your PATH"; \
	fi

test:
	go test -v ./...

test-yara:
	CGO_LDFLAGS="-Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64 -Wl,-rpath,$(HOME)/.local/lib -Wl,-rpath,$(HOME)/.local/lib/x86_64-linux-gnu" go test -v -tags yara ./...

test-packaging:
	go test -v ./test/packaging/...

test-fixtures:
	go test -v -run TestFixtures ./internal/scanner/...

benchmark:
	go test -v ./test/benchmark/...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		go vet ./...; \
	fi

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "Cleaned build artifacts."
