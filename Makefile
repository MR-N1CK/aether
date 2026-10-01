BINARY_NAME := aether
YARA_BINARY_NAME := aether-yara
YARA_DEV_BINARY_NAME := aether-yara-dev
YARA_STATIC_BINARY_NAME := aether-yara-static
BIN_DIR := bin
VERSION ?= 0.1.0-dev
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "standalone")
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
DEV_RPATH ?= 0

export PKG_CONFIG_PATH := /usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$(HOME)/.local/lib/pkgconfig:$(HOME)/.local/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_PATH)
export LD_LIBRARY_PATH := /usr/local/lib:/usr/local/lib64:/usr/lib/x86_64-linux-gnu:$(HOME)/.local/lib:$(HOME)/.local/lib/x86_64-linux-gnu:$(LD_LIBRARY_PATH)

LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT)' \
	-X 'main.buildDate=$(BUILD_DATE)'

ifeq ($(DEV_RPATH),1)
	YARA_TARGET_BIN := $(BIN_DIR)/$(YARA_DEV_BINARY_NAME)
	# DEV_RPATH includes user-home rpaths for local unprivileged development.
	# WARNING: Binary compiled with dev rpath refuses to run YARA when executed as root (euid 0).
	YARA_RPATH_FLAGS := -Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64 -Wl,-rpath,$(HOME)/.local/lib -Wl,-rpath,$(HOME)/.local/lib/x86_64-linux-gnu
	YARA_EXTRA_LDFLAGS := -X 'main.devRpath=1'
else
	YARA_TARGET_BIN := $(BIN_DIR)/$(YARA_BINARY_NAME)
	# Production root-safe build: strictly system paths only
	YARA_RPATH_FLAGS := -Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64
	YARA_EXTRA_LDFLAGS :=
endif

.PHONY: all build build-yara build-yara-static test test-yara lint clean help

all: build test

help:
	@echo "Aether Build Targets:"
	@echo "  build             - Compile static Linux binary (CGO_ENABLED=0)"
	@echo "  build-yara        - Compile Linux binary with YARA-X support (-tags yara)"
	@echo "                      Default: system rpaths only (bin/aether-yara)"
	@echo "                      DEV_RPATH=1: dev rpath build (bin/aether-yara-dev, refuses root)"
	@echo "  build-yara-static - Compile binary with static libyara_x_capi.a (no dynamic rpath)"
	@echo "  test              - Run all unit tests (pure Go)"
	@echo "  test-yara         - Run all unit and integration tests with -tags yara"
	@echo "  lint              - Run linter (golangci-lint or go vet)"
	@echo "  clean             - Remove compiled binaries and artifacts"

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Static binary compiled: $(BIN_DIR)/$(BINARY_NAME)"

build-yara:
	@mkdir -p $(BIN_DIR)
	@if ! pkg-config --exists yara_x_capi 2>/dev/null; then \
		echo "========================================================================"; \
		echo "ERROR: libyara_x_capi / yara_x_capi.pc not found via pkg-config."; \
		echo "To build Aether with YARA-X support:"; \
		echo "  1. Install Rust toolchain: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
		echo "  2. Install cargo-c: cargo install cargo-c"; \
		echo "  3. Clone & install yara-x-capi:"; \
		echo "       git clone https://github.com/VirusTotal/yara-x && cd yara-x"; \
		echo "       cargo cinstall -p yara-x-capi --release --prefix=/usr/local"; \
		echo "  4. Ensure PKG_CONFIG_PATH includes the installed pkgconfig directory."; \
		echo "See docs/BUILDING.md for detailed instructions."; \
		echo "========================================================================"; \
		exit 1; \
	fi
	CGO_ENABLED=1 CGO_LDFLAGS="$(YARA_RPATH_FLAGS)" go build -tags yara -trimpath -ldflags="$(LDFLAGS) $(YARA_EXTRA_LDFLAGS)" -o $(YARA_TARGET_BIN) ./cmd/$(BINARY_NAME)
	@echo "YARA-X enabled binary compiled: $(YARA_TARGET_BIN)"
	@echo "--- ldd output for $(YARA_TARGET_BIN) ---"
	@ldd $(YARA_TARGET_BIN) || true
	@echo "----------------------------------------------------"

build-yara-static:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-Bstatic -lyara_x_capi -Wl,-Bdynamic -lpthread -ldl -lm" go build -tags yara -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME) ./cmd/$(BINARY_NAME)
	@echo "Statically linked YARA-X binary compiled: $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME)"
	@echo "--- ldd output for $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME) ---"
	@ldd $(BIN_DIR)/$(YARA_STATIC_BINARY_NAME) || true
	@echo "----------------------------------------------------"

test:
	go test -v ./...

test-yara:
	CGO_LDFLAGS="-Wl,-rpath,/usr/local/lib -Wl,-rpath,/usr/local/lib64 -Wl,-rpath,$(HOME)/.local/lib -Wl,-rpath,$(HOME)/.local/lib/x86_64-linux-gnu" go test -v -tags yara ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		go vet ./...; \
	fi

clean:
	rm -rf $(BIN_DIR)
	@echo "Cleaned build artifacts."
