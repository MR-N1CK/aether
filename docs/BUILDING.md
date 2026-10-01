# Building Aether

Aether supports two primary build modes:

1. **Standard Pure Go Build (Default)**: Fully static, zero CGO dependencies (`CGO_ENABLED=0`).
2. **YARA-X Extended Build (`-tags yara`)**: High-performance YARA-X signature scanning utilizing the official Rust-based YARA-X C API (`libyara_x_capi`).

---

## 1. Pure Go Static Build (Default)

To build the static Aether binary without any C dependencies:

```bash
make build
```

This generates `bin/aether`, which has no shared library dependencies and can run on any compatible Linux kernel.

To run tests:
```bash
make test
# or
go test -race ./...
```

---

## 2. Extended YARA-X Build (`-tags yara`)

To compile Aether with native YARA-X scanning support, you must have the `libyara_x_capi` C library and its `pkg-config` definition installed.

### Prerequisites

1. **Rust Toolchain**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **cargo-c Helper**:
   ```bash
   cargo install cargo-c
   ```

3. **Build & Install YARA-X C API**:
   ```bash
   git clone https://github.com/VirusTotal/yara-x.git
   cd yara-x
   cargo cinstall -p yara-x-capi --release --prefix=/usr/local
   ```

4. **Configure `PKG_CONFIG_PATH` and `LD_LIBRARY_PATH`**:
   ```bash
   export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:$HOME/.local/lib/pkgconfig:$HOME/.local/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH"
   export LD_LIBRARY_PATH="/usr/local/lib:/usr/local/lib64:$LD_LIBRARY_PATH"
   ```

---

## 3. Build Targets & Security Modes

### A. Production Root-Safe Build (Default `make build-yara`)
```bash
make build-yara
```
- Emits `bin/aether-yara`.
- Embeds strictly system RPATHs (`/usr/local/lib`, `/usr/local/lib64`).
- Can run safely as root or unprivileged users when `libyara_x_capi` is installed in `/usr/local/lib`.

### B. Static Linking (Preferred Release Build: `make build-yara-static`)
```bash
make build-yara-static
```
- Emits `bin/aether-yara-static`.
- Statically links `libyara_x_capi.a` into `bin/aether-yara-static`.
- **Eliminates dynamic library loading and RPATH hijacking risks completely.**
- Standalone: does not require `libyara_x_capi.so` on target systems.

### C. Local Development Build (`DEV_RPATH=1`)
```bash
make build-yara DEV_RPATH=1
```
- Emits `bin/aether-yara-dev` with `-X main.devRpath=1`.
- Embeds `$HOME/.local/lib` RPATH for unprivileged local developer testing.
- **Safety Enforcement**: Refuses to run YARA when executed as root (`euid 0`), reporting `"YARA not run: library path not trusted"`.

---

## 4. Running Tests

```bash
# Pure Go tests
make test
go test -race ./...

# YARA-X tagged tests
make test-yara
go test -race -tags yara ./...
```
