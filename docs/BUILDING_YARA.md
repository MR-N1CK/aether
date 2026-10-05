# Building Aether with YARA-X (`docs/BUILDING_YARA.md`)

Aether integrates **YARA-X** via the official Rust C-API (`libyara_x_capi`).

---

## 1. Default YARA Build: `make build-yara-static`

Going forward, **`make build-yara-static` is the documented default and recommended build target for YARA-X**.

```bash
make build-yara-static
```

This generates `bin/aether-yara-static`.

### Why Static Linking is the Default
1. **No Runtime Library Trust Issues**: Statically embeds `libyara_x_capi.a` directly into the binary.
2. **Zero Dynamic Dependency**: Eliminates reliance on `libyara_x_capi.so` on target systems.
3. **Root-Safe Execution**: Eliminates RPATH lookup vulnerabilities and avoids `/proc/self/maps` unverified library path rejections when scanning as root (`euid 0`).
4. **Zero Impact on Default Build**: The default `make build` remains pure Go (`CGO_ENABLED=0`) with zero C/CGO dependencies.

---

## 2. Prerequisites & Building `libyara_x_capi`

To compile with YARA-X support, you need the Rust toolchain and `cargo-c`.

### Step 1: Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Step 2: Install `cargo-c`
```bash
cargo install cargo-c
```

### Step 3: Clone and Install `yara-x-capi`
Clone the `yara-x` repository and install the C-API library:

```bash
git clone https://github.com/VirusTotal/yara-x.git
cd yara-x
git checkout v1.21.0
```

#### Option A: User-Local Install (Recommended for unprivileged development)
```bash
cargo cinstall -p yara-x-capi --release --prefix="$HOME/.local"
```

#### Option B: System-Wide Install (Requires sudo)
```bash
sudo cargo cinstall -p yara-x-capi --release --prefix=/usr/local
```

### Step 4: Environment Variables
Ensure `PKG_CONFIG_PATH` points to the directory containing `yara_x_capi.pc`:

```bash
export PKG_CONFIG_PATH="$HOME/.local/lib/x86_64-linux-gnu/pkgconfig:$HOME/.local/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:$PKG_CONFIG_PATH"
```

The Aether `Makefile` automatically includes these standard locations in `PKG_CONFIG_PATH`.

---

## 3. Build Targets Summary

| Target | Binary Emitted | Build Mode | Description |
|---|---|---|---|
| `make build` | `bin/aether` | Pure Go (`CGO_ENABLED=0`) | Default static Linux binary. Zero CGO dependencies. |
| `make build-yara-static` | `bin/aether-yara-static` | CGO (`-tags yara`) | **Default YARA target.** Statically links `libyara_x_capi.a`. |
| `make build-yara` | `bin/aether-yara` | CGO (`-tags yara`) | Dynamically links `libyara_x_capi.so` using system RPATHs (`/usr/local/lib`). |
| `make build-yara DEV_RPATH=1` | `bin/aether-yara-dev` | CGO (`-tags yara`) | Local unprivileged dev build with user-home RPATH (refuses root execution). |

---

## 4. Verification & Testing

### Verify Version Output
```bash
./bin/aether-yara-static version
```
Expected output confirms YARA compilation:
```text
Aether Threat Hunter v0.1.0-dev
  Commit:     ...
  Build Date: ...
  Go Version: go1.x.y
  OS/Arch:    linux/amd64
  YARA:       YARA-X v1.21.0
```

### Run Unit and Integration Tests
```bash
# Pure Go unit tests (without yara tag)
make test
go test -race ./...

# Full test suite including YARA-X engine & integration tests
make test-yara
go test -race -tags yara ./...

# Golden fixture offline forensic tests
make test-fixtures
```
