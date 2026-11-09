# Aether — Architecture Review, Technical Evaluation & Redesign Proposal

**Date:** 2026-11-04 · **Scope:** full repository at working tree `cdcd911` + 34 uncommitted modified files
**Method:** static code reading + real verification runs (build, test suite, live fixture scans). No project source was modified.
**Verification commands actually executed:**

| Command | Result |
|---|---|
| `CGO_ENABLED=0 go build ./cmd/aether` | OK |
| `go vet ./...` | OK, zero findings |
| `go test ./...` (default timeout) | **FAIL `aether/internal/scanner` 600.044s** (default 10-min timeout panic) — all 12 other packages OK |
| `go test -timeout 25m ./internal/scanner/` | **OK 169.317s** — so the failure is timeout, not deadlock |
| Live scan: `aether scan --quick --plain --no-report testdata/fixtures/clean_debian` | Ran clean, 6.7s, produced verdict (see Accuracy §A3) |
| Live scan with `--html-out` | 812 KB self-contained HTML, mode 0600, CSP nonce present |

---

# PART 1 — Understand the tool

## What it is, and who it is for

Aether is a **read-only Linux threat-hunting and compromise-assessment scanner** written in Go (module `aether`, Go 1.26.8, `go.mod`), positioned as a THOR-Lite-inspired endpoint triage tool (`cmd/aether/main.go:537-543`). It inspects a live (or mounted offline image via `--root`) Linux endpoint for: reverse shells, web shells, ransomware encryptors, exfiltration stealers, rogue persistence (systemd/cron/SSH/PAM/profiles/udev/sudoers/APT hooks), unauthorized accounts, kernel-module rootkit artifacts, fileless execution (`/memfd:`, deleted binaries), and hash/path IOC matches.

**Target users:** Linux system administrators, incident responders, and security-minded power users running triage on their own hosts or mounted forensic images — not an EDR agent, not a real-time monitor. This is a *point-in-time scanner*.

## Architecture and data flow

```
cmd/aether/main.go (cobra CLI: scan/quick/full/setup/update/ack/rules/intel/demo)
        │ builds config.Config (YAML + 27 flags), EventBus, ConcurrentReporter
        ▼
internal/scanner (Scanner.Run orchestrator)
  ├─ ResolveTargets() → quick/full/custom path sets (config.go:295-324)
  ├─ runModules() → 7 live modules (internal/modules/*)
  │     process · persistence · users · network · kernel · container (+filesystem below)
  │     each module publishes FindingRaised events through a busReporter
  ├─ filesystem pipeline (scanner.go:~880-1000)
  │     walker (one-FS, excludes, swap skip) → fileChan → worker pool (N threads,
  │     watchdog: 30s/file timeout, abandon+replace, cap 8, degraded-coverage notice)
  │     per file: inspectFileWithOversize (inspect.go:30)
  │       safeopen open (O_NOFOLLOW|O_NOATIME|O_NONBLOCK|O_CLOEXEC, regular-file
  │         fstat check, size pre-check) → hash (dev,ino)-deduped SHA256/SHA1/MD5
  │       → IOC hash/path/benign/allowlist checks (internal/ioc)
  │       → native heuristics (heuristics.go: 17 regex families + ELF/SUID/world-writable)
  │       → ELF structural analysis (elf_analysis.go, entropy, RPATH hijack, UPX)
  │       → layered decode & re-scan (decode.go: base64/hex/rev/gzip/zlib, depth ≤3,
  │         ≤50 candidates) feeding YARA again
  │       → YARA engine scan (internal/yara: YARA-X via cgo when built -tags yara,
  │         otherwise the pure-Go FallbackEngine interpreting the same embedded rules)
  │       → finding consolidation (score/max severity/corroboration) → accumulator groups
  └─ correlation & verdict: internal/report/verdict.go (evidence-strength state machine),
        internal/report/correlate.go, triage ack engine, FP filters, baseline delta
        ▼
internal/events (EventBus: lossless critical queue + droppable ephemeral)
        ▼
Consumers: TUI (bubbletea/lipgloss) · plain ANSI cards · JSON stream reporter ·
           self-contained HTML report (CSP nonce, no innerHTML) · executive assessment
           (internal/realworld/assessment.go) · baseline snapshot / delta mode
```

**Languages & dependencies:** Go only (+ embedded YARA rule source; optional cgo link to `libyara_x_capi`). Key deps: `VirusTotal/yara-x/go`, `spf13/cobra`, `charmbracelet` bubbletea/bubbles/lipgloss stack, `golang.org/x/sys`, `gopkg.in/yaml.v3`. Zero web framework, zero telemetry.

**Notable engineering assets:** `internal/safeopen` (forensic open semantics + chroot-style `ResolveUnderRoot` with 40-hop symlink-loop detection and confinement check, safeopen.go:160-262), `internal/scanner/memory_budget.go` (pooled, context-aware buffer budget), `internal/triage` (hash-pinned acknowledgments, ALERT/IOC non-ackable), `internal/pkgdb` (dpkg ownership verification), 561 test functions, golden-fixture corpus (`testdata/fixtures`: clean_debian, compromised_cron, preload_rootkit, multi_persistence…), benchmark + real-world harness (`internal/benchmark`, `internal/realworld` with race harness), packaging + release-verify scripts, CI matrix (ubuntu x86_64/arm64 + Debian 12 container, gofmt/vet/build/test/race).

## Current status: **beta** — high-quality, not yet production-ready

**Beyond prototype:** 561 test functions with fixture corpora, cross-engine parity tests (`fallback_parity_test.go`), registry-coverage tests that fail when a rule lacks report metadata (`registry_coverage_test.go`), packaging/verification pipeline, benchmark and race harnesses, reproducible-build support, real-world evaluation taxonomy.

**Short of production:**
1. `make test` (Makefile `test:` target, no `-timeout` flag) **fails on this machine** at the default 10-min Go test timeout, while CI passes only because it uses `-timeout 20m`. A reproducible red `make test` is a release blocker.
2. Several core tests are **not hermetic** — e.g. `TestScanner_ModuleFindingsCount_MatchesEmittedFindings` (scope_test.go:166) runs a live `--quick` scan of `/tmp`, `/etc`, `/home/*/.ssh`, `/root` of the *test machine*; runtime is machine-dependent.
3. **FP calibration on non-Kali hosts** (demonstrated live below, §A3): the process module and multi-vector correlation escalated a clean dev workstation to "COMPROMISED, risk 100/100, CRITICAL".
4. README admits "Not yet tested: Ubuntu, Debian, Arch, arm64, kernels 5.x/6.x" while claiming "kernel 7.1.5+kali" (a kernel version that does not exist — likely a typo) and "License: TBD" although the repo ships Apache-2.0.
5. No signed releases/tag policy yet (VERSION defaults 1.0.0 in Makefile despite pre-1.0 maturity signals).

---

# PART 2 — Technical evaluation

## Accuracy — **7.5 / 10**

**Strong evidence:**
- Dual-engine consistency: fallback and YARA-X compile the identical embedded source (18 rules, embedded_rules.go) and `fallback_parity_test.go` asserts identical verdicts; scoring thresholds shared via `ScoreFromMeta` (yara.go:85).
- Verdict engine is evidence-tiered, not score-only: DIRECT / CORROBORATED / CONTEXTUAL / INCOMPLETE strength (finding.go:59-77), package-ownership and context profiles (doc_metadata, historical_artifact, package_test, build_tree, vendor_app_tree) with hash-IOC matches never softened (verdict.go:13-31, 171-181).
- Corroboration gating: a lone static anomaly stays SUSPICIOUS; escalation requires two independent signals (heuristics.go:24-30) or operational corroboration.
- Golden fixtures + benign corpus tests (`benign_corpus_test.go`, `elf_system_corpus_test.go`, `fpfilter_test.go`, `corroboration_test.go`).

**Where it can be wrong or misleading (all observed in code or live runs):**
- **A1. Non-hermetic accuracy tests.** `scope_test.go:166-213` scans the live host; results depend on what the developer has running. It passed in isolation (169.3s) but contributed to the 10-min full-suite timeout — CI variance risk.
- **A2. Regex breadth.** Heuristics use wide cross-line windows, e.g. `reDataExfiltration` with `[\s\S]{0,1000}` bridges (heuristics.go:502). Vendor-tree/doc/test demotion (verdict.go:15-70) mitigates, but unusual benign code layouts can still surface as warnings.
- **A3. Live FP calibration on developer hosts (verified).** Scanning the repo's own `clean_debian` fixture *on this workstation* produced 2 Alerts / 29 Warnings / 20 Notices and a final banner "COMPROMISED … (Persistence_Multi_Vector_Persistence)", risk score 100/100. Root causes in code:
  - `Process_Anonymous_RWX_Memory_Injection` and `Process_Interactive_Reverse_Shell` fire on legitimate software (Electron/Chromium JIT keeps anon RWX regions; monitoring agents hold socket-backed stdio) — process/detections.go.
  - `Persistence_Multi_Vector_Persistence` (persistence.go:260-400) escalates when a payload is referenced by **≥3 mechanisms** and is hidden, missing, or **unowned** — benign user tooling in hidden home paths referenced by user units + profile + cron satisfies this on dev machines.
  - Risk math (plain/verdict.go:29-45): `alerts×25 + warnings×5 + notices×1`, capped 100, "CRITICAL" whenever `alerts>0 || score≥25` → **5 warnings alone already display CRITICAL**, which erodes trust in the number.
- **A4. Fallback-engine subset.** External user rules are parsed by a YARA *subset* parser (fallback_parse.go; tags unsupported per comment in fallback_engine.go ruleDisabled) — user rules outside the subset are skipped-with-count, not error, which can silently reduce coverage (visible in coverage stats, but easy to miss).

## Reliability — **7 / 10**

**Strong:** explicit error taxonomy (`ErrOversizeFile/ErrPermission/ErrVanished/ErrNotRegularFile`, safeopen.go:13-21); worker watchdog abandons a stuck file, spawns a replacement, caps at 8 and announces degraded coverage (scanner.go:157-180, 990-1030); per-file 30s timeout; memory budget blocks with context cancellation (memory_budget.go:60-100); event bus guarantees lossless critical delivery and drops only ephemeral telemetry (bus.go:120-140); graceful SIGINT/SIGTERM via `signal.NotifyContext`; baseline load failure degrades to "no delta mode" with a warning rather than aborting (scanner.go:~600); FP-filter load failure is fail-closed (filters disabled, findings stay visible); HTML written atomically 0600 with symlink refusal (html.go WriteHTMLReport).

**Weak:**
- **R1. `make test` red by default** (Makefile `test: go test -v ./...` lacks the `-timeout 20m` CI uses). Verified failing here; isolated re-run passes. Also `test` runs with `-v` making CI logs enormous.
- **R2. Non-hermetic suite** (same tests as A1) — reliability of CI, not just runtime.
- **R3.** `busReporter.Summary()` returns five zeros (scanner.go:~420) — a dead stub kept to satisfy the Reporter interface; harmless but a trap for future callers.
- **R4.** `WithBuildInfo(version, info ...string)` silently mis-binds when called with 2 variadic args (scanner.go options) — latent API wart; main.go currently passes 3 and works.
- **R5.** Filter input in the TUI handles only runes/backspace (model.go:435-455) — no cursor movement; surprising but not a crash.
- No crash risks found in reviewed paths: no unchecked index arithmetic on untrusted input spotted; regexes are RE2 (linear); decode depth/candidate/size caps are enforced.

## Efficiency — **6.5 / 10**

**Strong:** worker pool with buffered channel; hardlink dedup by (dev,ino) so a file is hashed once; 5-class pooled buffers charged against a 256 MB budget; oversize files hash-only up to 2 GB (`--hash-oversize-max`), YARA capped at 20 MB, inspection capped at 50 MB; script scanning chunked 1 MB/64 KB overlap with 16 MB cap (heuristics.go:874-905); decode depth ≤3, ≤50 candidates, ≤32 MB decompressed (decode.go:23-26); `--one-file-system` default for `--full`; per-module `--modules` selection; quick mode restricts to high-risk paths.

**Bottlenecks (measured/observed):**
- **E1. Pure-Go fallback engine pays regex on every candidate file.** The timeout goroutine dump and `top` (193% CPU for the test binary) show `regexp.FindIndex` inside `fallbackPatternMatches` and `DecodeAndRescanWithYARA` as the hot path. YARA builds get a native Aho-Corasick; the default pure-Go build has **no shared literal prefilter** across the ~17 rule regexes. A single AC automaton over all literal alternates would reject most files before any regex runs.
- **E2.** Decode-and-rescan triggers on any text candidate ≥16 B containing a ≥32-char base64/hex run — common in legitimate files (configs, JSON tokens, certs) — and can evaluate up to 50 candidates per file.
- **E3.** Full-suite test wall time (10+ min, CPU-saturated) is itself a productivity tax traced to E1/E2-style scanning inside hermetic-less tests.

## Code quality & maintainability — **7.5 / 10**

**Strong:** clean package boundaries with dependency injection options (`WithYARAEngine`, `WithPackageDB`, …); event-driven decoupling between scanner and 4 output surfaces; unusually good *why*-comments (e.g. build-tree FP logic heuristics.go:210-240; NUL-padded script evasion gate heuristics.go:803-808; weakest-link condition design in embedded_rules.go); gofmt-clean, `go vet` clean; CI matrix incl. arm64 and Debian-container compat; race tests; benchmarks with a mutation harness; design tokens centralized in theme.go + report/palette.go with DESIGN.md as source of truth.

**Debt:**
- **Q1.** `cmd/aether/main.go` is 1,273 lines; `executeScan` copies ~27 flags into config one `if cmd.Flags().Changed(...)` at a time (main.go:~186-330) — a binding table or cobra `Flags().Visit` loop would remove ~150 lines and a class of copy-paste bugs.
- **Q2.** `internal/scanner/scanner.go` (1,697 lines) mixes worker-pool tracker, accumulator, busReporter, target resolution, and orchestration; `view.go` (2,015 lines) hand-mirrors rendered geometry for mouse hit-testing (documented, but two sources of truth).
- **Q3. Severity taxonomy sprawl:** 8 levels defined (finding.go:15-25: CRITICAL…INFO) but the theme styles only 4 badges and tab buckets collapse HIGH/MEDIUM into "anomalies" (view.go tabLabels) — the extra levels are mostly noise.
- **Q4.** README hygiene: "License: TBD" vs Apache-2.0 LICENSE; "kernel 7.1.5+kali" is not a real kernel version.
- **Q5.** 34 files modified uncommitted in the working tree — release discipline (tag/commit cadence) lags the code velocity.

## Security — **8.5 / 10**

**Strong (this is the project's best dimension):**
- Read-only invariant engineered, not promised: `O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW|O_NOATIME` with EPERM fallback, fstat regular-file verification, size pre-check, and on failure the fd is closed (safeopen.go:60-120). Offline root mode adds chroot-style resolution with loop detection (max 40 hops) and a final confinement invariant (safeopen.go:174-262).
- Rules-directory trust qualification: non-root-owned or world-writable rule paths rejected unless `--trust-rules-dir` (lib_trust.go); rule self-match prevention; pentest-dir downgrade is opt-in (`--trust-installed-pentest-tools`).
- Report security: strict CSP `default-src 'none'; script-src 'nonce-…'` with `crypto/rand` nonce, `<` escaped as `\u003c` in the embedded JSON blob (html.go:533) — kills the classic `</script>` breakout; DOM built with createElement/textContent only (app.js contract comment html.go:1323); atomic 0600 writes.
- `aether ack` is hash-pinned (file, symlink target, unit Exec targets, matched line) and voids on change; ALERT and IOC findings are non-ackable (main.go:775+; triage.go).
- Redaction of hosts/users/home paths for JSON+HTML (`--redact-hosts`); demo EICAR rules opt-in; no implicit network egress — `update --intel-url` is the only remote fetch path and is operator-invoked.

**Minor:**
- **S1.** TUI `openHTMLReport` spawns `xdg-open` on a candidate path with no confirmation (model.go:1004-1017) — low risk, but an unguarded process spawn from an interactive tool.
- **S2.** Demo path uses non-seeded `math/rand` (fine functionally; not security-relevant, listed for completeness).
- **S3.** `nice` silently degrades to a warning if unsupported — acceptable, worth surfacing in coverage notes.

## Overall — **7.3 / 10**

**Verdict:** Aether's *forensic core* (safeopen, dual-engine signatures, evidence-tiered verdicts, acknowledgment pinning) is production-grade engineering with unusually honest self-limitation documentation. What holds it back from production-ready is calibration and process, not architecture: live-FP tuning on ordinary developer/desktop hosts, hermetic tests, the default `make test` timeout failure, and executive-risk math that overstates ("CRITICAL" from 5 warnings, "COMPROMISED" from benign multi-vector persistence on unowned user tooling). Fix the HIGH-priority items in Part 3 and it is a credible open-source THOR Lite alternative.

---

# PART 3 — Improvements (priority order)

| # | Priority | Improvement | What to change | Why it matters | Effort |
|---|---|---|---|---|---|
| 1 | **High** | Make `make test` green by default | Add `-timeout 20m` (match CI) to `test`/`test-yara` targets; drop `-v` or route to `go test -json` for CI | A red default entry point destroys contributor trust; verified failing today | S |
| 2 | **High** | Hermetic scanner tests | Fixture-rooted targets (or `testing.Short()` guard + tmpfs fixtures) for `scope_test.go` live-scan tests | Machine-dependent CI + 3-min package wall time | M |
| 3 | **High** | Recalibrate executive risk & verdict | Rework `plain/verdict.go:29-45` (no CRITICAL from warnings-only; weight by verdict/strength not raw counts); require a *strong* signal (exec-bit payload, missing+exec, or ≥1 non-notice hit on the payload) before `Persistence_Multi_Vector_Persistence` escalates (persistence.go:260-400) | Trust: today a clean dev box reports COMPROMISED 100/100 (verified) | M |
| 4 | **High** | Process-module FP waiver profile | Built-in `--profile developer/desktop` waiving Electron/Chromium RWX-JIT and known monitoring agents (hash+path scoped, reported as waived in coverage); extend the existing fp-filters YAML mechanism | 29/60 findings on a clean fixture were workstation software | M |
| 5 | **High** | Fallback-engine literal prefilter | Shared Aho-Corasick/Boyer-Moore gate over all rule literal alternates (and regex literal prefixes) before `FindIndex`; benchmark with `internal/benchmark` | Default build throughput; removes the measured hot loop | M |
| 6 | Medium | Split main.go flag plumbing | Table-driven flag→config binding shared by scan/quick/full | ~150 fewer lines; kills copy-paste drift | S–M |
| 7 | Medium | Collapse severity taxonomy to 5 | INFO/NOTICE/WARNING/ALERT/CRITICAL; single mapping table feeding badges, tabs, HTML; keep aliases for old names | 8 levels vs 4 badge styles is incoherent UX and code | M |
| 8 | Medium | Race & hermetic CI expansion | `-race -short` across all packages; add realworld corpus job with cached fixtures | Race coverage currently only 3 package groups | S |
| 9 | Medium | TUI filter input upgrade | Use `bubbles/textinput` (cursor, Ctrl+A/E/W/U), live match count, `Esc Esc` clear | Filter is a primary analyst flow | S |
| 10 | Medium | Scan ETA & scope preview | Show targets + file-count estimate at start, ETA from rolling throughput | "How long will this take?" is the first operator question | S |
| 11 | Medium | README/release hygiene | Fix license section, kernel claim, add RELEASE.md + `git tag` policy, commit the 34 dirty files or rebase them | Credibility for adopters | S |
| 12 | Low | Guard `openHTMLReport` | Confirm toast or `--open-report=false` default | Unguarded process spawn | S |
| 13 | Low | Interface cleanup | Remove `busReporter.Summary()` stub; split Reporter interfaces | Dead code invites misuse | S |
| 14 | Low | Extension-gated YARA skip | Skip YARA for known binary-media extensions outside volatile paths (keep hash) | Small throughput win | S |
| 15 | Low | arm64 YARA static build | Package `aether-yara-static-arm64` in `scripts/package.sh` | Coverage parity on ARM servers | M |

---

# PART 4 — UI/UX review & redesign proposal

## Current state (evidence-based)

The TUI is already well above typical terminal-tool quality: obsidian 4-tier elevation palette (theme.go:60-79), zero-emoji geometric glyph set (theme.go:34-50), adaptive 4-tier responsive layout (TierCompact/Standard/Wide/UltraWide, theme.go:22-26), 60 FPS render loop with idle power-saver, guarded quit, command palette, mouse hit-testing with documented geometry mirroring, severity-only-loud color discipline. DESIGN.md ("Aurora Command Deck") already codifies tokens, motion (120/200/300/600 ms, ease-out-quart), and feedback states, and the HTML report implements CSP nonce, no-innerHTML DOM, focus-trapped drawer, theme toggle, print support.

**Real weaknesses found in code:**
1. **Trust gap in numbers** — "CRITICAL (100/100)" reachable from warnings only (plain/verdict.go:29-45); the risk meter contradicts the finding list a user can see.
2. **Splash friction** — animated splash with "Press any key" gate before every interactive run; power users will immediately alias `--no-anim`.
3. **Severity surfaces disagree** — 8 finding severities, 4 badge styles, tab buckets collapse three levels; HTML/plain/TUI each re-bucket slightly differently.
4. **Filter input is bare-bones** (no cursor editing), and compact layouts lose row-click support (documented in view.go dashFeedGeom comments).
5. **No sense of scope/ETA** — files/sec and counts exist, but no "scanning 12 targets, ~N files, ~3 min remaining" orientation line.
6. **Information density vs hierarchy** — the Flight Deck shows everything at once at ≥120 cols; first-run users get no progressive disclosure (summary → threats → dossier) unless they learn tabs 1–5.
7. Empty/error states are good in DESIGN.md spec; the plain card output is excellent; the HTML report is genuinely strong. The redesign should focus on **trust, orientation, and progressive disclosure**, not a visual from-scratch.

## Design direction (one sentence)

**"A precision instrument, not an alarm system: calm obsidian surfaces where severity color is the only loud element and every number shown is one the analyst can defend."**

## Three style options

| Option | Concept | Key changes | Risk/effort |
|---|---|---|---|
| **A. Flight Deck 2.0** (evolve current) | Keep Aurora Noir cockpit; fix trust & orientation | Sticky telemetry rail with scope+ETA; verdict hero driven by *verdict/strength*, not raw counts; consistent 5-severity tokens everywhere; splash auto-dismiss ≤800 ms; staggered row enter (20 ms/row, cap 8); count-up stats (300 ms) | Low risk, M effort — pure refinement, no layout rewrite |
| **B. Analyst Console** (calm re-orientation) | Reading-first: summary card → top-5 actions → details on demand | Replace always-on 3-pane with two-mode layout: "Overview" (posture, deltas, top actions) and "Workbench" (current Flight Deck) toggled by `Tab`; dossier becomes the primary surface with side-by-side evidence; tighter typographic scale (11/13/18), more whitespace, color only in badges + left rails | Medium risk, L effort — changes information architecture and hit-testing |
| **C. Terminal Classic** (density for responders) | 80×24-first, mouse-optional, scriptable output parity | Monochrome base + single accent; severity via glyphs+text, not color; everything reachable by keyboard; plain output promoted to first-class; TUI becomes an optional layer | Low risk, M effort — but discards current visual identity |

**My recommendation:** **A** — it keeps the existing identity users already have, targets the actual weaknesses (trust, orientation, coherence), and reuses DESIGN.md tokens and the existing component inventory.

## Cross-cutting specs (apply to any option)

- **Color:** keep the elevation ladder; map severities to 5 tokens (slate/sky/amber/rose + new deep-rose CRITICAL) defined once in `report/palette.go`; every text token ≥ WCAG AA on its tier; geometric glyphs stay (already color-blind-friendly).
- **Typography:** TUI scale 11 (meta, muted) / 13 (body) / 18 (display, brand only); tabular numerals for all counters; monospace only for paths, hashes, commands. HTML: Inter variable + JetBrains Mono.
- **Spacing:** 4/8 rhythm; card padding 1×2; exactly one blank band between sections (already specified in DESIGN.md — enforce with a layout lint test).
- **Motion:** 120 ms ease-out (hover/select) · 200 ms (modal/drawer) · 300 ms (verdict change) · 600 ms (gauge fill); list stagger 20 ms/row cap 8; alert pulse decays in 1.5 s (exists); all state-driven, `--no-anim` + `prefers-reduced-motion` render final state (exists).
- **Feedback states:** loading = per-module sweep bars (exists) + new scope/ETA line; empty = "✓ No indicators detected" + coverage chips (exists) + *what was not scanned* (new); error = module row rose + stderr excerpt in dossier (exists) + retry hint; success = verdict hero with strength rationale (exists) + honest risk math (fix §A3).
- **Keyboard:** add `gg/G` jump, `o` open report (guarded), `w` copy remediation command, `Esc Esc` clear filter; keep existing 1–5/j/k/Enter//,s,p/y/c,?,q map; show cheat-sheet in `?` palette (exists).
- **Accessibility:** NO_COLOR, `--ascii`, OSC 52 yank with fallback, mouse+keyboard parity (exists); add aria-live to HTML verdict hero; verify focus order in drawer (exists per DESIGN.md).
- **Responsiveness:** keep 84/120/160 tiers; restore row-click support in compact tier or formally document keyboard-only below 84 cols.

---

# PART 5 — Step-by-step implementation plan (pending your approval; no code written yet)

Per AGENTS.md §5, this plan is a proposal — implementation starts only after you approve scope and choose a design direction.

**Phase 0 — Verification debt (days 1–2)**
1. Add `-timeout 20m` to Makefile test targets; align CI and Makefile (Improvement #1).
2. Guard live-scan tests with fixture-rooted targets or `testing.Short()` (#2); add benign-workstation corpus entries (Electron, agent sockets) to `benign_corpus_test.go`.
3. Commit/stash the 34 dirty files; fix README license + kernel claim (#11).

**Phase 1 — Trust recalibration (days 3–7)**
4. Rework risk score & verdict thresholds (plain/verdict.go, realworld/assessment.go) with table-driven weights; add regression tests: warnings-only ≠ CRITICAL (#3).
5. Gate `Persistence_Multi_Vector_Persistence` on payload strength signals (#3); add fixtures for benign-multi-vector.
6. Add `--profile developer` FP waivers for process-module findings (#4), reported transparently as waived findings.

**Phase 2 — Throughput (days 8–12)**
7. Shared literal prefilter for the fallback engine (#5); wire into `internal/benchmark` before/after.

**Phase 3 — UX pass (days 13–20, design-option dependent)**
8. Unify severity tokens (5-level) across theme/plain/TUI/HTML (#7).
9. Implement chosen design option (A/B/C above): telemetry rail with scope+ETA (#10), splash auto-dismiss, filter input upgrade (#9), motion stagger, empty/error copy.
10. Keyboard additions + updated `?` cheat-sheet; a11y checks.

**Phase 4 — Structure & release (days 21–25)**
11. Table-driven flag binding in main.go (#6); interface cleanup (#12, #13).
12. Race-coverage expansion (#8); release checklist: tag policy, signed artifacts, package arm64 YARA build (#15).

**Verification strategy for every phase:** `go vet ./... && gofmt -l . && go build ./... && go test -timeout 20m ./...` green, plus the benchmark suite for Phase 2 and golden-fixture HTML diffs for Phase 3.

**Acceptance criteria:** (a) `make test` green by default on a clean clone; (b) clean-fixture scan on a developer workstation reports no CRITICAL/COMPROMISED without a DIRECT/CORROBORATED finding; (c) fallback-engine files/sec ≥ 3× current on the benchmark corpus; (d) all three output surfaces show identical severity bucketing; (e) every new behavior has a table-driven test.
