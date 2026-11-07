# Aether Design System — Aurora Command Deck

Design direction: **a threat-hunting cockpit that reads like a precision
instrument — calm, quiet surfaces where only threats are loud** — rendered
with cinematic Aurora Noir depth: glass panes, lit rails, and gradient
energy reserved for signal, never decoration.

This document is the single source of truth for tokens, motion, and state
design across all three user-facing surfaces (TUI, plain ANSI, HTML report).
Code references: `internal/ui/theme/theme.go`, `internal/report/palette.go`,
`internal/report/html/assets/report.css`.

---

## 1. Color system

### Elevation ladder (TUI surfaces) — Deep Ocean Teal
| Token | Hex | Role |
|---|---|---|
| `ColorVoid`     | `#0B1220` | Tier 0 — root void canvas (deep navy) |
| `ColorSurface`  | `#101828` | Tier 1 — panels, standard cards |
| `ColorRaised`   | `#16203A` | Tier 2 — headers, floating cards |
| `ColorOverlay`  | `#1D2A45` | Tier 3 — modals, active selections |
| `ColorBorder`   | `#24334F` | Hairline borders |

### Accent ramp (Aurora gradient — meters, rails, logo)
3 stops, always cold→bright, never decorative:
`#0E7490` (deep steel teal) → `#22D3EE` (electric teal) → `#E0FEFF` (ice).
Implemented by `theme.RenderGradientBar` / `theme.RenderGradientText`.
The HTML report mirrors this system: navy glass surfaces, teal accent
(`--accent: #22d3ee`), violet washes replaced by teal washes.

### Severity palette (canonical, shared by TUI + plain + HTML)
Defined once in `internal/report/palette.go`:
slate INFO · sky NOTICE · mint SAFE · amber WARNING · rose ALERT.
Never hardcode severity hex values in surface code.

---

## 2. Typography

Terminal: lipgloss defaults with a codified scale — `Title` (bold, brand
only), `Lg` (section headers), `Base` (body), `Sm`/mute (timestamps,
metadata). HTML: inline variable font (Inter subset) when size budget
allows; system stack fallback. Monospace everywhere in data columns.

---

## 3. Spacing & layout rhythm

- 4/8 rhythm: card padding `1×2` (vertical×horizontal), section gaps exactly
  one blank band (`\n\n`) in the TUI — no drifting extra lines between branches.
- Responsive tiers: `<84` compact · `84–120` standard · `120–160` Flight Deck
  · `>160` ultra-wide (theme.go `Tier*` constants).
- Every screen answers "am I safe?" within its first three lines.

---

## 4. Motion spec

| Token | Duration | Easing | Used for |
|---|---|---|---|
| `motion-fast` | 120ms | ease-out | hover, select, key feedback |
| `motion-base` | 200ms | ease-out-quart | panels, drawer, modal open |
| `motion-slow` | 300ms | ease-out-quart | verdict, state change |
| `motion-draw` | 600ms | ease-out-quart | chart draw-on, gauge fill |

CSS easing reference: `cubic-bezier(0.22, 1, 0.36, 1)`.

TUI motion runs on the existing 60 FPS tick (model.go `tick60FPS`) with
graceful degradation: 8 FPS idle power-saver, static under `--no-anim`,
NO_COLOR, or non-TTY. All TUI animation is *state-driven* (selection pulse,
verdict gauge fill, sweep bars) — never ambient decoration.

Reduced motion: HTML freezes all animation under `prefers-reduced-motion`;
TUI offers `--no-anim`; both render final-state visuals.

---

## 5. Feedback states

| State | TUI | HTML |
|---|---|---|
| Loading | Module matrix: spinner + "Loading rules…", sweep bars per running module | Skeleton shimmer on cards before data mount |
| Empty | "✓ No indicators detected" + coverage chips of what was checked | Coverage section + empty-state copy in feed |
| Error | Module row turns rose with `IconCross`; stderr excerpt in dossier | Module health row with expandable detail |
| Success | Verdict banner, gauge fills over 600ms ease-out-quart | Verdict hero with `verdict-in` entrance |

---

## 6. Interaction

- Mouse: click tabs to switch, click row to select, click again for dossier
  (Flight-Deck layout; keyboard always equivalent).
- Keyboard: `1-5` tabs · `j/k` nav · `Enter` dossier · `/` filter ·
  `s` sort · `p/y/c` yank (OSC 52 fallback) · `?` palette · `q` quit.
- HTML: `/` search, `e` export CSV, `t` theme toggle, scrollspy mini-nav,
  focus-trapped drawer.
- Plain output: OSC 8 clickable `file://` paths when stdout is a TTY.
