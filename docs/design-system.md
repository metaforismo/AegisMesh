# Design system and console UI

The operator console (`internal/consoleui`) and the project site (`site/`)
share one set of tokens and components. This document is the written
reference. `site/design-system.html` shows every component rendered.

## Files

| Path | Role |
|---|---|
| `internal/consoleui/static/assets/css/tokens.css` | Design tokens: type, space, radii, motion, layers, light and dark color |
| `internal/consoleui/static/assets/css/base.css` | Reset, document type, focus ring, `.visually-hidden`, skip link, reduced motion |
| `internal/consoleui/static/assets/css/components.css` | Component library (inventory below) |
| `internal/consoleui/static/assets/css/app.css` | Console screen layout only |
| `site/assets/css/{tokens,base,components}.css` | Byte-identical copies for the site. `webtest/site.test.mjs` fails if they drift: edit the console copy, then copy it over |
| `site/assets/css/site.css` | Landing page and reference-page layout |

There is no build step, no npm dependency and no third-party code. The console
is plain HTML, CSS and ES modules embedded into the binary with `go:embed`.

## Principles

1. **Evidence is never interface.** Every string the API marks as
   attacker-controlled (paths, previews, user agents, tool names, summaries,
   source keys) is rendered with `.evidence`: monospace on a faint violet
   inset. It is only ever a Text node. Interface text, ids and rule-authored
   reasons never use it.
2. **Never color alone.** Severity is a five-segment meter plus a word.
   Classification is a glyph shape (circle, diamond, triangle) plus a word.
   State badges also change dot shape. Charts always carry a legend, glyph
   shapes and a table view.
3. **Neutral numbers.** Changes against the previous window are shown in ink,
   not red or green. More observations are not "bad" and fewer are not
   "good".
4. **Calm and dense.** Cool graphite neutrals, one cobalt accent, a 13–14px UI
   body, a 4px spacing grid. Times are always UTC.
5. **Honest copy.** Events are observations, not incidents. Recommendations
   are labelled "proposed, not executed". Limits (bounded index, single node,
   what the audit chain proves) are stated where they matter.

## Tokens

### Color and measured contrast

Ratios are WCAG 2 contrast, computed from the token values (not estimated).

| Token | Light | Dark | Use |
|---|---|---|---|
| `--color-ink` | 16.43:1 on surface | 14.46:1 | Primary text |
| `--color-ink-2` | 9.02:1 | 9.52:1 | Secondary text |
| `--color-ink-3` | 5.66:1 (4.99:1 on canvas) | 6.15:1 (5.75:1 on surface-2) | Muted text, never below 4.5:1 |
| `--color-accent` | 6.82:1; white on it 6.82:1 | 7.39:1; ink-inverse on it 7.97:1 | Links, primary action, focus |
| `--color-evidence-ink` | 13.18:1 on evidence-bg | 12.27:1 | Evidence text |
| `--color-border-strong` | 3.59:1 on surface, 3.17:1 on canvas | 3.44:1, 3.22:1 on surface-2 | Control edges (WCAG 1.4.11) |
| Status inks (`ok`, `warn`, `danger`, `info`) | ≥ 4.69:1 on their `-soft` fill | ≥ 6.00:1 | Badges and banners |
| Severity fills `--sev-*` | ≥ 3.41:1 on surface, ≥ 3.20:1 on surface-2 | ≥ 4.75:1; ≥ 3.40:1 on the meter track | Meter segments |

Status colors describe UI state only. They are never used for severity or as
a chart series.

### Classification series

`--class-interaction`, `--class-canary`, `--class-signal` are categorical slots
1–3 in a fixed order. They were run through the dataviz palette validator
(lightness band, chroma floor, adjacent color-vision-deficiency separation,
normal-vision floor, contrast) against the surface each theme actually uses:

| Theme | Surface | Result |
|---|---|---|
| Light | `#ffffff` | All checks pass. Worst adjacent CVD ΔE 9.2 (deutan), normal-vision ΔE 27.6. Signal green is 2.82:1 on the surface (contrast warning), so the table view and legend are required, not optional |
| Dark | `#151b24` | All checks pass. Worst adjacent CVD ΔE 9.4 (deutan), normal-vision ΔE 26.5, all ≥ 3:1 |

Color follows the entity: a filter never repaints the remaining series.

### Type, space, shape, motion

- `--font-sans` and `--font-mono` are system stacks; nothing is fetched.
- Scale from a 14px base: `--text-2xs` 11 … `--text-4xl` 52. Body numerals are
  tabular.
- Space is a 4px grid (`--space-1` = 4px … `--space-24` = 96px).
- Radii encode hierarchy: chips 2px, controls 4px, panels 6px, dialogs 10px.
- Motion durations are 80–320ms and drop to 0 under
  `prefers-reduced-motion`.

### Theme resolution

Light by default, dark when the OS prefers it, and an explicit
`data-theme="light|dark"` on `<html>` always wins. The console's theme button
cycles System → Light → Dark and remembers the choice in `localStorage`
(a convenience only; nothing else is stored in the browser).

## Component inventory

| Class | What it is | Rules |
|---|---|---|
| `.btn`, `--primary`, `--ghost`, `--danger`, `--sm` | Buttons | One primary per view. Destructive actions are outlined, never filled |
| `.segmented` | Mutually exclusive choice (`aria-pressed`) | Time windows, filters with 2–4 options |
| `.field`, `.input`, `.select`, `.textarea` | Form controls | Always a visible `<label>`. Errors use `.field__error` plus `aria-invalid` |
| `.chip`, `--mono` | Static tag | Rule ids use `--mono` |
| `.sev`, `.sev--{info..critical,none}` | Severity meter plus word | The only way severity is shown |
| `.cls` plus `.glyph--{interaction,canary,signal}` | Classification | Also used in legends and tooltips |
| `.badge--{ok,warn,danger,info,neutral}` | System state | Sensor state, case status, audit outcome |
| `.seal--ok`, `.seal--fail` | Integrity result | Payload hash and audit chain |
| `.evidence`, `--block` | Attacker-controlled text | See principle 1 |
| `.panel` (`__head`, `__title`, `__meta`, `__body`, `__foot`) | Content container | |
| `.stat` | Stat tile | Delta in neutral ink |
| `.kv` | Key/value list | Empty values render "—" |
| `.table`, `.table--stack`, `.col-summary`, `.num` | Data table | Below 720px rows become labelled cards; `data-label` holds interface text only |
| `.tabs`, `.tab` | Tabs | |
| `.banner--{info,warn,danger,proposal}` | Callout | `--proposal` has the hatched "not executed" edge |
| `.state`, `--error`, `.spinner`, `.skeleton` | Empty, loading, error | Every view has all three |
| `.dialog`, `.drawer` | Native `<dialog>` | Focus trap, Esc and inert background come from the platform |
| `.toast` | Transient confirmation | Never the only place an error is reported |
| `.timeline` | Ordered signals or notes | Order is labelled |
| `.code`, `.json-*` | JSON viewer | Tokens built from the parsed value, rendered as text |
| `.bar-list` | Share within one measure | Fill width is set through CSSOM, not a style attribute |
| `.chart`, `.chart__*`, `.legend` | Hand-written SVG stacked bars | 2px surface gap between segments, focusable buckets, table view |
| `.shell`, `.nav-link`, `.brand` | Console frame | Navigation becomes a drawer below 960px |

## Console security rules

The console server sends
`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; …`
(see `docs/architecture/console-api.md`). The UI is written for it:

- All markup is built by `assets/js/lib/dom.js`. Children become Text nodes,
  attributes come from an allowlist, `href` accepts only `#/…` routes and a
  fixed set of project links, class names are validated tokens, and only
  form-state properties can be set. `innerHTML` and friends are never used.
- Route parameters and filters are validated against the contract's closed
  vocabularies before they reach a request, a class name or a link
  (`lib/route.js`).
- The CSRF token lives only in the API client's closure; the session is an
  HttpOnly cookie. Nothing sensitive goes into `localStorage`.
- The live stream is unfiltered by contract, so filters are re-applied in the
  browser with the same semantics as the server (`matchesEventFilters`). When
  the stream drops, the UI calls `GET /api/v1/session` to tell an expired
  session (stop and sign in) from an outage (reconnect with jittered
  exponential backoff, 1s to 30s). While paused, up to 500 new events are held;
  older ones are counted, not kept.

`internal/consoleui/embed_test.go` fails the Go build if any shipped file
needs inline script or style, an inline event handler, another origin, a
non-relative import, or a markup or code sink (`innerHTML`, `eval`,
`new Function`, dynamic `import()`, string timers, and others).

## Screens

Sign-in, Overview, Events (with live mode), Event detail, Sources, Source
detail, Sensors, Rules, Recommendations, Node, Investigations, Investigation
detail, and Audit trail (admin only). Analyst-only actions (create, rename,
change status or priority, attach and detach evidence, add notes) are hidden
for viewers; the server enforces the same rules.

## Developing and testing

```bash
# mock API + UI on http://127.0.0.1:9121 (tokens: dev-viewer, dev-analyst, dev-admin)
# (equivalent to: node internal/consoleui/devserver/mock-server.mjs --port 9121)
make ui-dev
# UI unit and integration tests (Node.js >= 20, no npm install)
make ui-test
go test ./internal/consoleui
```

The mock (`internal/consoleui/devserver/mock-server.mjs`) binds loopback only,
serves the UI with the production security headers, and answers every
endpoint from deterministic synthetic data: documentation-range addresses and
deliberately hostile evidence strings (markup, right-to-left override, very
long values, IPv6, keys containing `/`). It is a fixture: it is not embedded
and does not ship.

### Verification (2026-11-14, macOS, Node 25.8.2, Go 1.25.14)

| Check | Result |
|---|---|
| `node --test 'internal/consoleui/webtest/*.test.mjs'` (63 tests: DOM safety, routing, filters, API client, stream, chart math, JSON viewer, formatting, components, mock integration, site parity) | PASS |
| `go vet ./internal/consoleui` and `go test ./internal/consoleui` | PASS |
| `gofmt -l internal/consoleui` | PASS (no output) |
| Browser walk-through against the mock: all 13 screens, attach-to-investigation flow, live mode, dark and light, 375px width without horizontal scroll | PASS (manual) |
| `make lint test` for the whole module | NOT RUN: disk space was limited, and the instruction was to keep Go builds to this package |
| Behavior against the real Go console server | NOT RUN: the server is built on a separate branch; only the contract and the mock were available |
