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
| `internal/consoleui/static/assets/js/ui/icons.js` | The icon set and the brand mark (the site's static SVGs are generated from it) |
| `internal/consoleui/static/assets/js/lib/{palette,keys,batch,swr,chart}.js` | Pure logic behind the palette, keyboard navigation, live batching, the read cache and the small charts; unit-tested in `webtest/` |

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
6. **Honest marks.** A small chart never shows activity it did not load:
   activity traces draw time older than the oldest loaded event dashed and
   say so; the audit chain colors only what the server's one verification
   answer supports; sparklines exist only where the API has a per-bucket
   series.

## Tokens

### Color and measured contrast

Ratios are WCAG 2 contrast, computed from the token values (not estimated).

| Token | Light | Dark | Use |
|---|---|---|---|
| `--color-ink` | 16.43:1 on surface (14.38:1 on canvas) | 14.46:1 | Primary text |
| `--color-ink-2` | 9.02:1 (7.89:1 on canvas) | 9.52:1 | Secondary text |
| `--color-ink-3` | 5.66:1 (4.95:1 on canvas, 5.32:1 on surface-2) | 6.15:1 (5.75:1 on surface-2, 6.68:1 on canvas) | Muted text, never below 4.5:1 |
| `--color-accent` | 6.82:1; white on it 6.82:1 | 7.39:1; ink-inverse on it 7.97:1 | Links, primary action, focus |
| `--color-evidence-ink` | 13.18:1 on evidence-bg | 12.27:1 | Evidence text |
| `--color-border-strong` | 3.59:1 on surface, 3.14:1 on canvas | 3.44:1, 3.22:1 on surface-2, 3.74:1 on canvas | Control edges (WCAG 1.4.11) |
| `--color-accent` on `--color-accent-soft` | 5.68:1 | 6.00:1 | Selected palette row, open table row |
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

Values measured with the WCAG 2 formula on 2026-11-15 after the canvas and
hairline tokens were retuned (`--color-canvas` light `#edf0f4`, dark `#0d1218`;
`--color-border` is a decorative hairline and carries no information alone).

### Type, space, shape

- `--font-sans` and `--font-mono` are system stacks; nothing is fetched.
- Scale from a 14px base: `--text-2xs` 11 … `--text-4xl` 52. Stat values are
  28px (`--text-2xl`) with `--tracking-figure`; page titles 22px. All numerals
  are tabular (`font-variant-numeric: tabular-nums` on the body), so counts
  do not jitter as they change.
- Space is a 4px grid (`--space-1` = 4px … `--space-24` = 96px).
- Radii encode hierarchy: chips 2px, controls 5px, panels 8px, dialogs,
  drawers and the palette 12px.

### Elevation

Three planes, each a token tuned separately per theme:

| Token | Plane | Used by |
|---|---|---|
| `--elev-1` | Resting on the canvas | Panels, stat tiles, buttons, cards |
| `--elev-2` | Floating over content | Chart tooltip, evidence peek, toasts, the "new events" pill |
| `--elev-3` | Covering the page | Dialogs, the event side panel, the palette, the mobile nav |

Light depth is shadow-led (soft, low-opacity graphite). Dark depth is
surface-led: steps from `--color-canvas` to `--color-surface-3` plus
`--highlight`, a one-pixel inner top highlight, because shadows disappear on
dark canvases. Panels pair `--elev-1` with `--highlight`. `--shadow-1..3`
remain as aliases.

### Motion

Motion exists for spatial continuity, state-change feedback and first
impressions. It is never decoration on something used many times a day.

| Token | Value | Used for |
|---|---|---|
| `--duration-instant` | 100ms | Press feedback (`scale(0.97)`), hover color |
| `--duration-fast` | 160ms | Tooltips and peek, exits, crosshair, copy confirmation |
| `--duration-base` | 220ms | Dialogs, route content, nav indicator |
| `--duration-slow` | 300ms | Side panel and toasts entering |
| `--duration-chart` | 420ms | Chart, share bar and sparkline entry, once per load |
| `--duration-decay` | 1800ms | Live-row highlight fading out |
| `--stagger` | 18ms | Reserved step for entry waves |
| `--ease-out` | `cubic-bezier(0.23, 1, 0.32, 1)` | Anything entering or responding |
| `--ease-drawer` | `cubic-bezier(0.32, 0.72, 0, 1)` | Side panel, mobile nav |
| `--ease-in-out` | `cubic-bezier(0.77, 0, 0.175, 1)` | Things moving while on screen |

Rules:

- **Never animates:** the command palette and shortcut sheet (keyboard,
  many times a day), j/k row and event stepping, navigation driven from the
  keyboard (g-sequences, the palette, Enter on a link), filters, paging,
  numbers changing, an in-place refresh (it never replays entrances).
- **Animates briefly:** pointer route changes (a 10px directional slide of
  the content area only; View Transitions API with a keyframe fallback),
  dialogs and the side panel (interruptible transitions on `[open]` with
  `display`/`overlay` discrete; exits shorter than entries), toasts
  (transitions, so bursts retarget), the nav indicator, the copy icon
  morphing into a check, chart entry (bars rise in an eased 260ms wave) and
  hover (crosshair, dimming, a tooltip that glides), live rows (a color wash,
  never movement), the audit chain reflecting a verification.
- **Ambient:** only the very slow opacity breathing of mesh nodes (sign-in
  page, landing hero), the live dot ring and, on the landing page, one
  packet in the data-flow diagram and a recurring row wash in the
  illustration.
- **Properties:** `transform` and `opacity`; `background-color` and
  `border-color` only for short color feedback; `clip-path` for one-shot
  reveals. Nothing animates layout. Hover effects are gated behind
  `(hover: hover)`.
- **Reduced motion:** every duration token is 0 and `base.css` forces any
  remaining animation or transition, and its delay, to finish at once, so
  end states apply and nothing moves. View Transitions are skipped in
  script, ambient loops stop, scroll reveals on the site are not applied.

### Icons

One set in `ui/icons.js`, drawn on a 16-unit grid with a 1.5 stroke, round
caps and joins, in `currentColor`. Sizes are tokens: `--icon-xs` 12,
`--icon-sm` 14, `--icon-md` 16 (default), `--icon-lg` 20. An icon always
sits beside a word, or the button carries an `aria-label`. Icons are
`aria-hidden`. The brand mark is a shield plate carrying a small mesh (three
nodes linked to a core) on a 24-unit grid. `site/design-system.html` shows
the full set, generated from the module.

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
| `.shell`, `.nav-link`, `.nav-indicator`, `.brand` | Console frame | Navigation becomes a drawer below 960px; the indicator slides to the active link |
| `.icon`, `--xs`/`--sm`/`--lg` | Icon | See Icons |
| `.spark` | Sparkline | Beside a printed number only; decorative (`aria-hidden`) |
| `.segbar`, `.segleg` | Severity share | Legend rows carry meter, word, count and share; hovering a row isolates its segment |
| `.trace` | Activity trace | Unloaded time is dashed (`.trace__bar--unknown`) and labelled |
| `.chain`, `.chain-legend` | Audit chain | State is a `data-state` attribute with shape, color and an accessible label |
| `.palette` | Command palette | Native modal `<dialog>`, combobox + listbox, no open/close animation |
| `.keys`, `kbd` | Shortcut sheet and key caps | |
| `.copyable`, `.copy` | Value with copy button | Icon morphs to a check; a polite status announces it |
| `.peek` | Full value of truncated evidence | Hover after 350ms, focus at once; text only |
| `.skeleton` | Loading placeholder | Shaped like the screen; compositor-only sheen |
| `.route-progress` | Thin progress bar | Only when a screen takes more than ~140ms |
| `.live-pill` | "N new events" | Appears when rows arrive out of view |

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
`new Function`, string timers, and others). Dynamic `import()` is allowed in
exactly one form, a string-literal relative `.js` specifier
(`import('./overview.js')`), used to load screens on first visit; the test
checks that every such specifier resolves and still flags any other
`import()` (a variable, a template, a URL). CSSOM writes from script
(`el.style.transform = …`, `el.style.setProperty('--d', …)`) are allowed by
`style-src 'self'` and are used for computed geometry only; `cssText` stays
forbidden.

The read cache (`lib/swr.js`) keeps only responses the console server
already returned, in memory, for the life of the page: in-flight requests
are shared, a response under 10s old is reused, back/forward navigation
shows a response under 2 minutes old and refreshes it, and any write clears
everything. The audit trail is never cached or prefetched, because reading
it is an audited action.

## Screens

Sign-in, Overview, Events (with live mode), Event detail, Sources, Source
detail, Sensors, Rules, Recommendations, Node, Investigations, Investigation
detail, Audit trail (admin only), Fleet and Fleet node (experimental).
Analyst-only actions (create, rename, change status or priority, attach and
detach evidence, add notes) are hidden for viewers; the server enforces the
same rules.

### Fleet (experimental inventory)

The Fleet screen shows this node's hub and agent roles, and on a hub the
inventory of enrolled nodes. Its copy must keep three facts visible: node data
is self-reported in signed heartbeats (not attestation), the hub cannot
command or configure nodes, and no evidence is forwarded.

| Node status | Badge | Dot shape |
|---|---|---|
| Online | `badge--ok` | filled circle |
| Stale | `badge--warn` | diamond |
| Offline | `badge--neutral` | hollow ring |
| Revoked | `badge--danger` | triangle |

Admin-only controls: enrollment tokens (list, create, delete) and permanent
revocation behind a dialog that requires an explicit acknowledgement. A newly
created token is shown once in a dialog; its text node is emptied and the
dialog removed on close, and it is never written to storage, the URL or logs.
With the hub disabled, node and token routes answer `unavailable`, which the
screen shows as a hub-unavailable notice rather than a console error.

## Interaction

- **Command palette** (Cmd/Ctrl+K, or the search button): screens, actions
  (live events, theme, shortcuts, sign out), sensors, the top 50 sources of
  the last 24 hours and investigations. Ranking: exact, prefix, word start,
  substring, then fuzzy; tested in `webtest/palette.test.mjs`. A pasted
  32-hex event id offers to open that event.
- **Shortcuts** (`?` shows them): `g` then `o/e/s/i/r/n/a` to go to a
  screen, `/` to search events, `j`/`k` to move through the events list,
  Enter to open a row, `o` to open the side panel's event as a full page,
  Esc to close. Single-letter shortcuts never fire inside text fields.
- **Event side panel:** rows on the events list open the event over the
  list (`?event=<id>`, deep-linkable). Esc, the close button or back closes
  it; focus is trapped by the native modal dialog and returns to the row;
  `j`/`k` step through events while the row stays highlighted.
- **Live mode:** stream messages are batched per animation frame (at most 40
  rows per frame), prepended without rebuilding the table, capped at 300 DOM
  rows (the pager says when older rows were removed), held while the pointer
  is over the list, and counted as unread when the list top is out of view or
  the tab is hidden (pill and title count).
- **Investigations:** status, priority, title, notes and detaching are
  optimistic and roll back with an explanation when the server rejects them;
  a failed note gives its text back.

## Performance

Measured with Playwright (Chromium) against the mock, cache disabled,
1440×900, median of three loads of `#/overview`, on 2026-11-15. The mock does
not compress responses, so byte counts are uncompressed.

| Measure | Before | After |
|---|---|---|
| Static requests to a rendered Overview | 35 (every screen module) | 22 (entry graph and Overview, modulepreloaded) |
| Static bytes to a rendered Overview | 212 KB | 222 KB |
| Script evaluation (CDP `ScriptDuration`) | 7 ms | 8 ms |
| First contentful paint (local, noisy) | 112 ms | 84 ms |
| Long tasks during a 200-event live burst | 1 (430 ms) | 0 |
| Frames painted in the 3 s after the burst | 156 | 181 |
| Embedded UI (all files) | 195 KB, 36 files (52 KB gzip -9) | 329 KB, 43 files (90 KB gzip -9) |

The embedded size grew by 134 KB for the palette, side panel, icon set,
skeletons, the new charts and their tests' subjects; screens other than
Overview load only when visited, so the growth is mostly not on the first
paint. The burst figure comes from `GET /__mock/burst?n=200` on the mock.

## Developing and testing

```bash
# mock API + UI on http://127.0.0.1:9121 (tokens: dev-viewer, dev-analyst, dev-admin)
# (equivalent to: node internal/consoleui/devserver/mock-server.mjs --port 9121)
# add --fleet hub|agent|both|none to choose the mock node's fleet roles (default hub)
# add --burst N to push N observations 3s after each stream connects, or call
# GET /__mock/burst?n=200 while a live list is open
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

### Verification: Fleet screen (2026-11-15, macOS, Node 25.8.2, Go 1.25.14)

| Check | Result |
|---|---|
| `make ui-test` equivalent (81 tests, adding fleet helpers, fleet routes, fleet screen rendering per role and state, mock fleet routes as hub and with the hub disabled) | PASS |
| `go vet ./internal/consoleui` and `go test ./internal/consoleui` | PASS |
| Browser against the mock, hub mode, admin: create token, shown once, copy dialog closed, no 64-hex value left in the DOM, storage or URL, token listed, deleted via confirmation; revoke refused until acknowledged, then revoked; audit filter lists the fleet actions | PASS (manual) |
| Browser, viewer: inventory visible, no token panel, no revoke control | PASS (manual) |
| Browser, `--fleet none` (teaching state, node detail shows hub-unavailable), `--fleet agent` (agent role, inventory pointer) | PASS (manual) |
| Light at 800 and 1440px, dark at 375px (no horizontal scroll) | PASS (manual) |
| Fleet screen against the real Go hub | NOT RUN: the backend is in progress on another branch |

### Verification: polish pass (2026-11-15, macOS, Node 25.8.2, Go 1.27.4, Chromium via Playwright)

| Check | Result |
|---|---|
| `make ui-test` (108 tests: the 81 before plus palette ranking, keyboard helpers, frame batching, the read cache, sparkline and binning math, bucket ranges, drawer routing) | PASS |
| `GOTOOLCHAIN=go1.27.4 go test ./internal/consoleui` (embed safety, including the literal-only `import()` rule and its detector cases) | PASS |
| Browser, light and dark at 1440px: Overview (sparklines, chart hover, crosshair, keyboard bucket focus, click to filtered events), Events (side panel by click and Enter, j/k, Esc back with focus returned), Sources, Source (activity strip), Sensors (traces, dashed unloaded hours), Rules, Recommendations, Node, Fleet, Investigations, Investigation, Audit trail | PASS |
| Audit chain with a forced broken result (`first_invalid_seq: 4`, injected by the test): records 1–3 consistent, 4 broken, later records after the break | PASS |
| Investigation edits with forced server failures: priority rolled back with a toast; failed note text restored | PASS |
| Palette (Cmd/Ctrl+K, search, arrows, Enter), shortcut sheet (`?`), `g i` | PASS |
| 375px and 768px: Overview, mobile nav, side panel; no horizontal scroll | PASS |
| Reduced motion: durations computed as ~0, no View Transition, no entrance replay; landing page fully visible at once | PASS |
| Live burst of 200 events: 0 long tasks | PASS |
| Landing page and style guide in light and dark at 1440px, light at 375 and 768px, no horizontal scroll | PASS |
| Firefox and Safari | NOT RUN: only Chromium is available to the test harness. View Transitions, `@starting-style` and scroll-driven animations are progressive enhancement; without them the swap, dialogs and reveals are instant |
| Against the real Go console server | NOT RUN: verified against the mock only |
| `make lint test` for the whole module | NOT RUN: disk space is limited; only this package's Go tests were run |

