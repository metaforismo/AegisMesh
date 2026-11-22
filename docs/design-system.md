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
| `internal/consoleui/static/assets/js/lib/{brief,filters,views,cadence,glossary}.js` | The Overview's situation brief, filter chips and click-to-filter links, saved views and palette recents (browser storage, validated on read), source cadence statistics, and the Guide's glossary; unit-tested in `webtest/brief.test.mjs` and `webtest/understanding.test.mjs` |
| `internal/consoleui/static/assets/js/lib/{story,download}.js`, `ui/{story,downloads}.js` | Attacker-session wording and story layout (assessment, evidence codes, stages, phases, idle markers, the pace log scale, bounds sentence); authenticated downloads with fixed file names. Tested in `webtest/story.test.mjs` |
| `internal/consoleui/devserver/mock-analysis.mjs` | The mock's twin of the backend's sessions, framework relations, indicator downloads and reports (ADR-0022), with scripted sessions; tested in `webtest/mockanalysis.test.mjs` |
| `internal/consoleui/static/assets/js/lib/{auth,tenant}.js` | Sign-in option selection and OIDC error codes; tenant visibility, switch targets and where a switch lands; unit-tested in `webtest/` |

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
   activity traces draw time the index cannot speak for (or, in the
   fallback, older than the oldest loaded event) dashed and say so; the audit
   chain colors only what the server's one verification answer supports;
   sparklines and traces exist only where the API has a per-bucket series
   (`overview.buckets`, `overview.by_sensor[].buckets`).

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
| `--color-ink` / `--color-ink-2` on `--color-accent-soft` | 13.69:1 / 7.51:1 | 11.73:1 / 7.72:1 | Filter chip value and name, remove icon |
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

The filter chip's edge (`--color-accent-line` on `--color-accent-soft`,
1.41:1 light, 1.71:1 dark) is decorative: the chip is not a control, and its
remove link is identified by its icon at 7.51:1 / 7.72:1. The cadence fill
and the brief's left rule use `--color-accent` (6.82:1 / 7.39:1 on surface).
Ratios for the new pairs were computed with the WCAG 2 formula on 2026-11-22.

Values measured with the WCAG 2 formula on 2026-11-15 after the canvas and
hairline tokens were retuned (`--color-canvas` light `#edf0f4`, dark `#0d1218`;
`--color-border` is a decorative hairline and carries no information alone).

### Type, space, shape

- `--font-sans` and `--font-mono` are system stacks; nothing is fetched.
- Scale from a 14px base: `--text-2xs` 11 … `--text-4xl` 52. Stat values are
  28px (`--text-2xl`) with `--tracking-figure`; page titles 22px. All numerals
  are tabular (`font-variant-numeric: tabular-nums` on the body), so counts
  do not jitter as they change.
- `--tracking-caps` (0.08em) spaces the uppercase monospace micro-labels
  (`.caps`, the brief's "Situation", the readout head, Guide groups). They
  name a readout; they are interface text and never evidence.
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
  keyboard (g-sequences, the palette, Enter on a link), filters, filter
  chips and saved views, help tips, the situation brief and the chart
  readout, paging, numbers changing, an in-place refresh (it never replays
  entrances).
- **Animates briefly:** pointer route changes (a 10px directional slide of
  the content area only; View Transitions API with a keyframe fallback),
  dialogs and the side panel (interruptible transitions on `[open]` with
  `display`/`overlay` discrete; exits shorter than entries), toasts
  (transitions, so bursts retarget), the nav indicator, the copy icon
  morphing into a check, chart entry (bars rise in an eased 260ms wave; the
  source cadence columns rise once, `--duration-chart`) and
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
(a convenience only). The only other things kept in the browser are saved
event views and palette recents; see "Console security rules".

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
| `.table`, `.table--stack`, `.col-summary`, `.num` | Data table | Below 720px rows become labelled cards; `data-label` holds interface text only. From 1440px the header sticks under the top bar while the page scrolls; narrower, the table scrolls sideways in its own wrapper and the header sticks within it |
| `.tabs`, `.tab` | Tabs | |
| `.banner--{info,warn,danger,proposal}` | Callout | `--proposal` has the hatched "not executed" edge |
| `.state`, `--error`, `.spinner`, `.skeleton` | Empty, loading, error | Every view has all three |
| `.dialog`, `.drawer` | Native `<dialog>` | Focus trap, Esc and inert background come from the platform |
| `.toast` | Transient confirmation | Never the only place an error is reported |
| `.timeline` | Ordered signals or notes | Order is labelled |
| `.code`, `.json-*` | JSON viewer | Tokens built from the parsed value, rendered as text |
| `.bar-list`, `--aside` | Share within one measure | Fill width is set through CSSOM, not a style attribute. `--aside` adds a small decorative trace between label and value (Overview, Events by sensor); the printed value stays the number of record |
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
| `.menu` (`__title`, `__list`, `__item`, `__check`, `__hint`, `__note`, `__head`, `__kv`) | Top-bar menu | A native `popover` (light dismiss, Esc, top layer from the platform), placed under its button by CSSOM. Opened many times a day, so it never animates. The current item carries `aria-current`, a check and the word "Current". Route changes close it |
| `.caps` | Uppercase monospace micro-label | Interface text only |
| `.panel--primary` | The one panel a screen is about | A firmer, decorative edge and a 16px title; every other panel is secondary |
| `.brief` (`__head`, `__eyebrow`, `__dot`, `__meta`, `__text`, `__clause`, `__num`, `__foot`) | Situation brief (Overview) | Sentences from `lib/brief.js` only. Each clause links to the view that shows it; numbers are semibold ink; a source key is `.evidence`; a missing field is said, never zeroed |
| `.readout` (`__head`, `__list`, `__value`, `__total`) | Readout legend | Glyph, series name and value. Whole window at rest; the hovered or focused bucket otherwise. Not a live region: the focused bar's label already announces the values |
| `.help`, `.help-tip`, `.tip-pop` (`__term`, `__text`, `__more`) | "What is this?" tip | A `?` button beside a non-obvious term opening a native popover with the Guide's short definition and a link to the entry. Never animates |
| `.fchip-row`, `.fchip` (`__name`, `__value`, `__remove`) | Active filter | Name, value, remove link. Evidence values keep `.evidence` inside the chip |
| `.cell-link`, `.cell-filter` | Click-to-filter on a table value | Pointer convenience, out of the tab order (`tabindex="-1"`); the event's "Narrow the list" panel is the keyboard path. Hidden on devices without hover |
| `.cadence` (`__col`, `__bar`, `__fill`, `__count`, `__label`) | Gap histogram (Source) | Every column prints its count; the peak column is also named in text. Caption states how many loaded events it used |
| `.peek--plain` | Absolute time behind a relative time | Same floating element as the evidence peek, without the evidence look |
| `.assess` (`--filled`, `--ring`, `--dash`, `--compact`) | Automation observation | Shape plus words: filled diamond "Consistent with automation", hollow ring "No pattern established", dash "Too few events", always with the observation count. Never a verdict badge ("AI attacker", "bot") |
| `.cstrip` | Pace strip | Log scale 10 ms … 1 h: min-to-p90 range, a median tick, and the printed median beside it |
| `.stage` (`--discovery`, `--credential_access`, `--ai_service_abuse`, `--decoy_credential_replay`), `.ribbon` | Session stages | Word plus shape (ring, hatched square, diamond, triangle); the ribbon's segments are textured, and its legend prints each stage's event count |
| `.story` (`__phase`, `__event`, `__when`, `__gap`, `__node`, `__body`, `__summary`, `__meta`, `__idle`) | Attack story timeline | Time with milliseconds and the gap before each event in a left rail; a spine with the classification glyph; summary as evidence opening the side panel; gaps over 5 minutes collapse into a dashed "quiet" marker. Below 720px the rail folds above the summary |
| `.story-hero`, `.story-layout`, `.story-side` | Session detail layout | Hero: assessment, figures, stage ribbon. Two columns from 1200px, one below |
| `.figures` (`__item`, `__note`) | Labelled numbers | Pace figures; the note explains the formulas |
| `.obs-list`, `.obs` (`--quiet`) | Automation observations | Console title and explanation, a "what is this?" tip, and the server's fixed sentence labelled "Server" |
| `.fw-groups`, `.fw-group`, `.chip--fw`, `.fw-link` | Framework references | Grouped by framework in fixed order; each chip opens the matrix at that technique. Editorial "relates to", stated beside them |
| `.tgrid`, `.tcell` (`--observed`, `--quiet`) | Technique matrix | Observed: solid edge, accent rule, a count, last seen, a link to the events. Not observed: dashed edge, no fill, the words "not observed" |
| `.downloads` | Report and indicator downloads | Analyst only (viewers see why); fixed file names; status line with skip counts and scan bounds; "proposed, never applied" for the blocklist |
| `.top-tenant`, `--static` | Active tenant in the top bar | A button that opens the tenant menu with several tenants; a static label with one tenant not named `default`; absent otherwise |

## Console security rules

The console server sends
`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; …`
(see `docs/architecture/console-api.md`). The UI is written for it:

- All markup is built by `assets/js/lib/dom.js`. Children become Text nodes,
  attributes come from an allowlist, `href` accepts only `#/…` routes, one
  same-origin server path (`/api/v1/auth/oidc/login`, the single sign-on
  start) and a fixed set of project links, class names are validated tokens, and only
  form-state properties can be set. `innerHTML` and friends are never used.
- Route parameters and filters are validated against the contract's closed
  vocabularies before they reach a request, a class name or a link
  (`lib/route.js`).
- The CSRF token lives only in the API client's closure; the session is an
  HttpOnly cookie. Nothing sensitive goes into `localStorage`. Besides the
  theme it holds, per tenant (`aegismesh.views.<tenant>`,
  `aegismesh.recent.<tenant>`): saved event views, with only non-evidence
  filters (node, class, sensor, kind, rule, severity, since, until; source
  keys and search text are attacker-influenced and never written), and up to
  six palette recents by kind and id (screens, actions, rules, sensors,
  investigations, Guide entries; never sources or events). Both are read
  back as untrusted input: parsed defensively, names stripped of control and
  bidi characters and capped, filters re-validated by
  `normalizeEventFilters` before they reach a URL or a request. The UI says
  "stored in this browser only". A tenant
  switch replaces the token with the rotated one from the response. A 401
  for a request that was already in flight with the old cookie during a
  switch is treated as an answer, not as a sign-out.
- The live stream is filtered by the server only by origin (`node`), so every
  other filter is re-applied in the browser with the same semantics as the
  server (`matchesEventFilters`, which also re-checks the origin). When
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
shows a response under 2 minutes old and refreshes it, and any write (or
a tenant switch) clears everything. A response to a request that started
before the clear is handed to its caller but never cached, so a late answer
from the departing tenant cannot reappear in the new one. The audit trail is never cached or prefetched, because reading
it is an audited action.

## Screens

Sign-in, Overview, Events (with live mode), Event detail, Sources, Source
detail, Sensors, Rules, Recommendations, Node, Investigations, Investigation
detail, Audit trail (admin only), Fleet and Fleet node (experimental), and
the Guide.
Analyst-only actions (create, rename, change status or priority, attach and
detach evidence, add notes) are hidden for viewers; the server enforces the
same rules.

### Understanding aids (2026-11-22)

- **Overview situation brief.** The first panel under the page head. A few
  sentences from `buildBrief` (`lib/brief.js`), in a fixed order: volume
  against the previous window (neutral "more than" / "fewer than"), canary
  invocations, correlation signals, the highest finding severity present,
  the most active source (its share of the window and how many sensors saw
  it), the most cited rule, open investigations. Every clause links to the
  filtered view, with `since` set to the window start so the list matches
  what was counted. A field the server did not send produces a sentence
  saying so. With no events in the window, the brief shows first-run steps
  instead: `aegismesh doctor --config mesh.yaml`, `aegismesh run --config
  mesh.yaml --dry-run`, `aegismesh demo --console`, and a link to the 7-day
  window and the Guide; it says a quiet console is a normal state.
- **Hierarchy.** The chart is the primary panel (`.panel--primary`); the
  others are secondary. Panel titles for non-obvious terms carry a tip.
- **Chart readout.** The legend is a readout: whole-window totals at rest,
  the hovered or focused bucket's values otherwise, plus the existing
  crosshair, tooltip and table view.
- **Events filter bar.** Search is always visible; active filters are
  removable chips with "Clear all"; the full form is behind "All filters
  (n set)". Class, sensor, source and rule values in the table are
  click-to-filter links (pointer only, see `.cell-link`); the event's
  "Narrow the list" panel offers the same filters from the keyboard. An
  empty filtered list shows the chips so one can be removed in place; an
  empty index says an empty list is normal and links to the Guide.
- **Saved views.** "Views" next to search lists views saved in this browser
  for this tenant, opens one, deletes one, and saves the current filters
  under a name. Source and search filters are dropped and the save dialog
  says so.
- **Palette as global search.** Groups: Recent (on an empty query), Go to,
  Actions, Investigations, Rules (`GET /rules`), Nodes, Sensors, Sources,
  Guide; when the query has two or more characters, "Search all events for
  …" and up to six events from `GET /events?q=` (debounced, the same
  substring match as the Events list), each opening the event in the side
  panel over the filtered list. Results are grouped; a group sits where its
  best match ranks.
- **Guide** (`#/guide`, `g h`, nav "Help"). The glossary from
  `lib/glossary.js`: observation vs incident, classification, canary
  invocation, severity, finding, findings vs correlation signals, rule,
  evidence text, source, cadence, recommendations (proposed, not executed),
  investigation, index bounds, integrity, audit trail. `?t=<id>` scrolls to
  and marks an entry; CLI commands have a copy button.
- **Source cadence.** Beside the activity strip: the gaps between
  consecutive loaded events in seven ranges (under 1 s to over 1 h), the
  median, the 10th–90th percentile range and the share within a quarter of
  the median, captioned "from the N loaded events" with how many were not
  loaded. It says regular short gaps are typical of scripts and agent tool
  loops and that it is an observation, not a verdict.
- **Relative times** carry the absolute UTC time in the peek on hover and in
  visually hidden text.
- **Touch.** Under `(pointer: coarse)` buttons, nav links, segmented
  controls, menu and palette items, copy buttons and chip remove links are
  at least 44px; the help tip's hit area grows to 44px.

Extension points for later screens: a screen is an item in `NAV`
(`ui/shell.js`), a route in `lib/route.js`, and a descriptor in
`screens/index.js`; the palette picks up `NAV` automatically. Nothing is
listed before it exists.

### Attacker sessions, the attack story and techniques (2026-11-22)

Built on `GET /sessions`, `/sessions/{id}`, `/coverage`, `/export/indicators`,
`/sessions/{id}/report` and `/investigations/{id}/report`
(docs/architecture/console-api.md, ADR-0022).

- **Sessions** (`#/sessions`, nav Observe, `g c`, palette): source (evidence)
  with last seen, duration, events, surfaces, max severity, rules, a pace
  strip and the automation observation ("Consistent with automation · 3").
  Window and exact-source filters, cursor paging, the API's `bounds` as one
  sentence (scan size, scan limit reached, index history, "a source key is
  not an actor identity"). Rows consistent with automation carry an accent
  edge; the text says the same. The table scrolls in its panel.
- **Session detail** (`#/sessions/<id>`): hero with the assessment, figures
  and the stage ribbon; the timeline grouped by `phases`, gaps as durations
  (sub-second gaps in semibold), idles over 5 minutes collapsed, events
  opening the shared event side panel (`?event=`, j/k, Esc); "Automation
  observations" (each code in plain words, a tip, the server's sentence);
  "Pace" (min, median, p90, events per minute, regularity, the formulas, a
  gap histogram from the timeline); "Frameworks" (chips into the matrix);
  "Downloads"; "New investigation with these events" (analyst, local event
  ids only, at most 200). A truncated timeline says what it covers.
- **Techniques** (`#/techniques`, nav Investigate, `g t`): tabs for MITRE
  ATT&CK, MITRE ATLAS and OWASP LLM 2025 (arrow keys move), the API's
  `interpretation` verbatim in a "Not a coverage claim" banner plus what
  observed and unobserved mean, one cell per technique. An observed cell
  opens events citing its first rule since the window start.
- **Rules**: grouped by family with what each family does, framework
  references per rule, and a statement that the API does not report per rule
  whether a match only observes.
- **Integrations**: Source links to its sessions; Investigation has
  "Downloads"; the Overview brief adds "N sessions with pace or rules
  consistent with automation" ("At least" when more pages exist) when the
  endpoint answers; the palette lists sessions (source as evidence) and
  techniques; the Guide gains session, pace and regularity, automation
  observation, honeytoken, agent canary, LLMjacking pattern, technique
  mapping and proposed blocklist.
- **Downloads** go through the API client (session cookie, same origin;
  GETs need no CSRF token). The response is read as a Blob and saved under
  one of the server's fixed names chosen by kind; `Content-Disposition` is
  never read. They are never cached or prefetched (audited reads). Viewers
  see "Reports and indicator exports need the analyst role".

### Sign-in (operator token and experimental single sign-on)

The card is built from `GET /meta` `auth` (`signInOptions`):

| `auth.token` | `auth.oidc.enabled` | Card |
|---|---|---|
| true | false | Token form (as before OIDC existed; also when `/meta` cannot be read or has no `auth`) |
| true | true | "Continue with <display name>" as the primary button, an "or" divider, and the token form collapsed behind "Use an operator token" (`<details>`) |
| false | true | Only the single sign-on button |
| false | false | A notice that no sign-in method is enabled |

The single sign-on button is a plain same-origin link to
`/api/v1/auth/oidc/login`; the server redirects to the identity provider. The
display name is configuration shown as plain text, with control and bidi
characters removed and the length capped. A one-line note under the button
says it is experimental.

A failed callback returns to `#/login?error=<code>`. The code is read once,
removed from the address bar (`history.replaceState`), and mapped to fixed
words; provider text never reaches the page (the server discards it, and
the UI would not show it anyway):

| Code | Title |
|---|---|
| `unavailable` | Single sign-on is temporarily unavailable |
| `rate_limited` | Too many sign-in attempts |
| `invalid_request` | The sign-in response was incomplete |
| `invalid_state` | That sign-in attempt expired |
| `invalid_identity` | Your identity was not accepted |
| `access_denied` | Sign-in was not granted |
| anything else | Single sign-on did not complete |

Where the token form is also offered, `unavailable` and `access_denied`
mention it. A failed attempt while already signed in keeps the session and
shows a toast.

### Tenants (experimental, logical isolation)

A session acts in one tenant. The console shows tenant UI only when it
matters (`tenantInfo`): nothing with a single tenant named `default`; a
static label with one tenant of another name; a switcher with several.

- **Top bar:** the active tenant sits beside the principal. With several
  tenants it opens a menu of member tenants (current one checked and
  labelled), with one line on what switching does and that isolation is
  logical. The palette offers "Switch tenant: <name>" for each other tenant.
- **Account menu:** name, role, how the session signed in ("Operator token"
  or "Single sign-on (<display name>)"), the tenant, and when the session
  expires; sign out.
- **Switching** (`POST /session/tenant`): the current screen is torn down
  first (aborting its requests and closing its live stream), then the
  rotated session and CSRF token replace the old ones, the read cache is
  cleared, the shell is rebuilt and the same view renders in the new tenant.
  A route that names an object (event, investigation, fleet node, source)
  goes to Overview instead; on Events, the side panel and an origin filter
  are cleared (`routeAfterSwitch`). The address is replaced, not pushed, so
  Back does not lead to a page that cannot exist. A toast says where the
  operator is and why. No transition plays: it is a change of context.
- **Not found:** with tenant UI visible, a 404 on a page or in the side
  panel shows "Not found in tenant <name>" and says plainly that another
  tenant's objects answer exactly like missing ones.
- **Fleet:** the token dialog says which tenant the node will join (the
  hub binds it at enrollment; an agent cannot choose or move it), the shown
  token lists its tenant, and node detail shows the node's tenant.
- **Audit:** the subtitle names the tenant whose chain is shown. OIDC
  records carry `issuer` and `subject`; both are claims from an external
  provider, so they render as evidence (`.evidence`, truncated with the peek
  for the full value) in the Detail column. The action filter lists
  `session.oidc_login`, `session.oidc_denied` and `session.tenant_switch`.

The isolation is logical: one process, one disk and one evidence
encryption recipient serve every tenant. Copy never calls it a hard
boundary.

### Activity traces (per-sensor buckets)

Sensors and the Overview's "Events by sensor" panel draw traces from
`overview.by_sensor[].buckets`, which share the main series' starts. The
Sensors screen makes one overview request (24 hours, 48 half-hour buckets,
shared with Overview through the read cache) instead of one events request
per sensor. A sensor absent from a shorter `by_sensor` list had no events
(zeros on the main starts). The old per-sensor events request remains the
fallback for servers without buckets and for a sensor that may be past the
64-entry cap. Time before the index can speak for (`indexKnownFrom`: the
process start when history is `unavailable`, the oldest indexed event when
`truncated`) is dashed. On a hub that accepts forwarded evidence the
traces group by sensor id across origins, and the Sensors screen says so.

### Fleet (experimental inventory)

The Fleet screen shows this node's hub and agent roles, and on a hub the
inventory of enrolled nodes. Its copy must keep three facts visible: node data
is self-reported in signed heartbeats (not attestation), the hub cannot
command or configure nodes, and evidence forwarding is a separate opt-in
experiment (best effort, loss counted, each node's own store authoritative).

Forwarding state appears in the inventory (a Forwarding column, placed right
after Last seen, and a "View events" link when the hub accepts evidence), in
node detail (forwarded, dropped, gaps, last receive time, queue when reported,
last error as its fixed category code with words for known categories) and
in the role panel (hub "Evidence reception", agent "Evidence forwarding").
Dropped or gap counts above zero are a `badge--warn` labelled "Not forwarded:
N dropped, M gaps" plus one line saying the evidence still exists in the
node's own store; never `badge--danger`, because counted loss is expected of
best effort. The inventory table is wider than a 1440px column, so it scrolls
inside its panel at every width (`.table-wrap--scroll`) instead of widening
the page.

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

### Evidence origin (experimental forwarded evidence)

On a hub that accepts forwarded evidence, an event summary may carry `node:
{id, name}`; without it the event was observed on this node. The console:

- shows an Origin column (node name over its 8-character short id, linking to
  the fleet node; "This node" for local rows) in the events list, source
  detail and related events when `/fleet` says the hub accepts evidence, when
  a node filter is set, or when any loaded row was forwarded
  (`originVisible`). A node that never receives evidence keeps its tables
  unchanged. In tables the name truncates at 8rem and source keys cap at 9rem,
  so the extra column still fits a 1440px page;
- keys rows by id plus origin (`eventKey`): ids are unique only within an
  origin. Links to a forwarded event carry `?node=<id>` (full page) or
  `event_node=<id>` (side panel), so the detail request is pinned to it;
- offers a Node filter (any, this node, each enrolled node) that goes through
  the URL, the server query, the live stream (`node=` on the stream URL) and
  the browser-side matcher; the palette lists the same targets under "Nodes";
- states the limits in one compact line wherever lists or counts mix in
  forwarded evidence (`forwardedNote`): best effort, losses counted on Fleet,
  forwarded history only since the hub last started, each node's store
  authoritative;
- on event detail, names the origin, words the hub integrity scope itself
  ("consistent on this hub"; consistency, not provenance) and never shows the
  server's `description` as interface text, and hides "Add to investigation"
  for forwarded copies: investigations annotate bare ids that resolve to
  local observations only;
- on Overview, adds a "By node" bar list when `by_node` is present, ranked by
  events in the browser (the API sorts by id); each row opens Events filtered
  to that origin and to the overview window.

## Interaction

- **Command palette** (Cmd/Ctrl+K, or the search button): screens, actions
  (live events, theme, shortcuts, "Switch tenant: …" with several tenants,
  sign out), sensors, the top 50 sources of
  the last 24 hours, investigations, rules, Guide entries, recents, and a
  server-side event search (see "Understanding aids"). Ranking: exact, prefix, word start,
  substring, then fuzzy; tested in `webtest/palette.test.mjs`. A pasted
  32-hex event id offers to open that event.
- **Shortcuts** (`?` shows them): `g` then `o/e/s/c/i/t/r/n/a/h` to go to a
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
1440×900, median of three loads of `#/overview`, on 2026-11-15. At the time
the mock did not compress responses, so byte counts are uncompressed. The
mock now mirrors the server's static handling (gzip for text above 256
bytes when smaller, a strong SHA-256 `ETag` per representation,
`Cache-Control: no-cache`, `Vary: Accept-Encoding`, 304 on a matching
`If-None-Match`, 406 when every encoding is refused, `index.html` no-store);
these figures were not re-measured.

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
# add --accept-evidence on|off to choose whether the mock hub accepts forwarded
# evidence (default on: forwarded events, by_node, forwarding counters with one
# node reporting drops and gaps, a local/forwarded id collision)
# add --burst N to push N observations 3s after each stream connects, or call
# GET /__mock/burst?n=200 while a live list is open
# add --auth token|oidc|both to choose the sign-in methods in /meta (default
# token); with oidc, "Continue with Example IdP (mock)" goes through a fake
# provider page at /__mock/idp that offers synthetic identities (ada: admin,
# every tenant; ana: analyst, every tenant; vera: viewer, first tenant only)
# and every failure code
# add --tenants a,b to declare tenants (default one tenant, "default"); the
# first owns the local sensors, rules and node, the others hold only evidence
# forwarded by their own, differently named fleet; dev-admin and dev-analyst
# belong to every tenant, dev-viewer to the first only
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
| Browser, light at 1440px: Overview (sparklines, chart hover, crosshair, click to filtered events), Events (side panel by click and Enter, j/k, Esc back with focus returned), Sources, Source (activity strip), Sensors (traces, dashed unloaded hours), Rules, Recommendations, Node, Fleet, Investigations, Investigation, Audit trail. Dark at 1440px: Overview, Events in live mode, Node, Sources | PASS |
| Dark at 1440px: side panel (and j stepping), palette, sensor cards; chart bucket focus with arrow keys and Enter opening the bucket's events | PASS |
| No horizontal page scroll: 11 screens at 1440, 1280, 1024, 768 and 375px (found and fixed two causes: a table wider than its column with page-level sticky headers, and a visually hidden caption escaping its table wrapper) | PASS |
| Audit chain in dark mode | NOT RUN in the browser |
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

### Verification: forwarded evidence UI (2026-11-15, macOS, Node 25.8.2, Go 1.27.4, Chromium in the Claude browser pane)

| Check | Result |
|---|---|
| `make ui-test` (132 tests: the 108 before plus node filter normalization and live matching, origin formatting, row identity, by-node ranking, palette targets, forwarding summaries, mock routes as an accepting hub, a refusing hub and an agent, Fleet and event detail rendering with forwarded data) | PASS |
| `GOTOOLCHAIN=go1.27.4 go test ./internal/consoleui` | PASS |
| Browser, accepting hub, admin, light 1440px: Overview note and By node panel, drill-down to Events with `node` and `since`; Events Node filter applied from the form (URL updated, list filtered, live kept); live with `node=<id>` and `node=local` (only matching origins inserted during a 60-event burst); side panel on a forwarded row (URL carries `event_node`, origin, hub scope wording, no attach); full-page detail for a local/forwarded id collision with and without `node`; Source detail origin column and pinned links; palette "Nodes" results open the filtered list; Fleet table, loss line and node detail | PASS |
| Browser, viewer: Events with mixed origins, Fleet without token controls | PASS |
| Browser, `--accept-evidence off`: no By node, no origin column or Node filter, Fleet shows reception off and `evidence_disabled`, no View events links | PASS |
| No horizontal page scroll: Events and Overview at 1440px; Events, Overview, Fleet, Fleet node and Source at 375px (light and dark). Found and fixed: the origin column widened the events table past 1440px, the forwarding columns widened Fleet, and the loss badge overflowed at 375px | PASS |
| Dark mode at 1440px: Fleet and Fleet node | PASS |
| Live insertion and route changes in the browser | PASS with a caveat: the browser pane was hidden, so `requestAnimationFrame` and View Transitions never completed; the check replaced `requestAnimationFrame` with a timer and removed `startViewTransition` in the page. Batching and transitions themselves were not re-verified |
| Reduced motion | NOT RUN in the browser: the pane cannot emulate it. The change adds no animation or transition (static CSS only) |
| Against the real Go console server | NOT RUN: verified against the mock and the contract only |

### Verification: single sign-on, tenants, per-sensor traces (2026-11-15, macOS, Node 25.8.2, Go 1.27.4, Chromium in the Claude browser pane)

| Check | Result |
|---|---|
| `make ui-test` (169 tests: the 132 before plus sign-in option selection, display-name cleaning, error-code mapping, the sign-in card for each method combination, tenant visibility, switch targets and landing routes, CSRF rotation and superseded 401s across a switch, the read cache across an invalidation, the top-bar tenant and account controls, bucket → trace math and fallbacks, and mock routes for OIDC, tenants, `by_sensor` buckets and compressed static files) | PASS |
| `GOTOOLCHAIN=go1.27.4 go test ./internal/consoleui` (embed safety) | PASS |
| Browser, `--auth both --tenants alpha,bravo`: SSO button through the fake provider to a session (OIDC, admin); "Deny consent" lands on the sign-in card with the mapped message, the code removed from the address and the provider text absent; every code (and an unknown one) shows its own message | PASS |
| Browser, token only (default mock) and OIDC only (`--auth oidc`, `unavailable` without the token hint); token sign-in with one tenant named `default` shows no tenant control and "Operator token" in the account menu | PASS |
| Tenant switch from Overview (menu), from Events in live mode with the side panel open (palette action: panel and filter cleared, one live stream left on the mock, toast says why), from an investigation (lands on Overview); the investigation's deep link in the other tenant shows "Not found in tenant bravo" | PASS |
| Sensors traces from `by_sensor` buckets with no per-sensor events requests; Overview "Events by sensor" traces; Fleet token dialog and shown token name the tenant; node detail shows it; Audit shows issuer and subject as evidence and the new actions in the filter | PASS |
| No horizontal page scroll at 375px (dark: Overview, Sensors, Events live, Fleet, Audit, a not-found investigation; light: Audit, Fleet) and 1440px (Audit, Sensors); sign-in card at 375px dark and 1440px light; tenant and account menus open inside the viewport at 375px | PASS |
| Found and fixed: the Audit table's short hash broke into a vertical strip beside the wide Detail column (pre-existing; now one line); the toast after clearing the side panel claimed a move to Overview; menus stayed open across a route change | PASS |
| Reduced motion | NOT RUN in the browser: the pane cannot emulate it. The menus never animate; nothing new animates |
| Firefox and Safari (native `popover`, `<details>`) | NOT RUN: only Chromium was available |
| Real identity providers and the real Go console server | NOT RUN: verified against the contract and the mock's fake provider only |

### Verification: understanding aids (2026-11-22, macOS, Node 25, Chromium in the Claude browser pane)

| Check | Result |
|---|---|
| `make ui-test` (191 tests: the 169 before plus the situation brief, filter chips and click-to-filter links, saved views and recents parsing as untrusted input, cadence statistics, glossary cross-references and copy checks, chip/tip/relative-time rendering, the Guide route) | PASS |
| `go test ./internal/consoleui` (embed safety, literal `import()` for the Guide) | NOT RUN: another task was using the Go cache on a nearly full disk. The new code was checked by hand against the embed test's forbidden patterns (no markup sinks, no `localStorage.setItem` with token, csrf or session in the call, one new literal `import('./guide.js')`) |
| Browser against the mock, dark at 1440px: Overview brief with linked clauses, chart readout following a hovered bucket, help tip popover and its Guide link; Events filter chips, saved view stored and listed (only `sensor` and `severity` written), click-to-filter on a rule chip without opening the row, side panel "Narrow the list"; palette event search ("Search all events for …" and six results) and Guide entries; Source cadence beside the activity strip; Guide at `?t=severity` | PASS |
| Light at 1440px: Overview (brief, readout on a hovered bucket), Events side panel | PASS |
| 375px (mobile emulation, coarse pointer): Overview and Events, no horizontal page scroll | PASS |
| Site: style guide "Understanding aids" section and landing showcase brief, light, 1440px | PASS |
| Reduced motion, Firefox, Safari, the real Go console server, an empty index (first-run steps) in the browser | NOT RUN: the pane cannot emulate reduced motion, only Chromium was available, and the mock always has events (the empty brief is covered by unit tests) |

### Verification: attacker sessions and techniques (2026-11-22, macOS, Node 25, Go toolchain, Chromium in the Claude browser pane)

| Check | Result |
|---|---|
| `make ui-test` (204 tests: the 191 before plus story wording and layout, downloads, routes, the brief's session clause, and the mock's sessions, details, coverage, downloads and formulas) | PASS |
| `go test ./internal/consoleui` (embed safety: new screens, literal `import()`s) | PASS |
| Browser against the mock (port 9133), dark 1440px: Sessions, the LLMjacking story (phases, gaps, idle markers, observations, pace, side panel by click, a proposed-blocklist download), Techniques | PASS |
| Light 1440px: Techniques (ATT&CK with unobserved cells), Rules | PASS |
| 375px: the SSH story (light), Sessions, Techniques, Rules and Overview (dark); no horizontal page scroll (found and fixed: the framework tabs and the bounds note widened the page) | PASS |
| Session detail in light at 1440px, reduced motion, Firefox and Safari, the real Go server | NOT RUN |
