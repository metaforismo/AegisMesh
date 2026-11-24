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
| `site/assets/css/site.css` | Reference-page (`design-system.html`) layout; its `lp-*` rules are no longer loaded by the landing page |
| `site/assets/landing/` | Landing page only: `landing.css` (palette and page CSS), the vendored tasteskill kit CSS (`kit/`, MIT, unmodified) and console screenshots (`img/`); see `site/CREDITS.md` and "Landing page" below |
| `internal/consoleui/static/assets/js/ui/icons.js` | The icon set and the brand mark (the site's static SVGs are generated from it) |
| `internal/consoleui/static/assets/js/lib/{palette,keys,batch,swr,chart}.js` | Pure logic behind the palette, keyboard navigation, live batching, the read cache and the small charts; unit-tested in `webtest/` |
| `internal/consoleui/static/assets/js/lib/{brief,filters,views,cadence,glossary}.js` | The Overview's situation brief, filter chips and click-to-filter links, saved views and palette recents (browser storage, validated on read), source cadence statistics, and the Guide's glossary; unit-tested in `webtest/brief.test.mjs` and `webtest/understanding.test.mjs` |
| `internal/consoleui/static/assets/js/lib/{story,download}.js`, `ui/{story,downloads}.js` | Attacker-session wording and story layout (assessment, evidence codes, stages, phases, idle markers, the pace log scale, bounds sentence); authenticated downloads with fixed file names. Tested in `webtest/story.test.mjs` |
| `internal/consoleui/devserver/mock-analysis.mjs` | The mock's twin of the backend's sessions, framework relations, indicator downloads and reports (ADR-0022), with scripted sessions; tested in `webtest/mockanalysis.test.mjs` |
| `internal/consoleui/static/assets/js/lib/catalogs.js` | Decoy and honeytoken catalog logic, the rule action indicator, the server inter-arrival histogram, the SIEM event formats, and the digest (lead sentences, figures, limits, Markdown export with fenced server strings); tested in `webtest/catalogs.test.mjs` |
| `internal/consoleui/devserver/mock-catalogs.mjs` | The mock's twin of the round-3 API: `/decoys`, `/honeytokens`, `/digest`, `/export/events`, rule prose and `observe_only`, `overview.index`, `session_id`, `inter_arrival`, with a scripted MCP decoy-environment session; tested in `webtest/mockcatalogs.test.mjs` |
| `internal/consoleui/static/assets/js/lib/insight.js`, `ui/insight.js` | Round 4: campaign wording and the score layout (`campaignScore`), actor profile normalisation and signal meanings, posture grouping and docs links, shared `plural`/`listJoin`, and `isMissingEndpoint` for older servers; tested in `webtest/insight.test.mjs` |
| `internal/consoleui/devserver/mock-insight.mjs` | The mock's twin of contract r4: `/campaigns`, `/campaigns/{id}`, `/posture`, `campaign_id` and `actor` on sessions, from scripted playbook variants; `--round4 off` answers like an older server. Tested in `webtest/mockinsight.test.mjs` |
| `internal/consoleui/static/assets/js/lib/{auth,tenant}.js` | Sign-in option selection and OIDC error codes; tenant visibility, switch targets and where a switch lands; unit-tested in `webtest/` |
| `internal/consoleui/static/assets/js/lib/{prefs,settings}.js`, `ui/settings-kit.js`, `screens/settings{,-account,-admin}.js` | Round 5: the preferences store (server, browser copy, optimistic with rollback), the settings registry, role and source wording, validation and refusal messages; the confirmation dialog, one-time key reveal, form helpers and read-only settings renderer; the Settings screen. Tested in `webtest/settings.test.mjs` and `webtest/settingsscreen.test.mjs` |
| `internal/consoleui/devserver/mock-accounts.mjs` | The mock's twin of contract r5 (accounts, preferences, sessions, API keys, administration, effective settings, audit export, system); `--round5 off` answers like an older server, `--fail-prefs` refuses preference saves. Tested in `webtest/mockaccounts.test.mjs` |
| `internal/consoleui/static/assets/js/lib/perms.js`, `ui/settings-edit.js`, `screens/settings-roles.js` | Round 6: the permission catalogue fallback, built-in sets, what a principal may do (`permissionsOf`, `toCan`), which screen and settings page needs which permission, the role editor's rules (names, dependencies, diff sentence, summary); edit in place for console settings, the editing-off explanation and the change history; the Roles list and role page. Tested in `webtest/access.test.mjs` and `webtest/accessscreens.test.mjs` |
| `internal/consoleui/devserver/mock-roles.mjs` | The mock's twin of contract r6 (permissions, roles, the settings overlay and its history, accepted posture risk); `--round6 off` answers like a round-5 server, `--settings-editing off` like a server with console editing off. Tested in `webtest/mockroles.test.mjs` |
| `site/assets/brand/` | The mark and the horizontal lockup as standalone SVG: colour, dark-ground and one-colour variants; see "Brand" below |

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
   body, a 4px spacing grid. Times are UTC unless the operator chooses local
   time in Settings; then every absolute time carries its UTC offset.
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
| Severity fills `--sev-*` | ≥ 4.09:1 on surface, ≥ 3.83:1 on surface-2, ≥ 3.14:1 on the meter track | ≥ 4.75:1; ≥ 3.40:1 on the meter track | Meter segments (the track contrast is what separates one level from the next) |

Status colors describe UI state only. They are never used for severity or as
a chart series.

### Classification series

`--class-interaction`, `--class-canary`, `--class-signal` are categorical slots
1–3 in a fixed order. They were run through the dataviz palette validator
(lightness band, chroma floor, adjacent color-vision-deficiency separation,
normal-vision floor, contrast) against the surface each theme actually uses:

| Theme | Surface | Result |
|---|---|---|
| Light | `#ffffff` | All checks passed for the original slots (worst adjacent CVD ΔE 9.2, deutan; normal-vision ΔE 27.6). Signal green was darkened on 2026-11-23 from `#1baf7a` (2.82:1) to `#17a06f` (3.34:1 on surface, 3.13:1 on surface-2); the validator was not re-run for the new value. The table view and legend stay required |
| Dark | `#151b24` | All checks pass. Worst adjacent CVD ΔE 9.4 (deutan), normal-vision ΔE 26.5, all ≥ 3:1 |

Color follows the entity: a filter never repaints the remaining series.

The filter chip's edge (`--color-accent-line` on `--color-accent-soft`,
1.41:1 light, 1.71:1 dark) is decorative: the chip is not a control, and its
remove link is identified by its icon at 7.51:1 / 7.72:1. The cadence fill
uses `--color-accent` (6.82:1 / 7.39:1 on surface); the brief has no accent rule since 2026-11-23.
Ratios for the new pairs were computed with the WCAG 2 formula on 2026-11-22.

`webtest/contrast.test.mjs` recomputes every pair this section relies on
(text on each surface, status inks on their fills, focus ring and control
edges, severity fills on surface, surface-2 and the meter track, the
classification slots) from `tokens.css` in both themes, and fails below AA
(4.5:1 text, 3:1 non-text). It also checks the two dark blocks match.

Values measured with the WCAG 2 formula on 2026-11-15 after the canvas and
hairline tokens were retuned (`--color-canvas` light `#edf0f4`, dark `#0d1218`;
`--color-border` is a decorative hairline and carries no information alone).

### Type, space, shape

- `--font-sans` and `--font-mono` are system stacks; nothing is fetched.
- Scale from a 14px base: `--text-2xs` 11 … `--text-4xl` 52. Nothing in the
  console renders under 11px (chart ticks included). Stat values are 24px,
  the Overview lead figure 32px, with `--tracking-figure`; page titles 26px
  in the display serif (22px on phones); panel titles 16px. All numerals
  are tabular (`font-variant-numeric: tabular-nums` on the body), so counts
  do not jitter as they change.
- `--tracking-caps` (0.08em) is kept for the landing page. The console has no
  uppercase tracked labels since 2026-11-23: `.caps`, the readout head, rule
  prose labels and the digest kicker are 12px sentence case.
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

Resting surfaces (panels, buttons, the brief, heroes, cards) carry no
shadow since 2026-11-23: they are one surface step from the canvas with a
quiet hairline, in both themes. `--elev-2` and `--elev-3` are used only by
what floats (tooltips, popovers, toasts, dialogs, the side panel, the
palette). `--elev-1`, `--highlight` and `--shadow-1..3` remain for the
landing page.

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
`aria-hidden`. The brand mark (a net closed around a lure) is described in
"Brand". `site/design-system.html` shows
the full set, generated from the module.

### Theme resolution

Light by default, dark when the OS prefers it, and an explicit
`data-theme="light|dark"` on `<html>` always wins. Both dark blocks are
screen-only (`@media screen`), so print always uses the light palette. The console's theme button
opens a menu with an explicit choice (Match the system, Light, Dark; the
current one checked and labelled "Current"). The theme is one of the
operator's preferences (Settings, Preferences): saved to the account when the
server offers `/me/preferences`, in this browser otherwise, and always copied
to the browser so the next load starts in the right theme. The palette's "Switch color theme"
still cycles System → Light → Dark. The other things kept in the browser are the
other preferences, saved event views and palette recents; see "Console security rules".

## Component inventory

| Class | What it is | Rules |
|---|---|---|
| `.btn`, `--primary`, `--ghost`, `--danger`, `--sm` | Buttons | Fully round, flat, no shadow; outlined by default. One primary (cobalt fill) per view. Destructive actions are outlined, never filled |
| `.segmented` | Mutually exclusive choice (`aria-pressed`) | Time windows, filters with 2–4 options. No track or filled pill: the chosen label is full ink with a 1px accent line as wide as its word |
| `.field`, `.input`, `.select`, `.textarea` | Form controls | Always a visible `<label>`. Errors use `.field__error` plus `aria-invalid` |
| `.chip`, `--mono` | Static tag | Rule ids use `--mono` |
| `.sev`, `.sev--{info..critical,none}` | Severity meter plus word | The only way severity is shown, always built by `sevChip`. No severity is the empty meter with "No finding", or "Signal" (`SIGNAL_NO_SEVERITY`) for correlation rules |
| `.cls` plus `.glyph--{interaction,canary,signal}` | Classification | Built by `clsChip`; legends and tooltips use the same glyph plus word |
| `.badge--{ok,warn,danger,info,neutral}` | System state | Sensor state, case status, audit outcome |
| `.seal--ok`, `.seal--fail` | Integrity result | Payload hash and audit chain |
| `.evidence`, `--block` | Attacker-controlled text | See principle 1 |
| `.panel` (`__head`, `__title`, `__meta`, `__body`, `__foot`) | Content container | |
| `.stat`, `.grid--stats` | Stat cell in a divided container | Peer counts share one container split by 1px dividers (two or four columns, never an orphan); values 24px; delta in neutral ink |
| `.kv` | Key/value list | Empty values render "—" |
| `.table`, `.table--stack`, `.col-summary`, `.num` | Data table | Below 720px rows become labelled cards; `data-label` holds interface text only. From 1440px the header sticks under the top bar while the page scrolls; narrower, the table scrolls sideways in its own wrapper and the header sticks within it. `fitTable` switches a wrapper to `--scroll` whenever its table is wider than the column, so no table widens the page. Every table time is `timeEl(…, { relative: true })`; numbers go through `formatCount`/`formatNumber`, durations through `formatDurationMs` (`lib/format.js`), bytes through `formatBytes` |
| `.th-sort` (`__mark`) | Sortable column header | A button inside `th[aria-sort]`; only on tables whose rows are all loaded (`lib/tablesort.js`): sources, rules, investigations, fleet nodes, a campaign's sessions. Numbers and times start descending, words ascending; missing values sort last; a polite status announces the order |
| `.tabs`, `.tab` | Tabs | |
| `.banner--{info,warn,danger,proposal}` | Callout | `--proposal` has a dashed edge: "not executed", like unloaded time and techniques not observed |
| `.state`, `--error`, `.state__actions`, `.spinner`, `.skeleton` | Empty, loading, error | Every view has all three. A screen that fails keeps its page head; `screenFailure` picks the words and next step (older server, missing object with a link to its list, retryable outage) |
| `.dialog`, `.drawer` | Native `<dialog>` | Focus trap, Esc and inert background come from the platform |
| `.toast` | Transient confirmation | Never the only place an error is reported |
| `.timeline`, `--compact` | Ordered signals or notes | Order is labelled. `--compact` keeps each entry to one line under its time (summary cut with an ellipsis; the peek shows it whole) |
| `.code`, `.json-*` | JSON viewer | Tokens built from the parsed value, rendered as text |
| `.bar-list`, `--aside` | Share within one measure | Fill width is set through CSSOM, not a style attribute. `--aside` adds a small decorative trace between label and value (Overview, Events by sensor); the printed value stays the number of record |
| `.chart`, `.chart__*`, `.legend` | Hand-written SVG stacked bars | 2px surface gap between segments, focusable buckets, table view |
| `.shell`, `.nav-link`, `.nav-indicator`, `.brand` | Console frame | Navigation becomes a drawer below 960px. The sidebar and top bar sit on the canvas, flat; the current screen is full-ink semibold and the indicator, a 1px accent line on the sidebar edge, slides to it |
| `.icon`, `--xs`/`--sm`/`--lg` | Icon | See Icons |
| `.spark` | Sparkline | Beside a printed number in a list only (Events by sensor), never on a KPI; decorative (`aria-hidden`) |
| `.segbar`, `.segleg` | Severity share | Legend rows carry meter, word, count and share; hovering a row isolates its segment |
| `.trace` | Activity trace | Unloaded time is dashed (`.trace__bar--unknown`) and labelled |
| `.chain`, `.chain-legend` | Audit chain | State is a `data-state` attribute with shape, color and an accessible label |
| `.palette` | Command palette | Native modal `<dialog>`, combobox + listbox, no open/close animation |
| `.keys`, `kbd` | Shortcut sheet and key caps | |
| `.copyable`, `.copy` | Value with copy button | Icon morphs to a check; a polite status announces it |
| `.peek` | Full value of truncated evidence | Hover after 350ms, focus at once; text only |
| `.skeleton` | Loading placeholder | Shaped like the screen (`overview`, `table`, `cards`, `detail`, `digest`, `posture`, `story`, `kv`, `guide`); a test checks every screen names one; flat bars at the size of the value, no shimmer |
| `.route-progress` | Thin progress bar | Only when a screen takes more than ~140ms |
| `.live-pill` | "N new events" | Appears when rows arrive out of view |
| `.menu` (`__title`, `__list`, `__item`, `__check`, `__hint`, `__note`, `__head`, `__kv`) | Top-bar menu | A native `popover` (light dismiss, Esc, top layer from the platform), placed under its button by CSSOM. Opened many times a day, so it never animates. The current item carries `aria-current`, a check and the word "Current". Route changes close it |
| `.caps` | Readout label | Sentence-case 12px sans in muted ink ("Whole window", "Server", "Measured"); interface text only. Uppercase monospace until 2026-11-23 |
| `.panel--primary` | The one panel a screen is about | Marked by its place, size and a 16px title, not by a louder frame |
| `.tally` (`__row`, `--lead`, `__label`, `__value`, `__num`, `__delta`) | Divided count list | Label left, figure right, its change beside it on one baseline; the first row may lead at 32px. The baseline window is named in the panel meta and in visually hidden text |
| `.lead-row`, `.next` (`__cell`, `__title`, `__value`, `__text`, `__go`) | Overview composition | The brief beside its counts; then one divided block of what to read next, each cell a count and its one action |
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
| `.fam` (`--ai`, `--mcp`, `--proto`, `__glyph`), `.fam-row` | Decoy surface family | Hexagon (AI-service shape), bracketed square (MCP), ring (protocol), always with the family's word |
| `.tkind` (`--key`, `--flag`) | Honeytoken kind | Key or flag icon plus "Decoy credential" / "Agent canary" |
| `.ract` (`--observe`, `--act`, `__mark`) | Rule action | Hollow ring "Observe only"; filled square "Can select an action"; the hint is the title and visually hidden text |
| `.activity-mark` (`__fill`) | Share bar beside a printed count | Decorative (`aria-hidden`); the count is the number of record. Fill width by CSSOM |
| `.crumbs` (`__list`, `__item`, `__here`) | Breadcrumbs on detail pages | `nav[aria-label=Breadcrumb]`, the current page last with `aria-current="page"`; a source key stays evidence |
| `.page-head__hint` | "What you can do here" | One line under every screen's subtitle; interface text |
| `.empty-art--decoys`, `--tokens`, `--digest`, `.empty-art__ring` | Empty-state art variants | `emptyArtVariant(kind)`: a decoy in its listening ring, a key path returning to a marker, a briefing sheet; all in the lattice |
| `.actor` (`--auto`, `--agent`, `--human`, `--none`, `--compact`) | Actor reading | Filled diamond "Likely automated", diamond with a centre dot "Possibly an AI agent", filled circle "Likely a person", dash "Inconclusive"; compact form adds "n of N" signals observed. Never a percentage or a gauge |
| `.strength` (`--1..3`) | Signal strength | Three bars plus Weak, Moderate or Strong |
| `.signals`, `.signal` (`--present`, `--absent`, `__box`, `__looked`, `__detail`, `__side`, `__lean`) | Actor checklist | Ticked box for observed, dashed empty box for not observed; what it measures, the server's measurement, which way it points |
| `.profile` | Actor profile panel | Reading, the server's hedged sentence in the display serif, the tally, then the two checklist groups |
| `.mix` (`__bar`, `__seg--*`, `__list`, `--compact`) | Automation mix of a campaign | Textured segments plus counts in words |
| `.miniscore` | Campaign card art | Identical stops on every lane; decorative, the card prints the numbers |
| `.score` (`__step`, `__lane`, `__who`, `__cell--performed/absent/unknown`, `.is-shared`), `.score-legend` | Campaign score | A real table: rows are sessions, columns shared steps; lane line through every cell; times from the session's first event; sticky lane labels and a scroll shadow |
| `.pstatus` (`--attention`, `--info`, `--ok`), `.pcheck`, `.parea`, `.psummary` | Posture review | "!" square, italic "i" ring, check, each with its words; attention items carry a warn edge |
| `.quiet-line` | One quiet line on the Overview | Posture attention count as a link, never a banner or alarm |
| `.camp-strip` | Session's campaign | On the session story, links to the campaign with its label and basis |
| `.stage-row` | Stage tags in a row | More air than a chip row; each tag carries its own mark |
| `.risk` (`--high`, `--elevated`, `--low`, `--unknown`, `--compact`, `__mark`, `__word`), `.risk-legend` | Permission risk | Filled triangle "High risk", half-filled square "Elevated", hollow dot "Low"; the word always printed (visually hidden only beside a count). High risk = can grant access or change behaviour |
| `.perm-matrix`, `.perm-group`, `.perm` (`--high`, `--on`, `--off`, `__row`, `__label`, `__id`, `__why`, `__state`) | Permission matrix | Grouped as the server's catalogue; check boxes in the editor, a granted mark or a dash read-only (no disabled form); high-risk rows carry their reason and a warn edge |
| `.role-summary`, `.role-diff` (`__add`, `__remove`, `__sign`), `.role-layout`, `.roles-risk`, `.holders` | Role page | Live "can and cannot" beside the matrix (sticky from 1200px); the unsaved difference first, with a dashed edge, then the same lists |
| `.setting` (`__tag`, `__override`, `__actions`, `__history`, `__status`, `__editor`), `.setting-edit` (`__duration`, `__words`, `__count`, `__applies`) | Edit in place | The row keeps its read-only layout; Change opens the editor under it; the status line says the server's answer after a save |
| `.src-chip--console` | Console override | Hollow square under a 1px accent line, "Console"; the row says which file value it overrides |
| `.editing-off` | Console editing off | One calm panel: why it is off and the two config lines that turn it on; values stay read-only rows, never disabled inputs |
| `.change` (`__from`, `__arrow`, `__to`, `__reason`, `__key`), `.audit-change` | A change | Old value struck through in muted ink, arrow, new value semibold; "to" for screen readers; the reason as text |
| `.pstatus--accepted`, `.pfig--accepted`, `.pcheck--accepted`, `.pcheck__accepted` | Accepted posture risk | Square with a bar, "Accepted risk"; dashed card edge; who, why, until and "Still present"; never the check of "looks right" |
| `.notice-bar` | Organisation notice | The sign-in banner after sign-in, once per console session: plain text, dismissible, above the screen |
| `.top-org`, `.nav-org`, `.login__org`, `.login__banner` | Organisation name and banner | Plain text from `/meta`; name in the top bar from 720px, in the phone drawer below; banner on the sign-in card with line breaks kept |
| `.cell-lead` (column option `lead`) | Phone card head | Below 720px the row's identity (a source, a title, a name) heads its stacked card, unlabelled and a step larger |
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
  HttpOnly cookie. Nothing sensitive goes into `localStorage`; an API key's
  token exists only in the create response, one Text node of the reveal
  panel and that function's closure, and is emptied when the panel is
  dismissed or the page is left. Besides the
  preferences (`aegismesh.theme`, `aegismesh.density`, `aegismesh.prefs`:
  closed values, parsed on read) it holds, per tenant (`aegismesh.views.<tenant>`,
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
detail, Sessions, Session detail, Campaigns, Campaign detail, Digest,
Investigations, Investigation detail, Techniques, Recommendations, Decoys,
Honeytokens, Sensors, Rules, Posture, Node, Fleet and Fleet node
(experimental), Audit trail (`audit.read`), and the Guide. The sidebar groups
them as Observe (Overview, Digest, Events, Sources), Understand (Sessions,
Campaigns, Techniques, Investigations, Recommendations), Deception (Decoys,
Honeytokens, Sensors, Rules), Operate (Posture, Node, Fleet, Audit trail) and
Help.
Since round 6 every screen, settings page and action follows a permission
(`lib/perms.js`), not a role rank: a screen whose permission the principal
lacks is left out of the sidebar, the palette and the shortcut sheet, and
opening it says which permission is missing; actions are hidden, or said
once where they would be ("Accepting a risk needs …"). Investigation
writes need `investigations.write`; downloads `reports.download` or
`evidence.export`; fleet enrollment and revocation `fleet.manage`. The
server enforces the same rules and every 403 is answered in place.

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
- **Touch.** Under `(pointer: coarse)` and, since 2026-11-23, below 768px whatever the pointer, buttons, inputs, selects, nav links, segmented
  controls, menu and palette items, copy buttons and chip remove links are
  at least 44px; the help tip's hit area grows to 44px; standalone links
  (crumbs, row links, framework, token and Guide contents links) are at least
  40px. Links in running prose keep the WCAG 2.5.8 inline exception.

Extension points for later screens: a screen is an item in `NAV`
(`ui/shell.js`), a route in `lib/route.js`, and a descriptor in
`screens/index.js`; the palette picks up `NAV` automatically. Nothing is
listed before it exists.

### Identity pass (2026-11-22)

Art direction: **a written briefing inside an instrument.** The console keeps
its calm graphite-and-cobalt instrument, and adds one bold move: page titles
and the situation brief are set in the platform's serif (`--font-display`:
New York on Apple systems, then Iowan Old Style, Charter, Georgia), the
voice of a briefing a defender reads, while every operational surface stays
in the sans with tabular numerals. The mesh appears as a faint 24px lattice
(`--lattice-line`, `--lattice-node`) behind the top of each screen and the
landing hero, and the evidence inset gains a 2px "tag" notch, the only
ornament in the product and reserved for attacker-supplied text. Mono text
uses a slashed zero.

| Token | Value | Notes |
|---|---|---|
| `--font-display` | system serif stack | Titles, brief, session sentence. No font is fetched |
| `--text-display`, `--leading-display` | 30px, 1.12 | Page titles (24px below 720px) |
| `--lattice-line`, `--lattice-node` | cobalt at 5.5% / 12% (light), 4% / 10% (dark) | Decorative only; carries no information |

Contrast: the display face uses the existing ink tokens, so text ratios are
unchanged. New marks are non-text and redundant with printed values: mesh
node edges use `--color-ink-3` (4.95:1 on canvas light, 6.15:1 dark) or the
accent; tempo ticks use the classification slots (light signal green is
2.82:1, so the list beside it carries the data, as for the main chart).

New pieces:

- **Sparkline marks** (`.spark__mark`, `lib/viz.js sparkMarks`): the start
  point, the interior maximum and a nonzero interior minimum, on the same
  geometry as the line; the last point keeps its dot.
- **Sensor mesh** (Overview, `.mesh`, `meshLayout`): sensors from
  `overview.by_sensor` as nodes around the console core; node area follows
  events in the window; a pulsing ring and a solid edge only for sensors with
  events in the newest bucket (`lastBucketActive`), dashed when that bucket was
  empty, plain when the API sent no buckets. Every node is a link to the
  sensor's events with its name and count in text. The pulse stops under
  reduced motion.
- **Sessions tile** beside Investigations on the Overview.
- **Tempo ribbon** (session story, `.tempo`, `tempoLayout`): every timeline
  event on one axis, gaps on a log scale, quiet stretches over 5 minutes as
  labelled breaks, stage bands underneath, taller ticks for correlation
  signals. One tab stop, arrow keys, Enter opens the event; hover or focus
  highlights the matching event in the list.
- **"How this session unfolded"** (`unfoldSentence`): one sentence in the
  display serif composed only from the session's fields; the source stays
  evidence.
- **Row density** (top bar): comfortable or compact, remembered in this
  browser (`aegismesh.density`, parsed against a closed list) and applied as
  `html[data-density]`. Stacking tables had a zebra until 2026-11-23; rows
  are now told apart by rules and alignment only.
- **Empty-state art** (`emptyArt`, `.empty-art`): a lattice, one decoy and a
  probe line, drawn inline; used where an empty list is a normal state.
- **Stat hierarchy**: the all-events tile leads (accent top rule, larger value).

Motion fix: route transitions no longer crossfade. The old view leaves in
`--duration-instant`, the new one enters after it, and the transition group
no longer morphs between page heights; `swapView` finds the current view when
the swap actually runs, removes any stray view and skips a running
transition, so a navigation that overtakes another cannot leave two screens
stacked (the ghosting seen in phase 2).

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
  references per rule, and (on servers without `observe_only`) a statement
  that the API does not report per rule whether a match only observes; see
  the catalogs pass below for the indicator that replaced it.
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
  see "Reports, indicator exports and event files need the analyst role".

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

### Decoys, honeytokens, digest and the filled API gaps (2026-11-22)

Built on the round-3 contract (`docs/architecture/console-api.md`, "Round 3
additions"): `GET /decoys`, `/honeytokens`, `/digest`, `/export/events`, rule
`description`/`guidance`/`observe_only`, `overview.index` and
`top_rules[].title`, event `session_id`, and source `inter_arrival`.

- **Decoys** (`#/decoys`, nav System, `g d`, palette): "What attackers see,
  and what is real" first (nothing behind a decoy is real, no model runs, tool
  calls never execute, the record is the only real thing), four counts
  (decoys, AI-service shapes, MCP environments, planted ids), then one card
  per decoy: kind, listen address, surface families (`.fam`), static rules,
  tools and fake files where they apply, planted honeytoken ids (each opens
  the Honeytokens row), events in the window with an activity mark, last
  activity, "View its events" (sensor and `since` set to the window start)
  and "Runtime state". The page note words the API's `bounds` and says
  planting is detected only in inline response material. Window 1h/24h/7d.
- **Honeytokens** (`#/honeytokens`, nav System, `g k`): a "Values are never
  shown" banner (the API returns ids and kinds only), four counts, a table
  (token, kind, planted in, hits, last hit, presented by), ranked by hits
  then recency, `?t=<id>` marks a row. Sources are evidence, each linking to
  the source and its sessions. "What a hit means" states, per kind, what a
  hit means and does not mean. The empty state (and "Mint another") gives the
  CLI commands from `docs/cli.md` with copy buttons and "Never use a real
  credential".
- **Digest** (`#/digest`, nav Observe, `g b`; "Read the 24-hour digest" in
  the Overview brief): a written briefing in the display serif. Masthead,
  lead sentences (`digestLead`: neutral comparisons, a missing count said,
  never zeroed), Volume (this window, the window before, a signed difference
  in ink), Sources and sessions, Most cited rules (id, catalog title,
  severity meter or "Signal", count; each opens its events since the window
  start), Newly observed techniques (grouped by framework, editorial),
  Planted markers and open work (a `null` open-investigations count is "not
  available"), and Limits (the server's `interpretation` and
  `source_comparison` quoted verbatim and marked "server text", then index
  history, scan, recommendation exclusions, "Nothing is scheduled, stored or
  sent"). Window 24h/7d. "Copy as Markdown" composes the same fields in the
  browser (`digestMarkdown`); every server string, the rule titles included,
  is an inline code span with control, bidi and zero-width characters
  removed, a fence longer than any backtick run inside and escaped table
  pipes. When the browser refuses the clipboard, the Markdown opens selected
  in a read-only field. "Print" uses the print stylesheet: no navigation, top
  bar, actions, hints, tips or lattice; light ink on paper; sections avoid
  page breaks.
- **Rules:** a column "On a match" (`.ract`) and, per rule, the catalog
  description with "Check next" guidance. "Can select an action" means a
  match may tag, throttle, isolate or refuse the decoy's own connection under
  the configured severity mapping; nothing outside the decoy is touched.
  Without `observe_only` the column is omitted and the banner says the server
  does not report it.
- **Overview:** the brief's most-cited-rule clause and the Top rules list use
  the catalog title. The empty state reads `index.events`: 0 is "Nothing
  indexed yet" (first-run steps and a link to Decoys); a nonzero index with
  an empty window is "A quiet window" (links to the 7-day overview, the
  7-day digest and every indexed event); no `index` keeps the combined copy.
- **Event detail and side panel:** a "Session" row links to the session
  story when `session_id` is a session id, says "Not in a retained session"
  when it is empty, and is absent on servers that do not send it. The full
  page adds a "Session story" button and breadcrumbs.
- **Source cadence:** the server's histogram over all retained events from
  the source (signals included, independent of paging) when `inter_arrival`
  is well formed, labelled as such, with the browser's median and spread from
  the loaded events underneath; otherwise the browser's histogram as before.
- **Downloads** (sessions and investigations) gain "Event files for a SIEM":
  CEF, Syslog (RFC 5424), OTLP JSON and ECS NDJSON, saved under the server's
  fixed names. The group says "File formats only: AegisMesh sends nothing and
  ships no exporter or collector"; the OTLP button's hint says "File format
  only: AegisMesh sends nothing and ships no exporter".
- **Polish:** breadcrumbs on Event, Source, Session, Investigation and Fleet
  node; a "what you can do here" hint under every screen's subtitle; sticky
  first cells take the row's tint (`--row-tint` for hover, zebra, cursor,
  open), row headers in a table body read as cells, and numeric columns stay
  on one line; the theme is an explicit menu; the digest's copy icon morphs
  into a check like every copy button.
- **Guide** gains Decoy, AI-service decoy, MCP decoy environment, Honeytoken
  hit, Digest and SIEM event formats (group "Decoys and planted markers").
  The first-run tour has six steps (Digest added after Sessions).

Motion: the request also listed number changes and palette and popover
entrances. The motion rules above keep those still on purpose (the palette,
menus and changing numbers are used many times a day), so they were not
added; nothing in this pass animates except the copy-to-check morph, which
uses the duration tokens and is instant under reduced motion.

Contrast for the new pairs (WCAG 2, computed from the tokens on 2026-11-22;
no color token was added):

| Pair | Light | Dark |
|---|---|---|
| `.fam--ai` glyph (`--color-accent`) on surface | 6.82:1 | 7.39:1 |
| `.ract--observe` ring (`--color-ink-3`) / `.ract--act` square (`--color-ink`) on surface | 5.66:1 / 16.43:1 | 6.15:1 / 14.46:1 |
| `.activity-mark__fill` (`--color-accent`) on its track (`--sev-track`) | 5.24:1 | 5.29:1 |
| Ink / ink-2 on the "what is real" fill (`--color-accent-soft` 55% over surface) | 14.85:1 / 8.15:1 | 13.03:1 / 8.58:1 |
| Muted text (`--color-ink-3`) on a focused honeytoken row (`--color-accent-soft`) | 4.71:1 | 4.99:1 |
| `.decoy__mark` icon (`--color-accent`) on `--color-accent-soft` | 5.68:1 | 6.00:1 |
| Crumb separator (`--color-border-strong`), "what is real" edge (`--color-accent-line`) | decorative | decorative |

### Verification: catalogs, digest and API gaps (2026-11-22, Node 25, Go toolchain, Chromium in the Claude browser pane, mock on port 9135)

| Check | Result |
|---|---|
| `make ui-test` (233 tests: the 210 before plus catalog, digest, Markdown fencing, histogram and empty-state logic, the three new screens rendered into the fake DOM with hostile strings, the theme menu, and the mock's round-3 routes) | PASS |
| `go test ./internal/consoleui` (embed safety: three new screens, literal `import()`s) | PASS |
| Dark 1440px: Decoys, Honeytokens (7d), Digest (all sections), Rules, Overview (brief title, top rules, digest link), event detail (breadcrumbs, session row and button), Source cadence from the server histogram; theme menu open and choosing Light | PASS |
| Light 1440px: Decoys, Digest (7d) | PASS |
| 375×812: no horizontal page scroll on Decoys, Honeytokens, Digest, Rules, Overview, Source, Sessions, Investigations, Events, Guide; Decoys, Honeytokens and Digest viewed (found and fixed: rule ids breaking in the digest, a boxed first cell in stacked honeytoken rows) | PASS |
| "Copy as Markdown" | PARTIAL: the pane refused the clipboard, so the fallback (selected read-only field) was checked; the success path is covered by unit tests only |
| Print stylesheet, reduced motion, light at 375px for the new screens, Firefox and Safari, the real Go console server | NOT RUN: the pane cannot emulate print or reduced motion; only Chromium was available; verified against the mock and the contract only |

### Campaigns, actor profiles and posture (round 4, 2026-11-23)

Built on contract r4 (`GET /campaigns`, `/campaigns/{id}`, `/posture`, and
`campaign_id` plus `actor` on sessions). Every new endpoint is optional: a
404 (or 405/501) on a collection path shows "This server does not provide …
yet" with a next step, and the Overview, sessions list and palette simply
leave the new pieces out (`isMissingEndpoint`).

- **Campaigns** (`#/campaigns`, nav Understand, `g m`, palette group
  "Campaigns"): one card per campaign: the server's label in the display
  serif, the basis as a sentence ("4 sources showed the same sequence of
  steps, with a similar pace."), sources, sessions, events, span and last
  seen, stages, how the sessions read (`.mix`), surfaces and the source keys
  as evidence. A decorative mini score repeats the same stops on every lane.
  A banner states that similar behaviour is not one operator.
- **Campaign detail** (`#/campaigns/<id>`): crumbs, basis, span, a hero with
  figures, the basis as a ticked list, stages and the mix; the server's
  caveats quoted and marked "Server" under "Shared behaviour is not proof of
  a shared operator"; then the **score**: a table drawn as lanes, one row per
  session and one column per shared step (number, stage, the step shape as
  evidence, "n of N"). With the optional `sessions[].step_marks` extension
  each mark shows the time from that session's first event and a skipped
  step is an empty ring; without it a step only some sessions took is a
  dotted ring "not reported per session". Times count from the session's
  first interaction (the backend excludes correlation signals). The
  optional `client_families` field is shown as evidence. Columns every session took are
  shaded. Rules (each opens its events), sources, a sessions table with each
  reading, details with a copyable id. Print uses the paper stylesheet.
- **Actor profile** (session story and sessions list): the hero leads with
  the reading and the server's hedged sentence; beside the timeline the
  checklist lists every evaluated signal: observed first (strongest first)
  with strength bars, the measurement and which way it points, then "Looked
  for, not observed". No percentage or gauge anywhere. The list's "Reads as"
  column shows the reading and "n of N" signals; servers without `actor`
  keep the automation column. A session in a campaign carries a "Campaign"
  link in the list and a strip on the story with the campaign's label and
  basis.
- **Posture** (`#/posture`, nav Operate, `g p`): the header says it is a
  configuration review, not a security guarantee; counts for needs attention,
  for your information and looks right; attention items first with what was
  observed, the recommendation and the doc pointer; then each area
  (exposure, deception, detection, evidence, access) with its remaining
  checks. A doc pointer becomes a link only when it is a plain `docs/*.md`
  path (`docHref`, and `isSafeHref` accepts only that prefix on the project
  repository); anything else is shown as text. The server's `disclaimer` is
  quoted and marked "Server"; `scope: evidence_only` (a tenant without local
  configuration) is said in words. "Needs attention" filter in
  the URL (`?show=attention`). The Overview shows one quiet line under the
  brief linking here.
- **Navigation**: sidebar regrouped (see Screens); `g m`, `g p`, `g u` added;
  the shortcut sheet is generated from `NAV` per role; palette lists
  campaigns; the tour gains a Campaigns step (seven steps); the Guide gains
  Campaign, Actor profile and Posture review (group "Patterns across
  sources").
- **Polish**: detail screens name the browser tab (`ctx.setTitle`: control
  and bidi characters removed, 60 characters); the print stylesheet covers
  the session story and campaign detail; inline source, rule and campaign
  links have 40px targets on touch; plain links among page actions sit on
  the button line; the session id is copyable; unknown stage values keep
  their own words instead of "Other".

Contrast: the new marks reuse existing tokens (`--color-accent` 6.82:1 /
7.39:1 on surface, `--color-ink-2`, `--color-ink-3` ≥ 4.95:1,
`--color-warn` on `--color-warn-soft` ≥ 4.69:1, `--color-ok` on
`--color-ok-soft`); no color token was added. Score lanes and the column
shade are decorative; every mark has visually hidden text.

Motion: nothing new animates.

### Verification: round 4 (2026-11-23, Node 25, Go toolchain, Chromium via Playwright, mock on port 9141)

| Check | Result |
|---|---|
| `make ui-test` (the earlier tests plus `insight.test.mjs` and `mockinsight.test.mjs`: wording, score states, posture grouping and docs links, NAV and shortcut sheet, the three screens with hostile strings, missing fields and a 404 server, the mock's r4 routes and `--round4 off`) | PASS |
| `go test ./internal/consoleui/...` (embed safety, CSP, literal imports) and `go build ./...` | PASS |
| Dark 1440px: Campaigns, Campaign detail, session story with actor profile and campaign strip, Posture, Overview (quiet line, campaigns tile) | PASS |
| Light 1440px: Posture, session story, shortcut sheet; light 375px: Campaign detail | PASS |
| 375px: no horizontal page scroll on 20 screens (Overview, Digest, Events, Sources, Source, Sessions, Session, Campaigns, Campaign, Techniques, Investigations, Recommendations, Decoys, Honeytokens, Sensors, Rules, Posture, Node, Fleet, Guide); Campaigns and Posture viewed dark | PASS |
| Print emulation of Campaign detail (no chrome, score unclipped, marks in ink) | PASS |
| Reduced motion emulated for the screenshots (no entrance replays) | PASS |
| `g m`, `g p`, `g u`, `g c`, `g b`, `g a`, `g o` and `?` driven in the page | PASS |
| `--round4 off`: Campaigns and Posture show the older-server state; Overview has no posture line or campaigns tile; Sessions keeps the Automation column | PASS |
| Firefox, Safari, the real Go console server, screen readers | NOT RUN: only Chromium; the backend for r4 is being built in parallel |

### Audit-and-fix pass (2026-11-23)

A sweep of every screen (24 routes) in light and dark at 1440px and 375px,
plus loading, error and older-server states, measured in Chromium against
the mock. Defects were fixed in shared helpers rather than per screen.

| Defect | Fix |
|---|---|
| Severity drawn three ways: a meter-less "No finding" in the severity share key, "n/a" in Rules, "Signal" as plain text in the Digest; Sensors built its own classification chip | `sevChip` everywhere, with the empty meter and "No finding" or "Signal"; `clsChip` in Sensors |
| Table times in four formats (relative, `HH:MM:SS`, timestamp without zone, two stacked lines on Fleet); a forwarding time with no absolute value | One format: relative text, absolute UTC in `<time datetime>`, title, peek and hidden text |
| Durations in two styles ("3 min" vs "3m 20s"); four private number formatters | `formatDurationMs` and `formatNumber` in `lib/format.js`; others delegate |
| Audit and Events tables widened the page at 1440px | `fitTable`, and Audit uses the scrolling wrapper |
| No table could be reordered | `.th-sort` on the five client-complete tables; Sources says it is ranked by events |
| A failed screen lost its h1 and focus; an older server's 404 read as "aged out of the index"; a Markdown-quoted command in plain text | `screenFailure` + `failureState` under the screen's page head |
| Seven screens used the generic detail skeleton | Digest, posture, story, kv and guide skeletons |
| Light severity fills 2.62–2.90:1 against the empty segments; light signal green 2.82:1 | Token values darkened (table above); contrast test |
| Printing from a dark theme gave light-grey ink on white | Dark tokens are screen-only |
| Touch sizes only on coarse pointers; crumbs, row links, Guide contents, account button 18–32px at 375px | Same sizes below 768px; standalone links 40px |
| Density toggle reused the navigation menu icon (two identical icons on phones) and changed its name with its state | Own icons, one name, `aria-pressed` |
| Tempo ribbon focus was an 18% tint only | Focus stroke added |
| The session story's first sentence listed every stage switch (30+) | Long alternations are summarised with a count |
| "1 open investigations"; "Canary inv." abbreviation | Shared `plural`; the Guide's term in full |

Not fixed: sorting is not offered at phone widths (stacked tables hide the
header) nor on paged lists (events, sessions, audit), because the API has no
ordering parameter; the light classification slots were not re-run through
the dataviz CVD validator after the signal change.

Contrast before → after (light, WCAG 2, against `--sev-track` / surface):

| Token | Before | After |
|---|---|---|
| `--sev-info` `#7d8899` → `#727d8e` | 2.76 / 3.59 | 3.20 / 4.17 |
| `--sev-low` `#4f86c6` → `#4a80bf` | 2.90 / 3.78 | 3.14 / 4.09 |
| `--sev-medium` `#b58200` → `#a27400` | 2.62 / 3.41 | 3.20 / 4.17 |
| `--sev-high` `#d0682f` → `#c45f28` | 2.83 / 3.68 | 3.22 / 4.19 |
| `--class-signal` `#1baf7a` → `#17a06f` | 2.82 on surface, 2.64 on surface-2 | 3.34, 3.13 |

### Verification: audit-and-fix pass (2026-11-23, Node 25, Go toolchain, Chromium via Playwright, mock on port 9141)

| Check | Result |
|---|---|
| `make ui-test` (265 tests: adds the formatters, `tablesort`, sortable `table()`, the severity mark in every state and in the severity key, `screenFailure`, skeleton coverage, the unfold summary, and the token contrast and print-palette checks) | PASS |
| `go build ./...`, `go test ./internal/consoleui/...` | PASS |
| Scripted sweep of 24 routes, dark 1440px and light 375px (one h1, no skipped heading levels, captions and `th scope`, named controls, sticky headers, horizontal scroll, touch targets, console errors) | PASS after fixes; the only console errors were the intended 401 before sign-in and the forced 404s |
| No page-level horizontal scroll: 11 table screens at 1440 and 1280px dark | PASS |
| Viewed: Events, Sources (sorted), Rules, Audit, Overview, an older-server Decoys at 1440px; Event, Investigation, Recommendations, Sensors, Node, Audit, Rules, Sources, Investigations, Events and sign-in at 375px | PASS |
| Keyboard focus ring on the first 45 tab stops of Overview, Events, Sources, a session, Rules, Fleet, Guide, light and dark; focus returns after palette, shortcut sheet, side panel and theme menu | PASS (found and fixed the tempo ribbon) |
| Reduced motion emulated on the same seven screens: no element with a running transition or animation | PASS |
| Print emulation of the Digest, session story and campaign detail from a dark theme | PASS after the fix |
| Firefox, Safari, screen readers, the real Go console server, a real phone | NOT RUN: only Chromium and the mock were used |

### Console redesign: the data-terminal style (2026-11-23)

A redesign of the existing console, not a rewrite: same stack, routes, data
and behaviour. The method was the tasteskill (v2.1.5, MIT) app-screen route,
used as a design method only: nothing from it (CSS, scripts, fonts, images)
ships in the console. Its dealt style, **data terminal**, is a dark
monitoring screen read in long sessions where every selection is one 1px
accent line and numbers carry their sign in the text, not in colour; that
matches principle 3 (neutral numbers). Palette and typefaces were kept (the
draw dealt composition only), and `tokens.css` is unchanged. The dealt icon
rail was declined: the console has 19 destinations, and the skill's own rule
keeps labels beyond five.

Each key screen answers one question first, with its largest block:

| Screen | Question | Finding read first |
|---|---|---|
| Overview | What did the decoys observe in this window, and does any of it need me? | The brief beside its counts (total events and the change against the window before) |
| Events | What exactly happened, newest first, and which ones matter? | The matching count over the list, severity per row |
| Sessions / session story | What did this source do, in what order, and how sure are we it was automated? | The actor reading and its hedged sentence, beside duration, events, pace |
| Campaigns / detail | Are several sources following the same playbook? | The score: shared steps lane by lane |
| Posture | Is this deployment configured the way a decoy network should be? | Needs attention, first |
| Digest | What changed, in words I can forward? | The lead paragraph |

What changed:

- **Surfaces**: flat panels, briefs, heroes and cards (one surface step and
  a hairline, no resting shadow, no top sheen); no lattice behind data (it
  stays on sign-in, in empty states and on the landing page); an opaque top
  bar and sidebar on the canvas, no blur; sticky table headers opaque on the
  panel surface, no band; no zebra.
- **One selection mark**: the current screen (a 1px cobalt line on the
  sidebar edge, label in full ink), the time window and other segmented
  choices (the word with a 1px line under it, no track), tabs (1px), and the
  active palette row, open table row, current menu item and Guide entry (a
  neutral `--color-surface-3` step with a 1px line).
- **Controls**: fully round, flat, outlined; one cobalt primary per view.
- **Type**: page titles 26px serif (22px on phones), panel titles 16px,
  stat values 24px, the Overview total 32px; `.caps` and the other readout
  labels sentence case; nothing under 11px (chart, mesh, tempo and score
  labels went from 9-10px to 11px).
- **Overview**: the brief (21px serif from 1200px) beside a divided count
  list (`.tally`) replaces six sparkline tiles; then the chart; then one
  divided block of what to read next (investigations, sessions, campaigns);
  paired panels end level: top rules capped at 5 and recent signals at 7 as
  compact one-line entries, each with a link to the full list; on phones the
  ranked sources keep their first five.
- **Elsewhere**: peer counts (Decoys, Honeytokens) in one divided
  container; the session hero keeps the reading on the left over the
  figures and stage ribbon; tempo break labels that would overlap are left
  out (the marks stay); the sessions list shows two rule chips and counts the
  rest; proposal callouts get a dashed edge; skeletons are flat; the digest
  title has no eyebrow; the select chevron is an inline SVG; the score's
  scroll cue is a visible scrollbar.

Kept on purpose, against the skill: three typefaces (the serif briefing
voice and monospace for evidence and ids are project rules); hatched textures
on stages, the automation mix and "no finding" (shape, not colour alone);
attacker strings shown exactly as received, emoji included; the "what you
can do here" hint under each title; relative times left-aligned as the first
column of a log.

Contrast: no token value changed. `webtest/contrast.test.mjs` now also checks
the 1px selection line (`--color-accent`) on surface, surface-3 and canvas
(3:1 non-text, both themes). Muted text on the neutral selected step:
`--color-ink-3` on `--color-surface-3` 4.77:1 light, 5.01:1 dark.

Motion: the skeleton shimmer is gone; the nav indicator still slides (as a
line); nothing new animates.

### Verification: data-terminal redesign (2026-11-23, Node 25, Go toolchain, headless Chromium via the skill's inspector, mock on port 9161)

The skill's inspector (`inspect.mjs --app`, 1440, 768 and 390px, the
browser's dark scheme) cannot sign in, so it was run through a scratch
wrapper that posts the mock's `dev-analyst` token first and marks the tour
done; nothing in the repository changed for it. FAIL / WARN per screen:

| Screen | Before | After |
|---|---|---|
| Overview | 4 / 3 | 0 / 3 |
| Events | 3 / 2 | 1 / 2 |
| Sessions | 2 / 2 | 0 / 2 |
| Session story | 4 / 4 | 1 / 5 |
| Campaigns | 1 / 1 | 0 / 1 |
| Campaign detail | 4 / 1 | 0 / 2 |
| Posture | 3 / 3 | 0 / 2 |
| Digest | 3 / 1 | 0 / 1 |
| Sign-in | 2 / 3 | 0 / 2 |
| Total | 26 / 20 | 2 / 20 |

The two FAILs left are an emoji inside attacker-supplied evidence in the
mock's synthetic data (Events, session story): evidence is shown exactly as
received. Remaining WARNs, each defended: three typefaces (serif briefing
voice, monospace evidence); text under 13px (a dense 13px table with 12px
meta); relative times left-aligned as a log's first column, and stacked
phone cards; blocks below the first screen on long screens whose answer is
on it (Overview, Posture, the story); the story's timeline beside a shorter
side column, and the campaign hero beside its caveats (a list and its
detail rail); one empty "Automation observations" card keeping its frame.
The skill's source lint went from 28 FAIL / 94 WARN to 0 FAIL / 71 WARN
(the rest: shadows on what floats, monospace evidence, one sticky bar).

| Check | Result |
|---|---|
| `make ui-test` (266 tests: adds `tally` and the selection-line contrast pairs) | PASS (one run hit "mock did not start" under load; the re-run passed) |
| `go build ./...`, `go test ./internal/consoleui/...` | PASS |
| Viewed, dark and light, 1440 and 390px: Overview, Events, Sessions, a session story, Campaigns, a campaign, Posture, Digest; sign-in dark 1440; the command palette dark 1440 | PASS after fixes (hero band, phone rule labels, surfaces chips, signals balance) |
| Scripted at 375px light on ten screens (those eight, Decoys, Honeytokens): one h1, no skipped heading level, no horizontal page scroll, `aria-sort` on the sortable campaign table | PASS; panel-head and card-foot links raised to 40px |
| Page exceptions in the browser on the screens above | PASS (none) |
| Firefox, Safari, screen readers, the real Go console server, a real phone | NOT RUN: only Chromium and the mock |

### Settings and administration (round 5, 2026-11-23)

What a security team expects from a serious console: who am I and what may I
do, how the console shows time, where am I signed in, keys for scripts, and,
for admins, who has access and what the server is running with. Built
against contract r5 while the backend landed in parallel; every page has an
older-server state.

**Where it is.** Sidebar, Operate, Settings (`g ,`); the account menu in the
top bar (Your profile, Preferences, Sessions, API keys); the palette
(Preferences, Manage API keys, Your sessions; for admins Manage accounts and
Export the audit trail). Tab titles read "API keys · Settings · AegisMesh";
detail pages carry crumbs (Settings / Your account / API keys).

**Layout.** One screen, `#/settings[/<section>]` and
`#/settings/accounts/<id>` (ids from a closed list and three closed shapes,
`lib/route.js`). Desktop: a sub-navigation beside the section, the current
item marked with the console's one selection (neutral step and a 1px accent
line). Below 768px the index is the list (each row its name, what it is for,
a chevron) and each section is its own page whose crumbs lead back.

| Section | What it does |
|---|---|
| Profile | Name, account id (copyable), kind, role, tenants, active tenant, sign-in method, account source with its reason, created, last seen, session expiry; "What the role can do" in two lists, said to explain and not grant |
| Preferences | Time zone (UTC, local time), default time window, row density, colour theme, motion (follow the system, always reduce). Native radios drawn as words with the 1px line; each applies at once; a polite status says where it was saved |
| Sessions | Your signed-in sessions: client family, method, address, started, last active, expires and idle expiry; "This browser" marked; Revoke, or Sign out for this browser; sign out all others |
| API keys | Create (label, lifetime 30/90/180/365 days, default 90), the one-time reveal, the list with status, created by, expires, last used; revoke with the label typed. Accounts that may not manage keys get the reason instead of a form |
| Accounts (admin) | Every account with a source mark, role, tenants, status, last seen, keys, sessions; a source filter; create a managed person or service; the source legend |
| Account detail (admin) | Managed: name, role, tenants (form), disable or enable (typed name), create and revoke keys, revoke sessions. Configured and single sign-on: read-only with the reason; their keys and sessions can still be revoked |
| Active sessions (admin) | Every session with its account; revoke any (your own signs you out) |
| Single sign-on, Security and access, Data and retention, Detection, Fleet, Exports (admin) | `/admin/settings` sections, read-only: label, value, source mark, how to change it, copyable config key; a banner says they are file-driven. Single sign-on without OIDC links the configuration reference |
| Audit export (admin) | JSON Lines or CSV, everything or the last 24 hours, 7 or 30 days; the audited download helper with a fixed file name; what the file proves and does not |
| System (admin) | Version, commit, build, Go, schema, started, uptime, where the licence notices are; component health as a word and a shape; any settings section the console does not know yet |

**Preferences.** `lib/prefs.js` is the one store. It applies the browser copy
before the first request, then the account's values after sign-in (a change
of time zone or default window redraws the open screen). A change applies at
once and is saved; a refused save puts the previous value back on screen and
in the browser copy, says so in the section's status and in a toast, and
serialises later saves so an early answer never overwrites a later choice.
The top-bar theme menu and density toggle change the same store. Local time:
`formatDateTime` prints `UTC+1` (or `UTC−3:30`) after every absolute time,
captions say "local time", and event filter inputs stay UTC (they say so).
"Always reduce" sets `html[data-reduce-motion]`, which zeroes transitions and
animations like the OS setting does and skips view transitions in script.

**One confirmation pattern.** `confirmAction` (`ui/settings-kit.js`): a
native modal dialog (focus trap, inert page, Esc), the consequence in one
sentence, the target named in a definition row, a typed match for keys and
accounts (exact; the confirm button stays disabled until it matches), both
buttons disabled while the request runs and Esc held, a refusal kept inside
the dialog in words (`refusalMessage`: `last_admin`, `not_managed`,
`name_taken`, `limit_reached`, 403, 404, unreachable). Focus starts on the
typed field or on Cancel and returns to the opener.

**One feedback pattern.** Forms report inline: each field's error under it
(`aria-invalid`), and an error summary above the form that takes focus and
links each problem to its field; submit is disabled with a busy label while
the request runs; Enter submits. An action's outcome is a toast, in the
console's polite live region. A server refusal on a form goes in the summary.

**The one-time reveal.** After a key is created, a framed panel replaces the
top of the section and takes focus: "Copy it now. You will not see this key
again.", the key in monospace, prefix, expiry, how to send it, Copy key and
"I have stored it". Dismissing it or leaving the page empties the Text node
and removes the panel. The list never carries the token.

**Gating.** Administration is drawn only when `/me` says
`capabilities.administer`. That is a convenience: an admin page reached
without it says "Your account cannot open this page" without asking the
server, a 403 from the server says the same in place, a 404 on an older
server says "This server does not provide account management yet" (no retry
button: retrying cannot help), and a 401 ends the session as everywhere else.

**Marks.** Account source: filled square Configured, ringed dot Single
sign-on, hollow diamond Managed (accent). Setting source: filled square
Config file, ring Default, half-filled square Environment, ringed dot
Measured (runtime), dashed Unknown.
Each with its word; the title explains it.

**Reconciled with the backend** (it landed during this work; the mock
follows it): `/admin/settings` items may have `source: "runtime"` (measured
facts: usage, occupancy, discovery, certificate expiry), drawn as "Measured"
with a ringed dot, and the body carries a top-level `note` the banner shows;
`/system` has no licence page (`licenses_url` is empty), so System names the
release's NOTICE file instead of linking; accounts carry `editable` (the
console edits only when it is true and the source is managed) and
`updated_at`; a configured operator reads "disabled" while token sign-in is
off, which also stops managed keys (the detail page says so); `limits`
carries `max_key_days` and `default_key_days`, which set the key lifetime
choices; sessions carry `account_id` and `account_name`; 409 codes are
`last_admin`, `not_managed` and a plain `conflict` (name taken, disabled
account, quota), whose server message is shown as is; the audit export is the
active tenant's chain, oldest first, at most 10,000 records; `/node` storage
adds `healthy` (shown on Node when present); the Audit screen's action filter
knows `account.create`, `account.update`, `key.create`, `key.revoke`,
`session.revoke`, `preferences.update`, `audit.export`. Still mock-only:
viewers and OIDC identities cannot manage their own keys (to exercise the
403 state), and `X-AegisMesh-Audit-Records` on the export.

**Not done (round 5).** Nothing in `/admin/settings` was editable then;
round 6 below adds the allowlisted console settings. `last_admin` cannot be produced by the mock while a
configured admin exists, so it is covered by a unit test only. Password
sign-in does not exist and is not planned.

### Roles, permissions, editable settings and accepted risk (round 6, 2026-11-24)

Built against contract r6 while the backend landed in parallel; the mock
follows the backend's answers (refusal codes, sources, audit detail
format). Every page has an older-server state (`--round6 off`) and an
editing-off state (`--settings-editing off`).

**Permissions drive the interface.** After sign-in the console reads
`/me` once: `permissions` on a round-6 server, else the built-in role's
fixed set (viewer, analyst, admin grant exactly what they granted before).
If `/me` fails for another reason and the role is not a built-in, nothing
is hidden and the server's 403s speak. Built-in roles are named by id on
the server ("viewer"); the console says them as words.

**Roles** (Administration, `#/settings/roles`, `#/settings/roles/<id>`,
`#/settings/roles/new[?from=<id>]`). The list: every role with kind (Built
in, Custom), permission count with a high-risk mark, who holds it by
source (one per line), last change; under it a risk summary (custom roles
of the limit, how many hold high-risk permissions, how many nobody holds)
and the risk legend. A role page: the permission matrix grouped as the
server's catalogue (`GET /permissions`, the built-in copy when absent),
each row its plain label, id and risk; high-risk rows carry their reason.
Beside it (sticky from 1200px) "What this role can and cannot do" redraws
as boxes change, and the unsaved difference leads it. The server's
dependency rules (roles.manage needs accounts.manage; settings.manage
needs accounts.manage and settings.read; accounts.manage and
sessions.manage need accounts.read) are said in one sentence with one
button that adds what is missing. Saving opens the confirmation dialog with
the sentence "Adds 2, removes 1; affects 3 accounts — takes effect on their
next request." and the lists. Built-ins are read-only (a granted mark or a
dash, no disabled form) with "Duplicate as custom role". Delete is typed;
an `in_use` refusal lists who holds the role, with links, and the page
shows the holders anyway. `exceeds_own_permissions` is said in words.
Account forms pick built-in or custom roles (optgroups) with the role's
summary and permission count; Profile lists your permissions grouped, with
"Not included" folded.

**Editable settings.** Where `/admin/settings` marks an item editable,
the row keeps its layout and gains: the Editable tag, the value in words
(the same words as the file value and the history: "12 hours", not "12h"),
"Overrides the config file value 8 hours." with the Console source mark,
the constraints as one help sentence, when it applies, Change, Revert to
file value, and a link to its history. Change opens the editor in place:
the new value (seconds as a number and a unit with the value in words;
days as a number; a choice as words; text with a character count), a
required reason (the server's `reason_max_len`), what the change affects.
Validation is inline from `constraints`; the save is not optimistic: the
row shows the server's answer ("Saved: 12 hours → 10 hours. Applies at
once.") and a toast. Revert asks first, naming both values. Without
`settings.manage` the page says once, in its banner, who may change the
rows marked Editable. When editing is off, one calm panel says why (the
file stays the one source of truth) and the two config lines that turn it
on; nothing on the page looks disabled. `posture.accepted` links to
Posture. The organisation name and banner refresh the top bar after a save.

**Change history** (`#/settings/history[?key=…]`): when, setting (label
and key), old → new in words, Changed or Reverted, who, reason; a filter
by setting; a link to the audit trail filtered to setting changes. The
server keeps a bounded history; the audit trail keeps every record.

**Organisation name and sign-in banner** (from `/meta`): the name in the
top bar (in the drawer on phones) and on the sign-in card; the banner on
the sign-in card and once per console session after sign-in as a
dismissible notice above the screen (remembered in this tab under the
session's expiry, which a tenant switch keeps). Both are Text nodes; the
banner keeps line breaks and nothing else is interpreted. Reports and
print headers do not carry the name yet.

**Posture, accepted risk.** Attention items offer "Accept risk…" to
`settings.manage` (the reason why not to everyone else): a reason and an
end date, 30, 90 or 180 days or a date (UTC, at most 180 days). Accepted
items move to their own panel, "Accepted risk · N", each with who, why,
until (and how long that is) and "Still present: accepting records a
decision, it does not fix anything", with Revoke acceptance. The summary
counts accepted risk separately and the Overview's quiet line says "1
accepted as a known risk". Nothing presents accepted risk as fixed.

**Audit.** The action filter is grouped (sign-in, access, settings and
posture, investigations, evidence out, audit, fleet), each action with
words beside its code, and knows role.*, settings.*, posture.*. A setting
change reads "Session lifetime: 12 hours → 10 hours" with the reason and a
link to the history (parsed from the server's `from="…" to="…" seq=N
reason="…"`); a role change names the role and its permissions; an
acceptance its end and reason. A detail that does not parse is shown as
written. Records (with the filters on them) come first; the chain check
follows.

**The tour.** Its popover is placed by `tourPlacement` (`lib/viz.js`):
never over the element it describes nor over the step's key content (the
brief and its counts), scrolling the page up when that makes room below.

### Verification: roles, settings and accepted risk (2026-11-24, Node 25, Go toolchain, Chromium in the Claude browser pane, mocks on ports 9191, 9192 `--round6 off`, 9193 `--settings-editing off`)

| Check | Result |
|---|---|
| `make ui-test` (342 tests: adds `access.test.mjs` for permissions, role rules, settings parsing and history, audit details, accepted risk and the tour placement; `accessscreens.test.mjs` for the roles list, built-in and custom role pages, the dependency fix, settings edit, refusal, revert, editing off, history, posture accept; `mockroles.test.mjs`; the banner as one Text node on the sign-in card) | PASS (one earlier run hit "mock did not start" under load; the re-run passed) |
| `go build ./...`, `go test ./internal/consoleui/...` | PASS |
| Driven in the browser as admin: edit a custom role (dependency warning, fix, diff dialog, save), change and validate session lifetime, change the organisation name (top bar follows), history, accept and revoke risk, audit details | PASS |
| Seen: Roles, a role page, Security and access, Console, Change history, Posture, Audit, sign-in (admin, dark 1440); Console as a custom-role auditor (light 1440); Profile and Posture as viewer (light 375, dark 1440); role editor and banner editor (admin, light 375); editing off (dark 1440); round 6 off (scripted: roles, console, history, posture) | PASS after fixes (cramped roles table, invisible high-risk fill, repeated permission reasons, "12h" beside "8 hours") |
| Tour at 1440 and 375: popover overlaps neither the brief nor the counts on steps 1 and 2 | PASS (scripted) |
| Scripted at 375px on 22 routes (the 15 reviewed screens and the new ones): one h1, no horizontal page scroll, no text under 11px | PASS after fixes |
| Firefox, Safari, screen readers, the real Go server with the r6 backend, a real phone | NOT RUN: only Chromium and the mock |

## Brand

The name stays **AegisMesh** (module path, binary, Helm chart and docs depend
on it). The mark changed on 2026-11-23 from a shield with a mesh to a **net
closed around a lure**: a diamond perimeter (the protective mesh), four links
reaching in from its sides, and a solid diamond at the centre that they do
not touch (the decoy, held in the net). It is the console's decoy glyph
caught inside a mesh: what the product is, without a padlock, a shield or a
check.

- **Geometry.** 24-unit grid, three paths (`BRAND_PATHS` in `ui/icons.js`):
  perimeter `M12 2.75 21.25 12 12 21.25 2.75 12z`, links, lure. Strokes 1.75
  with round caps and joins (2 in the favicon), lure filled. One colour:
  `currentColor`.
- **Files.** `site/assets/brand/aegismesh-mark{,-dark,-mono}.svg` and
  `aegismesh-lockup{,-dark,-mono}.svg` (mono uses `currentColor`, so an `<img>`
  draws it black); the favicons (`internal/consoleui/static/assets/icon.svg`,
  `site/assets/icon.svg`) switch between cobalt `#2e4fc9` and `#8ea5ff` with
  the colour scheme. `webtest/brand.test.mjs` fails if any copy drifts or the
  old shield returns.
- **Lockup.** Mark, then "AegisMesh" in the display serif (`--font-display`,
  semibold, −0.012em), gap 8px at a 24px mark. In the SVG lockups the wordmark is
  set as text in the same serif stack, so it renders in the platform serif.
- **Colour.** Cobalt `--color-accent` on light (the landing footer too),
  `#8ea5ff` on dark, white on a cobalt fill. Never two colours inside the mark, never a
  gradient, never on a busy photo.
- **Clear space.** Half the mark's height on every side (12px at 24px).
- **Minimum size.** 16px for the mark (favicon, rail sidebar); 96px wide for
  the lockup. Below 16px use the word alone.
- **Don't.** Rotate it (it is a diamond already: rotated it becomes a square
  grid), outline the lure, join the links to the lure, add a shield or a lock,
  put the mark inside a container shape, stretch it, or set the wordmark in
  the sans.

Rejected candidates (not in the repository): a hexagon of six nodes with
three spokes to a hollow core (read as a generic cube or cluster logo); an
"A" drawn as a mesh with a hollow decoy node on the crossbar (read as a
compass or a stick figure, and its legs thinned out at 16px); the chosen net
with filled nodes at its four corners (busy at 16px, read as a molecule);
and the net with a ringed core (read as a crosshair, the wrong idea for a
defensive product).

### Verification: settings, administration and brand (2026-11-23, Node 25, Go toolchain, Chromium via Playwright, mocks on ports 9181, 9182 `--round5 off`, 9183 `--fail-prefs`)

| Check | Result |
|---|---|
| `make ui-test` (304 tests, after reconciling with the backend: adds preferences store and rollback, time zone and default window, settings routes, gating, validation and refusals, the client's refusal reason, the confirmation dialog, the key reveal lifecycle, the settings renderer, screen rendering for viewer, admin, older server and 403, the r5 mock contract with `--round5 off` and `--fail-prefs`, and brand consistency) | PASS |
| `go build ./...`, `go test ./internal/consoleui/...` | PASS |
| Scripted sweep, 104 captures: admin 17 settings routes (index, four account sections, accounts, a managed and a configured account, active sessions, six settings pages, audit export, system), viewer 6 (incl. a denied admin page), older server 3; each dark and light at 1440 and 375px: signed in, one h1, no horizontal page scroll, no text under 11px, no page errors | PASS |
| Driven in the browser: create a key (empty label shows the summary and takes focus; the reveal takes focus; after "I have stored it" no `amk_` token remains in the page or in storage); revoke with typed label (button disabled until it matches); time zone to local (sidebar says "Times in local time", saved to the account); always reduce motion; density from the top bar updates the radio; theme change against `--fail-prefs` rolled back with a status line and a toast; `g ,`; `?` lists Settings; the account menu links | PASS (found and fixed: a 204 revoke read as "cancelled"; the submit button lost its icon after a request; synthetic idle times in the past) |
| Brand candidates compared at 16, 32 and 64px on dark and light | Done; see "Brand" |
| Landing pictures retaken (15 WebP, identical pixel sizes, 0.6 MB in all) and the landing viewed at 1440 and 390px: every picture loads, no horizontal scroll, no console errors; the footer mark was fixed (white on a light footer) | PASS |
| Firefox, Safari, screen readers, the real Go server with the r5 backend, a real phone | NOT RUN: only Chromium and the mock |

## Interaction

- **Command palette** (Cmd/Ctrl+K, or the search button): screens, actions
  (live events, theme, shortcuts, "Switch tenant: …" with several tenants,
  sign out), sensors, the top 50 sources of
  the last 24 hours, investigations, rules, Guide entries, recents, and a
  server-side event search (see "Understanding aids"). Ranking: exact, prefix, word start,
  substring, then fuzzy; tested in `webtest/palette.test.mjs`. A pasted
  32-hex event id offers to open that event.
- **Shortcuts** (`?` shows them): `g` then `o/b/e/s/c/m/t/i/r/d/k/n/u/p/a/h/,` to go
  to a screen (`b` Digest, `m` Campaigns, `d` Decoys, `k` Honeytokens, `u` Rules,
  `p` Posture, `a` Audit for admins, `,` Settings). The sheet's "Go to a screen" rows are
  generated from `NAV`, the same list the router binds, so it cannot drift. `/` to search events, `j`/`k` to move through the events list,
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
# add --round6 off to answer like a round-5 server (no permissions, roles,
# editable settings, history or accepted risk); --settings-editing off for a
# round-6 server with console editing off (default on in the mock)
# add --round5 off to answer like a server without accounts and settings
# (404 on /me, /admin/*, /system), --fail-prefs to refuse preference saves
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

### Verification: identity pass (2026-11-22, Chromium in the Claude browser pane, mock on port 9133)

| Check | Result |
|---|---|
| `make ui-test` (209 tests, adding sparkline marks, mesh layout, last-bucket activity, tempo layout, density parsing, the unfold sentence) | PASS |
| `go test ./internal/consoleui` | PASS |
| Overview dark and light at 1440px (display titles, brief, lattice, lead tile, sensor mesh); LLMjacking session dark at 1440px (unfold sentence, tempo ribbon, timeline) | PASS |
| 375px light: session story and Overview; no horizontal page scroll on Overview, Events, Sessions, Techniques, Rules, Guide (found and fixed: a help tip's enlarged hit area poking past the content edge) | PASS |
| Ghosting fix in a visible, motion-enabled browser; reduced motion; site pages after the identity change; dark at 375px for this pass | NOT RUN: the pane is hidden (View Transitions and animations do not progress), cannot emulate reduced motion, and refused the static site server |

### Identity pass, continued (2026-11-22)

- **Stage bar regression fixed.** The session hero's stage bar used the
  `reveal-x` clip-path entrance; where that reveal did not complete, the bar
  stayed clipped to a fraction of its width. The bar is now static and
  full-width, and the discovery segment has a visible fill. Checked in dark and
  light at 1440px and at 375px.
- **Sign-in:** the title and a one-line statement in the display serif, a
  lattice field behind the card, an accent top edge on the card.
- **Sidebar rail:** "Collapse sidebar" at the foot of the nav switches to an
  icon rail (`html[data-rail]`, remembered as `aegismesh.rail`, desktop widths
  only). Labels stay in each link's accessible name and tooltip.
- **First-run tour** (`ui/tour.js`): six steps (situation brief, counts,
  Sessions, Digest, search, Guide; Digest added in the catalogs pass) in a
  non-modal popover. No overlay, nothing behind
  it is inert, focus moves to the step title, Esc or "Skip tour" ends it,
  finishing or skipping is remembered (`aegismesh.tour`), steps whose target
  is hidden (the nav drawer on phones) are skipped, and the Guide has "Take
  the six-step tour again".
- **Tables:** while a table scrolls sideways in its wrapper, the first column
  sticks to the left edge.
- **Site:** `site/index.html` is rebuilt: a serif headline on a lattice field,
  a composed showcase from the real components (situation brief, sensor mesh,
  a story slice) with synthetic data and a caption that says so, one card per
  shipped capability, "What it is not", and a quick start whose commands are
  taken from `docs/cli.md` (`make build`, `demo --console`, `init --profile
  ai-decoy`, `honeytoken new`, `run --dry-run`). `site/design-system.html`
  gains "Identity" and "Mesh, tempo, density" sections; the earlier sections
  remain. The dev mock serves `site/` read-only under `/__site/` so the pages
  can be checked with the console's security headers.

| Check | Result |
|---|---|
| `make ui-test` (210 tests) and `go test ./internal/consoleui` | PASS |
| Stage bar: session hero, dark and light 1440px, 375px (DOM width and screenshot) | PASS |
| Landing: dark 1440px (hero, capabilities, what it is not, quick start), light 375px (hero, showcase); no horizontal scroll | PASS |
| Style guide: dark 1440px, Identity and Mesh/tempo/density sections; no horizontal scroll | PASS |
| Sign-in dark 1440px; tour and rail on Overview dark 1440px; no horizontal scroll at 375px on Overview, Guide, Sessions, a session | PASS |
| Landing light 1440px and dark 375px; style guide light and 375px; sign-in light and 375px; tour at 375px; reduced motion | NOT RUN |

## Landing page

`site/index.html` (not hosted, not embedded in the binary) was redesigned on
2026-11-23 with the tasteskill design method. It keeps the console's identity:
the dark graphite ground, the cobalt accent (dark-theme `#8ea5ff`, turned to
`#84a8ff`, OKLCH hue 266, because the kit refuses violet hues from 270 to 330),
the system serif for headings, the brand mark and the 24px lattice behind the
hero. The page is always dark (`color-scheme: dark`); it does not follow the
OS light theme as the console does.

- **Structure:** one section per screen (two for the feature cards, the steps
  and the questions on tablets and phones): the hero (the session timeline),
  the console's session page, four decoy and analysis cards, a statement of
  what AegisMesh never does, evidence, three setup steps, questions, and the
  close with the footer.
- **Pictures:** WebP screenshots of the console running on the development
  mock with synthetic data, at 2x and about 0.5 MB in all. Retaken on
  2026-11-23 after the data-terminal redesign and the new mark: same routes,
  crops, file names and pixel sizes (dark, 2x, `cwebp -q 80 -m 6`; phone
  files are top-left crops of the desktop captures); the event picture is
  taken at a 970px viewport, where the event page is one column, and
  `share.jpg` is the new first screen at 1200×750. No photographs,
  third-party logos or web fonts (`docs/license-policy.md`).
- **No script:** `webtest/site.test.mjs` keeps the site free of scripts and
  inline styles, so the hero entrance and the statement that lights up word by
  word as it scrolls are CSS (`@keyframes`, `animation-timeline: view()`), and
  both rest under `prefers-reduced-motion`. Without scroll-driven animation
  support the statement simply stands in full ink.
- **Checks:** the kit's checker and finish gate; results and waivers are in
  `docs/verification.md`.
