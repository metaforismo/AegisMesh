# Credits and licences for the landing page

The landing page (`site/index.html`) loads only files from this folder. It loads no
script, no web font and nothing from another host.

## Third-party files

| Path | Title | Creator | Licence | Source |
|---|---|---|---|---|
| `assets/landing/kit/system.css` | tasteskill kit: system | Leonxlnx and contributors | MIT (`assets/landing/kit/LICENSE`) | https://github.com/Leonxlnx/taste-skill, v2.5.1, commit `6c0b5c78f5d31776e2210305abaa210cdc0030bf`, `skills/taste-skill/assets/system.css` |
| `assets/landing/kit/ui/cards.css` | tasteskill kit: cards | Leonxlnx and contributors | MIT | same commit, `skills/taste-skill/assets/ui/cards.css` |
| `assets/landing/kit/motion/motion.css` | tasteskill kit: motion | Leonxlnx and contributors | MIT | same commit, `skills/taste-skill/assets/motion/motion.css` |
| `assets/landing/kit/layout/layout.css` | tasteskill kit: layout | Leonxlnx and contributors | MIT | same commit, `skills/taste-skill/assets/layout/layout.css` |

The four files are byte-for-byte copies; the kit's MIT licence text, which the licence
requires to travel with them, is `assets/landing/kit/LICENSE`. MIT is an allowed licence
in `docs/license-policy.md`.

## Project material

| Path | What it is | Licence |
|---|---|---|
| `assets/landing/img/console-*.webp` | Screenshots of the AegisMesh operator console, taken from the development mock (`internal/consoleui/devserver/mock-server.mjs`) with its synthetic data: documentation-range addresses (RFC 5737, RFC 3849) and invented markers | Apache-2.0, part of this project |
| `assets/landing/share.jpg` | The landing page's own first screen, for link previews | Apache-2.0, part of this project |
| `assets/landing/landing.css`, `assets/icon.svg`, `assets/brand/*.svg`, the inline brand mark | The project's own page CSS and brand mark (a net closed around a lure) | Apache-2.0, part of this project |

## Not used, and why

- **Photographs and stock images.** None. The page shows the product's own console instead.
- **Web fonts.** None. The page uses the console's system font stacks. The type pairing the
  design method suggested is published under the SIL Open Font Licence, which is not in the
  licence set allowed by `docs/license-policy.md`.
- **Third-party logos and icons** (Ollama, OpenAI, MITRE, OWASP). None. Product names appear as
  text only; they are trademarks of their owners.
