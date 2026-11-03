# Design — Detonation Chamber

<!-- impeccable:design-doc 1 -->

Visual world: **Screening Console** — a checkpoint baggage X-ray console. The
untrusted artifact goes through the tunnel; its behaviour comes out as a
false-colour image you read. Documented from the shipped build (`web/`).

## Principles

1. **Evidence is the surface.** The scan strip and event log are the product;
   the verdict is a summary of them, never a substitute.
2. **Colour is meaning, not decoration.** Every hue is a material role. If a
   colour is on screen, it is reporting a fact.
3. **Panels tile, they don't float.** Edge-to-edge on hairline rules. No cards,
   no shadows, no rounded containers. Depth comes from the red threat box, used
   only for contained attempts.
4. **One instrument voice.** Tabular mono for every number, path, and timestamp;
   a grotesk for prose.

## Color tokens

Light ground is deliberate: an X-ray is read on a bright lightbox, and an
analyst needs paths and numbers legible for long sessions. There is no dark
variant; browser surfaces are themed to the light ground.

| Token | Value | Role |
|-------|-------|------|
| `--ground` | `#f7f7f4` | page ground (air-white film) |
| `--film` | `#fbfbf9` | panel / input fill |
| `--ink` | `#141414` | primary text, borders, detonate button |
| `--ink-2` | `#45433e` | secondary text (≥4.5:1 on ground) |
| `--ink-3` | `#67645c` | tertiary / labels (≥4.5:1 on ground) |
| `--rule` | `#d9d6cd` | structural hairline (1px) |
| `--rule-2` | `#e6e3da` | inner hairline / lane grid |
| `--file` | `#e8871e` | **filesystem** events (orange) |
| `--proc` | `#2f8f43` | **process** events (green) |
| `--net` | `#2b5fb8` | **network** events (blue) |
| `--blocked` | `#141414` | **contained** events (ink fill) |
| `--threat` | `#d7261e` | threat box outline / contained marker (red) |
| `--benign` / `--suspect` / `--malware` | `#2f8f43` / `#b4600f` / `#c81e18` | verdict labels |

Material rule: bands use `mix-blend-mode: multiply` so overlapping behaviour
darkens where it coincides, like stacked X-ray exposures. Blocked and threat
bands switch to `normal` blend so the red box stays exact.

## Type

- Display / UI: **Archivo** (grotesk), 400–800, `font-stretch` for the wordmark.
- Data / mono: **Spline Sans Mono**, with `font-feature-settings: "tnum"` for
  aligned columns. Used for all paths, timestamps, ports, scores, and labels.
- Floors: functional text ≥ 11px; body 15px; measure held under ~75ch in prose.

## Signature component — the scan strip

A horizontal time axis. Three lanes: filesystem (top), process (middle),
network (bottom). Each event is a band positioned at its `ts`, width scaled to
its `duration`; the axis rescales as the run grows. Severity-3 or blocked events
get the red threat box (`outline` + offset, `z-index` lift). Selecting any event
(band or log row) adds `.has-sel` to the strip, dimming every other band to 0.22
so the selection and its detail read instantly. Entrance is a single authored
moment: bands `scaleX` in from the left over 0.32s ease-out; disabled under
`prefers-reduced-motion`.

## Layout

- `max-width: 1240px`. Status bar is sticky, hairline-divided.
- Lower region is a `1fr / 400px` grid (log | verdict), collapsing to one column
  under 920px with column-count reduction in the log table.
- Verdict panel recolours its ground only for `malicious` (`#fdf3f2`).

## States shipped

Empty (chamber sealed, legend explained), running (`body.running`, animated
wordmark aperture, disabled detonate), populated (live bands + log), verdict
(label + meter + reasons + IOCs with copy), synthetic replay (hazard-tape
banner). Hover and keyboard focus on bands and rows; `Esc` clears selection.

## Non-obvious decisions

- `?fixture=exfil` renders a representative completed run **with no network
  call**, via the production render path, for screenshots and offline demos.
- The hazard-tape repeating gradient on the synthetic banner and the X-ray
  aperture wordmark are the two intentional non-content textures; both carry
  meaning (synthetic warning; the scanner itself).
- Panels flush to the section border is the committed "tiles, not cards" world;
  inner panels carry their own padding.
