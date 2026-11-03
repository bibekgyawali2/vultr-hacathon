---
version: 1
slug: "web-index-html"
primary_target: "web/index.html"
related_targets: []
---

Scope: the single-page analyst console (web/index.html). Mode: Operate.
Audience: AppSec/SOC analyst first, developer second. Job: submit an artifact, watch the run, read the verdict, copy indicators.

## Direction contract

THESIS: The artifact goes through the tunnel and its behaviour comes out as an X-ray image, coloured by what it touched. Refuses the dark KPI-tile security dashboard.

OWN-WORLD: X-ray air-white ground (#f7f7f4), ink #141414. Material roles, fixed: orange = filesystem, green = process, blue = network, black = blocked/dense, red = screener's threat box only. Translucent layers multiply where they overlap. Panels tile edge to edge on 1px hairline rules; no cards, no shadows, no radius beyond 2px. One tabular mono for every number, path and timestamp; a grotesk for prose.
Raises: hairline mosaic (high-density); single mono at data density (datamatics); band length = exact duration (labanotation); selection dims all other layers (streaming wall).

STORY: The analyst sees the chamber is sealed, pastes an identifier, watches the strip fill in, sees a red box land on a contained attempt, reads a one-word verdict, copies the IOCs.

FIRST VIEWPORT: Status line (runtime, egress policy) at the top; full-width input with a Detonate action; the scan strip full width at ~200px; below it the event log (7/12) beside the verdict and agent notes (5/12).

FORM: Screening Console, position 4 of 7, seed f72475f6. Signature interaction: the live strip, with click-to-select dimming.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
