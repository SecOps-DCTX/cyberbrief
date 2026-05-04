---
name: cyberbrief-design
description: Use this skill to generate well-branded interfaces and assets for CyberBrief — a cyberpunk daily cybersecurity intelligence feed (breaches, CVEs, threat intel, news). Contains essential design guidelines, colors, type, fonts, components, and a runnable UI kit for prototyping.
user-invocable: true
---

Read the README.md file within this skill, and explore the other available files.

If creating visual artifacts (mocks, throwaway prototypes, additional report views, dashboards, etc), copy assets out and create static HTML files for the user to view. The brand essentials are:

- **Backgrounds:** deep navy-black (`#090d13`, `#0d1520`, `#111c2e`)
- **Neons:** cyan `#00f5ff` (primary), pink `#ff2d78` (accent), green `#00ff9d`, red `#ff3a3a`, orange `#ff8c00`
- **Type:** `Share Tech Mono` for display/labels/badges, `Rajdhani` for body/titles
- **Scanline overlay** (2px repeating, ~7% black) is the brand signature — apply via `body::before` to every screen
- **Sharp corners** (1–4px max), 1px borders in `#1a2e45`, neon glow halos in place of drop shadows
- **Voice:** operator-terse, command-prefixed (`// SECTION TITLE`), all caps for labels, mono for technical data, no emoji

If working on production code, copy `colors_and_type.css` and follow the patterns in `ui_kits/brief/index.html`. The design is single-column, full-bleed, with collapsible sections that have colored 2px left bars and 1px gradient hairlines on top.

If the user invokes this skill without any other guidance, ask them what they want to build (additional sections? archive view? alert digest? email template? dashboard?), then act as an expert cyberpunk-UI designer who outputs HTML artifacts or production code, depending on the need.
