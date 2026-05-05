# CyberBrief UI Kit

A working rebuild of the CyberBrief daily intel feed using the design-system tokens.

## What's here

- **`index.html`** — runnable single-file rebuild of the brief. Header (logo + date + transmit button), 4 metric tiles, 4 collapsible report sections (Breach / CVE / Threat / News). All data is inline in `DATA = {…}` for now.

## Wiring to GitHub `data.json` (next step)

1. Move the inline `DATA` object out to `data.json` at the root of your GitHub repo.
2. Replace the inline literal with:

```js
fetch('data.json')
  .then(r => r.json())
  .then(d => { DATA = d; render(); })
  .catch(err => { /* show fallback */ });
```

3. Set up a GitHub Actions workflow (or manual commit) that overwrites `data.json` daily with the new intel.
4. Host the artifact on GitHub Pages (or any static host) — `data.json` lives next to `index.html` and is fetched on every page load.

## Tokens

All colors, fonts, glows, and the scanline overlay come from `colors_and_type.css` at the root of this design system. To restyle, update that file — every preview card and the UI kit will pick up changes.
