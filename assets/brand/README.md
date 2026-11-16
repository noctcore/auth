# noctcore/auth identity

**Open passage** makes the library's promise visible: a small core stays in view,
framed by two offset, open boundaries. The diagonal opening becomes a passage
through the illustrations. A legitimate login continues; attack branches end
at the boundary that addresses them. The mark is original, hand drawn SVG
geometry, not a padlock, shield, certification seal or claim of perfect security.

The lead expression is night: pale blue on deep blue ink. Paper is the daytime
reading surface. Warm copper belongs to stopped attack branches and their
labels, never to the product name. The drawing language is precise linework,
solid depth planes and quiet construction lines. There are no gradients, glows
or embedded images.

The wordmark is **noctcore/auth**, rather than `auth` alone. It gives the new
library an identifiable home in the noctcore family and matches the GitHub
repository. In running prose and install instructions, use **@noctcore/auth**.
The leading promise is **Auth you can read.** Its supporting line is
**Every module tied to the attack it stops.**

## Files

| File | Purpose |
| --- | --- |
| `icon.svg` | Primary square icon, night tile on either theme |
| `icon-mono.svg` | Transparent, single color mark using `currentColor` |
| `icon-{16,32,64,180,512}.png` | Favicon, app icon and GitHub avatar exports |
| `favicon.svg` | Self contained SVG favicon, same pixel grid as the primary icon |
| `logo.svg` | Default transparent lockup for a light surface |
| `logo-light.svg` | Blue mark and ink wordmark for a light surface |
| `logo-dark.svg` | Pale blue mark and pale wordmark for a dark surface |
| `social-preview.svg` | Editable, outlined 1280 x 640 social artwork |
| `social-preview.png` | GitHub social preview, exactly 1280 x 640, under 1 MB |
| `readme-header-light.svg` | Wide 1280 x 360 banner for light mode |
| `readme-header-dark.svg` | Wide 1280 x 360 banner for dark mode |
| `hero-light.svg` | Paper version of the 1040 x 680 docs illustration |
| `hero-dark.svg` | Night version of the 1040 x 680 docs illustration |
| `design.mjs` | Editable geometry, typography and composition source for every SVG |
| `export.mjs` | Exports and verifies every shipped PNG; parses every SVG |
| `fonts/` | Exact, openly licensed fonts used to rebuild the outlined lettering |
| `licenses/` | Complete font copyright notices and SIL Open Font License texts |

Suffixes name the **intended background**, not the lettering color. Every SVG
contains a title and description. All visible lettering is paths: displaying
an asset requires no fonts, network requests, scripts or raster resources.
The font files are source material for editing, not runtime dependencies.

## Palette

Hex sRGB values are the source of truth. The OKLCH equivalents below are
calculated from those values and rounded to six decimals for lightness and
chroma, and three decimals for hue. CSS can use either notation. Do not
independently tune one representation and leave the other behind.

| Token | Hex | OKLCH | Role |
| --- | --- | --- | --- |
| Night | `#17212D` | `oklch(0.244064 0.027165 253.382)` | Lead background, icon tile |
| Paper | `#F6F5F1` | `oklch(0.969807 0.005408 95.100)` | Light background |
| Ink | `#202B39` | `oklch(0.285357 0.030053 254.712)` | Light text |
| Blue | `#355E87` | `oklch(0.470960 0.081369 249.927)` | Light mark and login path |
| Pale blue | `#AAC8E2` | `oklch(0.819224 0.048956 244.585)` | Night mark and login path |
| Cloud | `#F0F3F6` | `oklch(0.962726 0.005147 247.877)` | Night primary text |
| Slate | `#596773` | `oklch(0.506390 0.025655 244.160)` | Light secondary text |
| Mist | `#B3BEC9` | `oklch(0.796355 0.019786 248.077)` | Night secondary text |
| Copper, night | `#D9A08E` | `oklch(0.755069 0.073037 38.251)` | Attack labels and stop caps on night |
| Copper, day | `#92513E` | `oklch(0.507415 0.092265 37.120)` | Attack labels and stop caps on paper |

The supporting construction palette is decorative. Do not use these colors
for text or meaningful control boundaries without checking their contrast.
Grid lines are deliberately quiet and do not carry information by themselves.

| Role | Night | Paper |
| --- | --- | --- |
| Raised passage | `#202F40` | `#EDF0F1` |
| Side faces | `#2C4055` | `#CCD8E1` |
| Depth plane | `#101924` | `#DDE2E4` |
| Construction line | `#405367` | `#B9C6D0` |
| Grid, at 48% opacity | `#253344` | `#E3E6E6` |

### Text contrast

Ratios use WCAG relative luminance for opaque sRGB colors. All text pairings
exceed **4.5:1**, the WCAG AA threshold for normal text, including the small
mono labels. This is a palette statement, not a claim that every application
of the assets makes a site WCAG conformant. Keep important information in
HTML too, and provide descriptive image alternatives.

| Text | Background | Ratio |
| --- | --- | --- |
| Cloud `#F0F3F6` | Night `#17212D` | 14.60:1 |
| Pale blue `#AAC8E2` | Night `#17212D` | 9.34:1 |
| Mist `#B3BEC9` | Night `#17212D` | 8.61:1 |
| Copper `#D9A08E` | Night `#17212D` | 7.25:1 |
| Ink `#202B39` | Paper `#F6F5F1` | 13.13:1 |
| Blue `#355E87` | Paper `#F6F5F1` | 6.20:1 |
| Slate `#596773` | Paper `#F6F5F1` | 5.33:1 |
| Copper `#92513E` | Paper `#F6F5F1` | 5.55:1 |

Color is redundant in the illustrations: the legitimate route is continuous
with forward arrows, while attack branches are dashed and end with a
perpendicular cap. Keep the labels and these line styles when recoloring.

## Usage rules

- Keep the mark upright and preserve both open corners and the visible core.
  Do not close the openings, round the internal corners, rotate, stretch,
  add effects or insert a checkmark.
- The icon uses a 64-unit canvas. Its occupied area is x=12..52, y=12..52;
  strokes, core and openings use an exact four-unit grid. At 16 px, the
  eight-unit strokes and core are two pixels wide. The mark also fits inside
  a circular avatar crop without losing its corners.
- Keep at least eight SVG units of clear space beyond the mark's occupied
  geometry. The square icon already provides twelve. Around a lockup, allow
  at least one core-square width of clear space on every side.
- Use the supplied tile from 16 px up. Use a transparent mark at 24 px or
  larger, and the full lockup at 180 px wide or larger. Use the mono mark
  whenever the color version would lose contrast.
- For inline mono SVG, `currentColor` inherits from CSS. External SVG in
  `<img>` does not inherit the surrounding page color; use the default black,
  a CSS mask, or explicitly set a suitable color in a local copy.
- Choose `logo-dark.svg` for dark surfaces and `logo-light.svg` for light
  surfaces. The icon tile stays night in both themes. Do not tint the
  wordmark copper.
- Use external SVG images where possible. If inlining multiple SVGs, give
  their title and description IDs unique prefixes and update
  `aria-labelledby` to match.
- The docs heroes are designed and checked at **640 px wide**, where the
  20-unit explanatory captions render at about 12.3 px. Keep them near that
  width when their annotations need to be read. At narrow mobile widths,
  use the adjacent HTML explanation rather than relying on tiny image text.
- The README banners use larger module names and omit the hero's secondary
  captions. They are checked at 830 px wide, close to GitHub's reading width.
  Their role is an introduction, not a complete security diagram.
- Preserve the social preview's 1280 x 640 canvas. Essential content sits
  inside x=100..1176 and y=76..560. Keep those margins for replacement copy.
  Extreme alternate aspect-ratio crops can still remove secondary content.

### What the illustrations mean

The drawings are conceptual module maps, not executable flow diagrams or a
complete threat model. They show three examples of why a boundary exists:

1. **Reserve attempt** limits brute force before password work starts.
2. **Verify password** sits within the uniform-work and uniform-public-answer
   policy that limits enumeration. Password verification alone does not
   provide enumeration protection.
3. **Epoch fence** rejects a stolen session **after revocation** because its
   stamped epoch is stale. It does not promise to detect every stolen token.
   The README uses the shorter label **revoked token** for this same case.

The real epoch is read before checking credentials and checked again at mint;
validation also compares epochs. The simplified drawing does not replace that
ordering. CSRF, expiry, token storage and the library's other protections are
outside this illustration. Use the Learn pages for their actual rules.

## README picture snippet

Paste this into the repository root README when ready. The root README is not
changed by this asset set. Light is the fallback for renderers without media
support.

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/readme-header-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/brand/readme-header-light.svg">
  <img src="assets/brand/readme-header-light.svg" width="1280" height="360" alt="noctcore/auth. Auth you can read. Every module tied to the attack it stops.">
</picture>
```

For a docs illustration, choose the appropriate `hero-*.svg` with the site's
explicit theme state. The files do not read system preference internally, so
an explicit light theme still works on a computer set to dark mode. A useful
alternative is: "A login passes through rate limiting, password verification
and an epoch fence. Attack branches stop at the corresponding boundaries;
a stolen session is rejected after revocation."

## Typography and licensing

The wordmark and headings use **Manrope 600**; supporting prose uses
**Manrope 550**. Technical labels use **DM Mono Regular 400**. Both families
use the **SIL Open Font License 1.1**, with the complete upstream notices in
[`licenses/Manrope-OFL.txt`](licenses/Manrope-OFL.txt) and
[`licenses/DM-Mono-OFL.txt`](licenses/DM-Mono-OFL.txt). The included original
font binaries are unmodified. Provenance, pinned upstream links and SHA-256
hashes are recorded in [`fonts/README.md`](fonts/README.md).

The original mark, illustrations, layouts and scripts use this repository's
MIT license. Font software retains its separate OFL license. No stock icons,
third-party illustrations or raster images are included.

## Rebuild and verify

Requires Node.js 22 or later and npm. Tooling is self contained here; the Bun
workspace and its root dependencies are unchanged. From the repository root:

```sh
npm --prefix assets/brand ci
npm --prefix assets/brand run export
npm --prefix assets/brand run check
```

`export` renders the SVG sources directly with pinned `@resvg/resvg-js` 2.6.2,
with system fonts disabled. It writes all five icon PNG sizes and the native
1280 x 640 social preview, prints their dimensions and byte sizes, and rejects
an oversized preview. There is no screen capture or lossy post-processing.
`check` renders again without writing files and requires every PNG to match
byte for byte. Both commands parse every SVG and enforce the 150 KB hero limit.

To change copy, geometry or composition, edit `design.mjs` and run:

```sh
npm --prefix assets/brand run design
npm --prefix assets/brand run export
npm --prefix assets/brand run check
```

`design` uses the included fonts and pinned `fontkit` 2.0.4 to rebuild all SVGs,
including path outlines. SVGs can also be edited directly in a vector editor;
run `export` after those edits, and avoid running `design` until the source
changes have been transferred back to `design.mjs`.

GitHub's social preview must be uploaded manually in repository **Settings >
General > Social preview**. GitHub has no API for that upload; opening or
merging this asset PR does not activate the preview.
