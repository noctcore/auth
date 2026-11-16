// Original Open passage identity. All visible lettering is converted to paths.
import { writeFileSync } from 'node:fs';
import { fileURLToPath, URL } from 'node:url';
import console from 'node:console';
import * as fontkit from 'fontkit';

const directory = new URL('./', import.meta.url);
const font = fontkit.openSync(fileURLToPath(new URL('fonts/Manrope.ttf', directory)));
const sans = font.getVariation({ wght: 550 });
const display = font.getVariation({ wght: 600 });
const mono = fontkit.openSync(fileURLToPath(new URL('fonts/DMMono-Regular.ttf', directory)));
const palettes = {
  dark: {
    background: '#17212D',
    foreground: '#F0F3F6',
    accent: '#AAC8E2',
    secondary: '#B3BEC9',
    line: '#405367',
    grid: '#253344',
    raised: '#202F40',
    side: '#2C4055',
    attack: '#D9A08E',
    shadow: '#101924',
  },
  light: {
    background: '#F6F5F1',
    foreground: '#202B39',
    accent: '#355E87',
    secondary: '#596773',
    line: '#B9C6D0',
    grid: '#E3E6E6',
    raised: '#EDF0F1',
    side: '#CCD8E1',
    attack: '#92513E',
    shadow: '#DDE2E4',
  },
};
const round = (value) => Number(value.toFixed(3));
const escape = (value) =>
  value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');

function lettering(value, x, y, size, color, face = sans, spacing = 0) {
  const run = face.layout(value);
  let cursor = x;
  const paths = run.glyphs
    .map((glyph, index) => {
      const position = run.positions[index];
      const scale = size / face.unitsPerEm;
      const preciseScale = Number(scale.toFixed(6));
      const path = `<path d="${glyph.path.toSVG()}" transform="translate(${round(cursor + position.xOffset * scale)} ${round(y - position.yOffset * scale)}) scale(${preciseScale} ${-preciseScale})"/>`;
      cursor += position.xAdvance * scale + spacing;
      return path;
    })
    .join('');
  return `<g fill="${color}" aria-label="${escape(value)}">${paths}</g>`;
}

function document(width, height, title, description, content, extra = '') {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="title desc" ${extra}><title id="title">${escape(title)}</title><desc id="desc">${escape(description)}</desc>${content}</svg>\n`;
}

function rectangle(x, y, width, height, fill, radius = 0, stroke = 'none') {
  return `<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="${radius}" fill="${fill}" stroke="${stroke}"/>`;
}

// Two opposing open corners and a visible core, on an exact four-unit grid.
const geometry = '<path d="M12 12h28v8H20v20h-8zM52 52H24v-8h20V24h8zM28 28h8v8h-8z"/>';
function mark(x, y, size, color) {
  return `<g transform="translate(${x} ${y}) scale(${size / 64})" fill="${color}">${geometry}</g>`;
}

function lockup(x, y, scale, palette) {
  return `<g transform="translate(${x} ${y}) scale(${scale})">${mark(0, 0, 64, palette.accent)}${lettering('noctcore/auth', 72, 47, 43, palette.foreground, display, -0.4)}</g>`;
}

function line(path, color, width = 1, extra = '') {
  return `<path d="${path}" fill="none" stroke="${color}" stroke-width="${width}" ${extra}/>`;
}

function grid(palette, width, height) {
  return `<defs><pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse"><path d="M40 0H0V40" fill="none" stroke="${palette.grid}" stroke-width="1"/></pattern></defs>${rectangle(0, 0, width, height, palette.background)}<g opacity=".48">${rectangle(0, 0, width, height, 'url(#grid)')}</g>`;
}

// A split portal has real side faces. The pass line crosses its open diagonal.
function portal(cx, cy, size, palette) {
  const scale = size / 64;
  return (
    `<g transform="translate(${cx - size / 2} ${cy - size / 2}) scale(${scale})">` +
    `<g transform="translate(0 7)" fill="${palette.shadow}">${geometry}</g>` +
    `<path d="M12 40v7h8v-7zM20 20v7h20v-7zM24 52v7h28v-7zM52 24v7h-8v-7zM28 36v7h8v-7z" fill="${palette.side}"/>` +
    `<g fill="${palette.accent}">${geometry}</g>` +
    line('M12 12h28M12 12v28M24 44h20V24M28 28h8', palette.foreground, 0.55) +
    '</g>'
  );
}

function stopped(path, capX, capY, palette) {
  return (
    line(path, palette.attack, 2, 'stroke-dasharray="5 7"') +
    line(`M${capX - 9} ${capY}h18`, palette.attack, 3) +
    `<circle cx="${capX}" cy="${capY}" r="3" fill="${palette.attack}"/>`
  );
}

function routeDiagram(palette, { compact = false } = {}) {
  // All coordinates share a 1040 x 640 drawing space.
  let content = '';
  content += `<g opacity=".55">${line('M80 551L965 207M80 575L965 231', palette.line, 1)}${line('M220 140v430M500 100v450M780 70v370', palette.grid, 1)}</g>`;
  // Broad, lightly raised routing bed. No blur or gradient is used.
  content += `<path d="M76 512L950 172v28L76 540z" fill="${palette.shadow}"/>`;
  content += `<path d="M76 488L950 148v24L76 512z" fill="${palette.raised}" stroke="${palette.line}"/>`;
  const route = 'M76 501L950 161';
  content += line(route, palette.accent, 3);
  for (const [x, y] of [
    [111, 487],
    [383, 382],
    [661, 274],
    [924, 171],
  ]) {
    content += `<path d="M${x - 6} ${y - 2}l8 2-4 7" fill="none" stroke="${palette.accent}" stroke-width="2"/>`;
  }
  // The branches terminate at the outside face of each open boundary.
  const attackSize = compact ? 32 : 23;
  content += lettering('brute force', 92, 156, attackSize, palette.attack, mono);
  content += lettering('enumeration', 363, 101, attackSize, palette.attack, mono);
  content += lettering(
    compact ? 'revoked token' : 'stolen session',
    707,
    56,
    attackSize,
    palette.attack,
    mono,
  );
  if (!compact) content += lettering('after revocation', 742, 86, 18, palette.secondary, mono);
  content += portal(220, 445, 120, palette);
  content += portal(500, 336, 138, palette);
  content += portal(780, 227, 120, palette);
  content += stopped('M158 189v76l62 42v100.5', 220, 407.5, palette);
  content += stopped('M430 132v55l70 40v65.875', 500, 292.875, palette);
  content += stopped('M871 87v38l-91 35v29.5', 780, 189.5, palette);
  // Callouts sit at different depths, rather than inside a repeated card row.
  for (const [x, y, num, name, detail] of [
    [220, 445, '01', 'reserve attempt', 'before password work'],
    [500, 336, '02', 'verify password', 'one public answer'],
    [780, 227, '03', 'epoch fence', 'reject a stale epoch'],
  ]) {
    content += line(`M${x} ${y + 65}v39h20`, palette.line, 1);
    if (!compact) content += lettering(num, x + 27, y + 110, 15, palette.accent, mono);
    content += lettering(name, x - 39, y + 147, compact ? 36 : 26, palette.foreground, display);
    if (!compact) content += lettering(detail, x - 39, y + 180, 20, palette.secondary, mono);
  }
  content += `<circle cx="76" cy="501" r="7" fill="${palette.background}" stroke="${palette.accent}" stroke-width="3"/>`;
  content += `<circle cx="950" cy="161" r="9" fill="${palette.accent}"/>`;
  content += `<circle cx="950" cy="161" r="16" fill="none" stroke="${palette.line}"/>`;
  content += lettering('login', 51, 547, compact ? 26 : 21, palette.foreground, mono);
  content += lettering('session', 884, 117, compact ? 26 : 21, palette.foreground, mono);
  return content;
}

function ribbon(palette) {
  // A dedicated wide composition, preserving readable labels in social crops.
  let content = `<path d="M0 151L1040 101v22L0 173z" fill="${palette.shadow}"/>`;
  content += `<path d="M0 134L1040 84v17L0 151z" fill="${palette.raised}" stroke="${palette.line}"/>`;
  content += line('M0 142L1040 92', palette.accent, 3);
  const gates = [
    [165, 134, 100, '01', 'reserve attempt', 'brute force'],
    [510, 117, 116, '02', 'verify password', 'enumeration'],
    [855, 101, 100, '03', 'epoch fence', 'stolen session'],
  ];
  for (const [x, y, size, num, name, attack] of gates) {
    const top = y - (size * 20) / 64;
    content += lettering(attack, x - 80, 12, 18, palette.attack, mono);
    if (num === '03')
      content += lettering('after revocation', x + 14, 40, 16, palette.secondary, mono);
    content += portal(x, y, size, palette);
    content += stopped(`M${x - 43} 24v18l43 17v${top - 59}`, x, top, palette);
    content += line(`M${x} ${y + size / 2}v${200 - y - size / 2}`, palette.line);
    content += lettering(num, x - 80, 225, 13, palette.accent, mono);
    content += lettering(name, x - 48, 225, 20, palette.foreground, display);
  }
  for (const [x, y] of [
    [54, 139],
    [349, 125],
    [704, 108],
    [996, 94],
  ]) {
    content += line(`M${x - 6} ${y - 5}l8 4-7 5`, palette.accent, 2);
  }
  content += `<circle cx="0" cy="142" r="6" fill="${palette.background}" stroke="${palette.accent}" stroke-width="2"/>`;
  content += `<circle cx="1040" cy="92" r="8" fill="${palette.accent}"/>`;
  content += lettering('login', -17, 193, 16, palette.secondary, mono);
  content += lettering('session', 983, 141, 16, palette.secondary, mono);
  return content;
}

const outputs = new Map();
const save = (name, source) => outputs.set(name, source);
const description =
  'Open passage: two offset open corners frame a visible square core. Authentication with its rules and reasons in view.';
save(
  'icon.svg',
  document(
    64,
    64,
    'noctcore/auth',
    description,
    rectangle(0, 0, 64, 64, palettes.dark.background, 12) + mark(0, 0, 64, palettes.dark.accent),
  ),
);
save(
  'favicon.svg',
  document(
    64,
    64,
    'noctcore/auth',
    description,
    rectangle(0, 0, 64, 64, palettes.dark.background, 12) + mark(0, 0, 64, palettes.dark.accent),
  ),
);
save(
  'icon-mono.svg',
  document(64, 64, 'noctcore/auth', description, mark(0, 0, 64, 'currentColor')),
);
for (const theme of ['dark', 'light']) {
  const palette = palettes[theme];
  const logo = document(375, 64, 'noctcore/auth', description, lockup(0, 0, 1, palette));
  save(`logo-${theme}.svg`, logo);
  if (theme === 'light') save('logo.svg', logo);
  save(
    `hero-${theme}.svg`,
    document(
      1040,
      680,
      'A login, with its reasons in view',
      'A legitimate login continues through reserve attempt, verify password and the epoch fence to a session. Brute force and enumeration paths stop at the first two boundaries. A stolen session is rejected by the epoch fence after revocation. Simplified conceptual illustration, not executable flow code.',
      grid(palette, 1040, 680) +
        lettering('LOGIN / MODULE MAP', 52, 42, 14, palette.secondary, mono, 1.2) +
        `<g transform="translate(0 20)">${routeDiagram(palette)}</g>`,
    ),
  );
  const header =
    grid(palette, 1280, 360) +
    lockup(88, 56, 0.9, palette) +
    lettering('Auth you can read.', 88, 207, 54, palette.foreground, display, -1.3) +
    lettering('Every module tied to the attack it stops.', 90, 256, 23, palette.secondary) +
    `<g transform="translate(690 10) scale(.49)">${routeDiagram(palette, { compact: true })}</g>`;
  save(
    `readme-header-${theme}.svg`,
    document(
      1280,
      360,
      'noctcore/auth. Auth you can read.',
      'Every module tied to the attack it stops. A readable login path continues while attack branches stop at their boundaries.',
      header,
    ),
  );
}
const palette = palettes.dark;
const social =
  grid(palette, 1280, 640) +
  lockup(104, 76, 0.82, palette) +
  lettering('TYPESCRIPT / OPEN SOURCE', 855, 113, 13, palette.accent, mono, 1.1) +
  lettering('Auth you can read.', 104, 234, 65, palette.foreground, display, -1.4) +
  lettering('Every module tied to the attack it stops.', 107, 283, 25, palette.secondary) +
  `<g transform="translate(119 331)">${ribbon(palette)}</g>`;
save(
  'social-preview.svg',
  document(
    1280,
    640,
    'noctcore/auth. Auth you can read.',
    'Every module tied to the attack it stops. A login passes through readable boundaries while brute force, enumeration and a revoked stolen session are stopped. TypeScript. Open source.',
    social,
  ),
);
for (const [name, source] of outputs) writeFileSync(new URL(name, directory), source);
console.log(`Wrote ${outputs.size} outlined SVG sources.`);
