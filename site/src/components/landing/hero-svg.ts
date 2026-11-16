/**
 * Builds the landing page's animated hero from the two brand files
 * (assets/brand/hero-dark.svg and hero-light.svg) at build time.
 *
 * The brand files are the source of truth and stay untouched. This merges
 * them into one inline SVG whose colors are CSS variables (so it follows the
 * theme switch), and tags the parts the animation moves: the route, its
 * arrows, the three checkpoints, the attack branches with their stops and
 * labels, and the step labels. The only element added is the travelling
 * login dot, which ends fully transparent, so the final frame matches the
 * brand art exactly. If the brand art changes shape, this throws and the
 * build fails instead of animating the wrong paths.
 */

const COLOR = /#[0-9a-f]{6}/gi;

export interface HeroSvg {
  /** The inline SVG markup, ready for set:html. */
  readonly svg: string;
}

function pairColors(dark: string, light: string): Map<string, number> {
  if (dark.replace(COLOR, '#') !== light.replace(COLOR, '#'))
    throw new Error('hero-svg: hero-dark.svg and hero-light.svg no longer differ only in color');

  const darkColors = dark.match(COLOR) ?? [];
  const lightColors = light.match(COLOR) ?? [];
  const pairs = new Map<string, number>();

  darkColors.forEach((color, i) => {
    const key = `${color.toUpperCase()}|${(lightColors[i] ?? '').toUpperCase()}`;

    if (!pairs.has(key)) pairs.set(key, pairs.size);
  });

  return pairs;
}

/** Counts per tag signature, checked once the whole file is tagged. */
type Counts = Record<string, number>;

function expect(counts: Counts, name: string, wanted: number): void {
  if ((counts[name] ?? 0) !== wanted)
    throw new Error(
      `hero-svg: expected ${wanted} "${name}" in the brand hero, found ${counts[name] ?? 0}`,
    );
}

export function buildHeroSvg(dark: string, light: string): HeroSvg {
  const pairs = pairColors(dark, light);
  const lightColors = light.match(COLOR) ?? [];
  const counts: Counts = {};
  const masks: string[] = [];
  let colorIndex = 0;
  let attackLabel = 0;
  let stepLabel = 0;

  const count = (name: string): number => {
    counts[name] = (counts[name] ?? 0) + 1;

    return counts[name];
  };

  const tagged = dark.replace(/<(\w+)([^>]*?)(\/?)>/g, (_tag, name: string, attrs: string, selfClose: string) => {
    const classes: string[] = [];
    const extra: string[] = [];
    const styles: string[] = [];
    const d = /\sd="([^"]*)"/.exec(attrs)?.[1] ?? '';
    const label = /aria-label="([^"]*)"/.exec(attrs)?.[1];

    // Colors become variables, as style declarations so every browser reads them.
    let rest = attrs.replace(/\s(fill|stroke)="(#[0-9a-fA-F]{6})"/g, (_m, prop: string, color: string) => {
      const key = `${color.toUpperCase()}|${(lightColors[colorIndex] ?? '').toUpperCase()}`;

      colorIndex++;
      styles.push(`${prop}:var(--nc-h${pairs.get(key)})`);

      return '';
    });

    // The remaining colors (inside the grid pattern) keep the same count in step.
    colorIndex += (rest.match(COLOR) ?? []).length;

    if (name === 'svg') {
      rest = rest
        .replace(/aria-labelledby="title desc"/, 'aria-labelledby="nc-hero-title nc-hero-desc"')
        .replace(/\swidth="\d+"\s+height="\d+"/, ' width="1040" height="680"');
      classes.push('nc-hero-svg');
    }

    if (name === 'title' || name === 'desc') rest = rest.replace(/id="(\w+)"/, 'id="nc-hero-$1"');

    if (name === 'path' && d.startsWith('M76 501L950 161')) {
      classes.push('nc-h-route');
      extra.push('pathLength="1"');
      count('route');
    } else if (name === 'path' && /^M\d+ \d+l8 2-4 7/.test(d)) {
      classes.push('nc-h-arrow', `nc-h-n${count('arrow')}`);
    } else if (name === 'g' && /transform="translate\(\d+ \d+\) scale\((?!0\.0)[\d.]+\)"/.test(rest)) {
      classes.push('nc-h-gate', `nc-h-n${count('gate')}`);
    } else if (name === 'path' && /stroke-dasharray="5 7"/.test(rest)) {
      const n = count('attack');
      const id = `nc-h-mask-${n}`;

      masks.push(
        `<mask id="${id}" maskUnits="userSpaceOnUse"><path class="nc-h-draw nc-h-n${n}" d="${d}" pathLength="1" fill="none" stroke="#fff" stroke-width="10" stroke-linecap="round"/></mask>`,
      );
      classes.push('nc-h-attack', `nc-h-n${n}`);
      extra.push(`mask="url(#${id})"`);
    } else if (name === 'path' && /^M[\d.]+ [\d.]+h18/.test(d)) {
      classes.push('nc-h-stop', `nc-h-n${count('stop-bar')}`);
    } else if (name === 'circle' && /\sr="3"/.test(rest)) {
      classes.push('nc-h-stop', `nc-h-n${count('stop-dot')}`);
    } else if (name === 'path' && /^M\d+ \d+v39h20/.test(d)) {
      classes.push('nc-h-step', `nc-h-n${count('leader')}`);
    } else if (name === 'circle' && /cx="950"/.test(rest) && /\sr="16"/.test(rest)) {
      classes.push('nc-h-end-ring');
      count('end-ring');
    } else if (name === 'circle' && /cx="76"/.test(rest)) {
      count('start');
    } else if (label && ['brute force', 'enumeration', 'stolen session'].includes(label)) {
      attackLabel++;
      classes.push('nc-h-attack-label', `nc-h-n${attackLabel}`);
    } else if (label === 'after revocation') {
      classes.push('nc-h-attack-label', 'nc-h-n3');
    } else if (label && /^0[123]$/.test(label)) {
      stepLabel = Number(label);
      classes.push('nc-h-step', `nc-h-n${stepLabel}`);
      count('step-number');
    } else if (
      label &&
      stepLabel > 0 &&
      [
        'reserve attempt',
        'before password work',
        'verify password',
        'one public answer',
        'epoch fence',
        'reject a stale epoch',
      ].includes(label)
    ) {
      classes.push('nc-h-step', `nc-h-n${stepLabel}`);
    } else if (label === 'session') {
      classes.push('nc-h-end-label');
    }

    const attrList = [
      rest.trim(),
      classes.length ? `class="${classes.join(' ')}"` : '',
      styles.length ? `style="${styles.join(';')}"` : '',
      ...extra,
    ]
      .filter(Boolean)
      .join(' ');

    return `<${name}${attrList ? ` ${attrList}` : ''}${selfClose}>`;
  });

  expect(counts, 'route', 1);
  expect(counts, 'arrow', 4);
  expect(counts, 'gate', 3);
  expect(counts, 'attack', 3);
  expect(counts, 'stop-bar', 3);
  expect(counts, 'stop-dot', 3);
  expect(counts, 'leader', 3);
  expect(counts, 'step-number', 3);
  expect(counts, 'end-ring', 1);
  expect(counts, 'start', 1);

  if (attackLabel !== 3) throw new Error(`hero-svg: expected 3 attack labels, found ${attackLabel}`);

  const theme = (side: 0 | 1) =>
    [...pairs.keys()]
      .map((key, i) => `--nc-h${i}:${key.split('|')[side]}`)
      .join(';');

  // The legitimate login: a dot on the route that travels to the session and fades out.
  const traveler =
    '<circle class="nc-h-traveler" cx="76" cy="501" r="7" style="fill:var(--nc-h-traveler);stroke:var(--nc-h1)" stroke-width="3"/>';

  const svg = tagged
    .replace(
      '<defs>',
      `<style>.nc-hero-svg{${theme(0)};--nc-h-traveler:${pairColorFor(pairs, '#AAC8E2', 0)}}:root[data-theme='light'] .nc-hero-svg{${theme(1)};--nc-h-traveler:${pairColorFor(pairs, '#AAC8E2', 1)}}</style><defs>${masks.join('')}`,
    )
    .replace(/(<circle cx="76"[^>]*\/>)/, `$1${traveler}`);

  return { svg };
}

/** The light-theme partner of a dark-theme color (the route color, for the traveler). */
function pairColorFor(pairs: Map<string, number>, dark: string, side: 0 | 1): string {
  const key = [...pairs.keys()].find((k) => k.startsWith(`${dark.toUpperCase()}|`));

  if (!key) throw new Error(`hero-svg: the brand hero no longer uses ${dark}`);

  return key.split('|')[side] ?? dark;
}
