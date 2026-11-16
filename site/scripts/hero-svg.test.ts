import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildHeroSvg } from '../src/components/landing/hero-svg';

const brand = join(import.meta.dir, '..', 'src', 'assets', 'brand');
const dark = readFileSync(join(brand, 'hero-dark.svg'), 'utf8');
const light = readFileSync(join(brand, 'hero-light.svg'), 'utf8');

describe('buildHeroSvg', () => {
  const { svg } = buildHeroSvg(dark, light);

  test('turns every fill and stroke into a theme variable', () => {
    expect(svg).not.toMatch(/\s(fill|stroke)="#[0-9a-f]{6}"/i);
    expect(svg).toContain(":root[data-theme='light'] .nc-hero-svg{");
  });

  test('tags every part the animation moves', () => {
    const count = (name: string) => svg.match(new RegExp(`class="(?:[^"]* )?${name}(?=[ "])`, 'g'))?.length ?? 0;

    expect(count('nc-h-route')).toBe(1);
    expect(count('nc-h-gate')).toBe(3);
    expect(count('nc-h-attack')).toBe(3);
    expect(count('nc-h-draw')).toBe(3);
    expect(count('nc-h-stop')).toBe(6);
    expect(count('nc-h-attack-label')).toBe(4);
    expect(count('nc-h-traveler')).toBe(1);
  });

  test('refuses brand files that differ in more than color', () => {
    expect(() => buildHeroSvg(dark, light.replace('M76 501', 'M77 501'))).toThrow();
  });

  test('refuses art whose parts it can no longer find', () => {
    const noRoute = dark.replaceAll('M76 501L950 161', 'M76 500L950 160');

    expect(() => buildHeroSvg(noRoute, light.replaceAll('M76 501L950 161', 'M76 500L950 160'))).toThrow(
      /route/,
    );
  });
});
