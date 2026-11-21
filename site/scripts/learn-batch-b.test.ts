// Ties the enumeration, captcha, trust proxy, cookies and revocation Learn
// pages, their code samples and their diagrams to the package source, the
// way learn-numbers.test.ts does for the pages it lists. Captcha, trust proxy
// and cookies already have their numbers checked there; this file adds the
// two pages it does not list, the numbers the diagrams draw, and the attack
// links of all five.
import { readFileSync } from 'node:fs';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { clientIp, type AuthMailEvent } from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { enqueueOnlyMailer } from '../snippets/learn/enumeration';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(SITE, '..');
const LEARN = join(SITE, 'src/content/docs/learn');
const DIAGRAMS = join(SITE, 'src/components/docs/diagrams');

const page = (slug: string) => readFileSync(join(LEARN, `${slug}.mdx`), 'utf8');
const diagram = (name: string) => readFileSync(join(DIAGRAMS, `${name}.astro`), 'utf8');
const snippet = (name: string) => readFileSync(join(SITE, 'snippets/learn', `${name}.ts`), 'utf8');
const source = (path: string) => readFileSync(join(REPO, 'packages', path), 'utf8');

/** The one capture of `pattern` in `text`; it must match exactly once. */
function only(text: string, pattern: RegExp): string {
  const matches = [...text.matchAll(new RegExp(pattern.source, `${pattern.flags}g`))];

  expect(matches.map((m) => m[0])).toHaveLength(1);

  return matches[0]?.[1] ?? '';
}

const PAGES = {
  enumeration: 'EnumerationLogin',
  captcha: 'CaptchaOrder',
  'trust-proxy-and-client-ips': 'TrustProxyHops',
  'cookies-and-desktop-shells': 'CookiesShell',
  'revocation-races': 'RevocationRace',
} as const;

// Values from the code ------------------------------------------------------

/** The |t| threshold the timing comparison uses (dudect's). */
const timingThreshold = Number(
  only(source('auth/tests/timing/compare.ts'), /const THRESHOLD = ([\d.]+);/u),
);

const captchaTimeoutMs = Number(
  only(source('auth/src/http/turnstile.ts'), /options\.timeoutMs \?\? (\d+);/u),
);

// The facts of the two pages learn-numbers.test.ts does not list -------------

const FACTS: Record<string, readonly string[]> = {
  enumeration: [
    // A wall-clock measurement on one laptop, not a constant: listed so that
    // no other number can slip onto the page unchecked.
    'The taken path about 4.5 ms slower',
    `(\\|t\\| under ${timingThreshold}, on a heavily loaded machine)`,
  ],
  'revocation-races': [],
};

const NOT_NUMBERS = [/\]\([^)]*\)/gu, /\bA\d{3}\b/gu];

function strayLines(text: string, facts: readonly string[]): string[] {
  let rest = text;

  for (const fact of [...facts].sort((a, b) => b.length - a.length)) rest = rest.replace(fact, ' ');
  for (const pattern of NOT_NUMBERS) rest = rest.replace(pattern, ' ');

  return rest.split('\n').filter((line) => /\d/u.test(line));
}

describe('Learn batch B page numbers', () => {
  for (const [slug, facts] of Object.entries(FACTS)) {
    it(`${slug} states the values the code uses`, () => {
      const text = page(slug);

      expect(facts.filter((fact) => !text.includes(fact))).toEqual([]);
    });

    it(`${slug} holds no number that is not checked here`, () => {
      expect(strayLines(page(slug), facts)).toEqual([]);
    });
  }
});

describe('Learn batch B diagrams', () => {
  it('each page shows its diagram right after "What goes wrong"', () => {
    for (const [slug, name] of Object.entries(PAGES)) {
      const text = page(slug);
      const section = text.slice(text.indexOf('## What goes wrong'), text.indexOf('## The rule'));

      expect(text).toContain(
        `import ${name} from '../../../components/docs/diagrams/${name}.astro';`,
      );
      expect(section).toContain(`<${name} />`);
      expect(text).toContain('<InShort>');
    }
  });

  it('draws the captcha timeout turnstile.ts uses', () => {
    expect(Number(only(diagram('CaptchaOrder'), /const TIMEOUT_MS = (\d+);/u))).toBe(
      captchaTimeoutMs,
    );
  });

  it('draws the X-Forwarded-For example of the trust proxy page', () => {
    const drawing = diagram('TrustProxyHops');
    const text = page('trust-proxy-and-client-ips');

    expect(only(drawing, /const FORWARDED_FOR = '([^']+)';/u)).toBe(
      only(text, /^X-Forwarded-For: (.+)$/mu),
    );
    expect(only(drawing, /const SOCKET = '([^']+)';/u)).toBe(
      only(text, /^socket address: +(.+)$/mu),
    );
  });

  it('labels the trust proxy picks the way clientIp makes them', () => {
    const remoteAddress = '203.0.113.9';
    const forwardedFor = '192.0.2.66, 198.51.100.23';
    const pick = (trustedHops: number) => clientIp({ remoteAddress, forwardedFor, trustedHops });

    // The notes the drawing puts under each pick.
    expect([pick(0), pick(1), pick(2)]).toEqual([remoteAddress, '198.51.100.23', '192.0.2.66']);
  });

  it('draws salmon only where the package refuses something', () => {
    // The enumeration drawing has no refusal: both paths are the same.
    expect(diagram('EnumerationLogin')).not.toMatch(/nc-d-attack|nc-d-stop|<Stop/u);

    for (const name of ['CaptchaOrder', 'CookiesShell', 'RevocationRace']) {
      expect(diagram(name)).toContain('<Stop');
    }
  });

  it('says the revocation axis is not to scale', () => {
    expect(diagram('RevocationRace')).toContain('not to scale');
  });
});

describe('Learn batch B code samples', () => {
  it('the enumeration Mailer only enqueues the event, under its dedupe key', async () => {
    const added: { data: AuthMailEvent; jobId: string }[] = [];
    const mailer = enqueueOnlyMailer({
      add: async (data, { jobId }) => {
        added.push({ data, jobId });
      },
    });
    const event = {
      type: 'account-exists',
      to: 'owner@example.com',
      userId: 'user-id',
      dedupeKey: 'account-exists:user-id',
    } as unknown as AuthMailEvent;

    await mailer.send(event);

    expect(added).toEqual([{ data: event, jobId: 'account-exists:user-id' }]);
  });

  it('the captcha sample turns on both checks the page asks for', () => {
    const text = snippet('captcha');

    expect(text).toContain('expectedHostnames: [');
    expect(text).toContain('checkAction: true');
    expect(text).toContain('onResult: record');
  });

  it('the cookies sample lists the same shell origin it gives SameSite=None', () => {
    const text = snippet('cookies');
    const shell = only(text, /const SHELL = '([^']+)';/u);

    expect(shell).toBe('app://desktop');
    expect(text).toContain("sameSite: (origin) => (origin === SHELL ? 'none' : 'lax')");
    expect(text).toContain('crossSiteOrigins: [SHELL]');
  });

  it('the revocation sample goes through the public revoke-all', () => {
    expect(snippet('revocation')).toContain('auth.sessions.revokeAll(');
    expect(source('auth/src/session/session-manager.ts')).toContain(
      "return { ok: false, reason: 'epoch_fence' };",
    );
  });
});

describe('Learn batch B attack links', () => {
  const index = readFileSync(join(REPO, 'packages/auth/tests/attacks/ATTACKS.md'), 'utf8');
  const LINK =
    /\[(A\d{3})\]\(https:\/\/github\.com\/noctcore\/auth\/blob\/main\/(packages\/[a-z-]+\/tests\/attacks\/(A\d{3})-[a-z0-9-]+\.test\.ts)\)/gu;

  for (const slug of Object.keys(PAGES)) {
    const text = page(slug);
    const title = /^title: (.+)$/mu.exec(text)?.[1] ?? '';
    const links = [...text.matchAll(LINK)];
    const table = text.slice(text.indexOf('<div class="nc-attacks">'), text.indexOf('</div>'));

    it(`${slug} links attack tests that exist, by their bare id`, () => {
      expect(links.length).toBeGreaterThan(0);

      for (const [, label, path, id] of links) {
        expect(label).toBe(id);
        expect(existsSync(join(REPO, path ?? ''))).toBe(true);
      }
    });

    it(`${slug} has a table row for every attack ATTACKS.md files under it`, () => {
      const named = [...index.matchAll(/^\| (A\d{3}) \| [^|]+ \| ([^|]+) \|/gmu)]
        .filter(([, , pages = '']) => pages.split(';').some((p) => p.trim() === title))
        .map(([, id]) => id);
      const rows = new Set([...table.matchAll(LINK)].map(([, id]) => id));

      expect(named.length).toBeGreaterThan(0);
      expect(named.filter((id) => !rows.has(id))).toEqual([]);
    });
  }
});

describe('Learn batch B text', () => {
  it('has no em or en dash in the pages, diagrams or samples', () => {
    const files = [
      ...Object.keys(PAGES).map(page),
      ...Object.values(PAGES).map(diagram),
      ...['enumeration', 'captcha', 'trust-proxy', 'cookies', 'revocation'].map(snippet),
    ];

    for (const text of files) expect(text).not.toMatch(/[–—]/u);
  });
});
