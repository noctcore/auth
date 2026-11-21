// Ties the enumeration, captcha, trust proxy, cookies and revocation Learn
// pages (the ones about what a request does and does not reveal), their code
// samples and their diagrams to the package source. The numbers on the pages
// are checked in learn-numbers.test.ts; this file checks the drawings, the
// samples and the page structure, and the attack links of all five.
import { clientIp, type AuthMailEvent } from '@noctcore/auth';
import { describe, expect, it } from 'bun:test';
import { enqueueOnlyMailer } from '../snippets/learn/enumeration';
import { attackLinkTests, diagram, num, only, page, snippet, source } from './learn-checks';

const PAGES = {
  enumeration: 'EnumerationLogin',
  captcha: 'CaptchaOrder',
  'trust-proxy-and-client-ips': 'TrustProxyHops',
  'cookies-and-desktop-shells': 'CookiesShell',
  'revocation-races': 'RevocationRace',
} as const;

const captchaTimeoutMs = num('auth/src/http/turnstile.ts', /options\.timeoutMs \?\? (\d+);/u);

describe('Learn request diagrams', () => {
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

describe('Learn request code samples', () => {
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

describe('Learn request attack links', () => {
  attackLinkTests(Object.keys(PAGES));
});

describe('Learn request text', () => {
  it('has no em or en dash in the pages, diagrams or samples', () => {
    const files = [
      ...Object.keys(PAGES).map(page),
      ...Object.values(PAGES).map(diagram),
      ...['enumeration', 'captcha', 'trust-proxy', 'cookies', 'revocation'].map(snippet),
    ];

    for (const text of files) expect(text).not.toMatch(/[–—]/u);
  });
});
