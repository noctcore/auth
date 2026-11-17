import { describe, expect, it } from 'vitest';

import {
  createCsrfToken,
  verifyCsrfToken,
  verifyFetchSite,
  verifyRequestOrigin,
} from '../../src/http/csrf';

const allowed = ['https://app.example.com', 'app://app'];

describe('verifyRequestOrigin', () => {
  it('lets safe methods through', () => {
    expect(verifyRequestOrigin({ method: 'GET', origin: undefined, allowedOrigins: allowed })).toBe(
      true,
    );
  });

  it('accepts an allowed origin, including a desktop shell scheme', () => {
    expect(
      verifyRequestOrigin({
        method: 'POST',
        origin: 'https://app.example.com',
        allowedOrigins: allowed,
      }),
    ).toBe(true);

    expect(
      verifyRequestOrigin({ method: 'post', origin: 'app://app', allowedOrigins: allowed }),
    ).toBe(true);
  });

  it.each([
    undefined,
    null,
    '',
    'null',
    'https://evil.example',
    'https://app.example.com.evil.example',
    'not a url',
  ])('refuses origin %j on an unsafe method', (origin) => {
    expect(verifyRequestOrigin({ method: 'POST', origin, allowedOrigins: allowed })).toBe(false);
  });
});

describe('signed double-submit token', () => {
  const current = new TextEncoder().encode('current-secret-current-secret-00');
  const previous = new TextEncoder().encode('previous-secret-previous-secret-');

  it('verifies when cookie and header match and the binding is right', () => {
    const token = createCsrfToken(current, 'session-1');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 'session-1',
        secrets: [current],
      }),
    ).toBe(true);
  });

  it('refuses a token minted for another binding', () => {
    const token = createCsrfToken(current, 'session-1');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 'session-2',
        secrets: [current],
      }),
    ).toBe(false);
  });

  it('refuses when the header does not echo the cookie', () => {
    const token = createCsrfToken(current, 's');
    const other = createCsrfToken(current, 's');

    expect(
      verifyCsrfToken({ cookieToken: token, headerToken: other, binding: 's', secrets: [current] }),
    ).toBe(false);

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: undefined,
        binding: 's',
        secrets: [current],
      }),
    ).toBe(false);
  });

  it('accepts a previous secret during rollover and nothing after it is dropped', () => {
    const token = createCsrfToken(previous, 's');

    expect(
      verifyCsrfToken({
        cookieToken: token,
        headerToken: token,
        binding: 's',
        secrets: [current, previous],
      }),
    ).toBe(true);

    expect(
      verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 's', secrets: [current] }),
    ).toBe(false);
  });

  it('refuses malformed tokens', () => {
    for (const token of ['', '.', 'abc', 'abc.', '.abc', 'zz.zz']) {
      expect(
        verifyCsrfToken({
          cookieToken: token,
          headerToken: token,
          binding: 's',
          secrets: [current],
        }),
      ).toBe(false);
    }
  });
});

describe('verifyFetchSite', () => {
  it('accepts same-origin unsafe requests and any safe request', () => {
    expect(verifyFetchSite({ method: 'POST', secFetchSite: 'same-origin' })).toBe(true);
    expect(verifyFetchSite({ method: 'GET', secFetchSite: 'cross-site' })).toBe(true);
  });

  it.each([undefined, null, '', 'cross-site', 'none', 'same-site'])(
    'refuses %j on an unsafe method by default',
    (value) => {
      expect(verifyFetchSite({ method: 'DELETE', secFetchSite: value })).toBe(false);
    },
  );

  it('accepts same-site only when asked', () => {
    expect(
      verifyFetchSite({ method: 'POST', secFetchSite: 'same-site', allowSameSite: true }),
    ).toBe(true);
  });
});

describe('csrf token hardening', () => {
  const secret = new TextEncoder().encode('current-secret-current-secret-00');

  it('refuses secrets shorter than 32 bytes', () => {
    const short = new TextEncoder().encode('too-short');

    expect(() => createCsrfToken(short, 's')).toThrow(/at least 32 bytes/u);

    expect(() =>
      verifyCsrfToken({ cookieToken: 'a.b', headerToken: 'a.b', binding: 's', secrets: [short] }),
    ).toThrow(/at least 32 bytes/u);
  });

  it('refuses a token whose nonce is not 32 lowercase hex characters', () => {
    const token = createCsrfToken(secret, 's');
    const [, mac] = token.split('.');

    for (const nonce of ['', 'zz'.repeat(16), 'AB'.repeat(16), 'ab'.repeat(15)]) {
      const forged = `${nonce}.${mac}`;

      expect(
        verifyCsrfToken({
          cookieToken: forged,
          headerToken: forged,
          binding: 's',
          secrets: [secret],
        }),
      ).toBe(false);
    }
  });

  it('frames binding and nonce so a colon in the binding cannot shift them', () => {
    // Without framing, binding "a:b" + nonce "c" and binding "a" + nonce "b:c" sign the same text.
    const token = createCsrfToken(secret, 'a');

    expect(
      verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 'a:', secrets: [secret] }),
    ).toBe(false);

    expect(
      verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 'a', secrets: [secret] }),
    ).toBe(true);
  });

  it('refuses everything with no secrets', () => {
    const token = createCsrfToken(secret, 's');

    expect(
      verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 's', secrets: [] }),
    ).toBe(false);
  });
});

describe('verifyRequestOrigin with a malformed allowlist entry', () => {
  it('never matches an origin it cannot parse against an entry it cannot parse', () => {
    for (const origin of ['not a url', '::', 'https://'])
      expect(
        verifyRequestOrigin({ method: 'POST', origin, allowedOrigins: ['also not a url'] }),
      ).toBe(false);
  });
});

describe('verifyRequestOrigin case folding', () => {
  it('matches a custom-scheme origin whatever its case, since URL keeps the host of app:// as written', () => {
    expect(new URL('app://APP').host).toBe('APP');

    expect(
      verifyRequestOrigin({ method: 'POST', origin: 'app://APP', allowedOrigins: ['app://app'] }),
    ).toBe(true);

    expect(
      verifyRequestOrigin({ method: 'POST', origin: 'app://app', allowedOrigins: ['APP://App'] }),
    ).toBe(true);
  });
});
