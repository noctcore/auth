import { describe, expect, it } from 'vitest';

import { createCsrfToken, verifyCsrfToken, verifyFetchSite, verifyRequestOrigin } from '../../src/csrf';

const allowed = ['https://app.example.com', 'app://app'];

describe('verifyRequestOrigin', () => {
  it('lets safe methods through', () => {
    expect(verifyRequestOrigin({ method: 'GET', origin: undefined, allowedOrigins: allowed })).toBe(true);
  });

  it('accepts an allowed origin, including a desktop shell scheme', () => {
    expect(verifyRequestOrigin({ method: 'POST', origin: 'https://app.example.com', allowedOrigins: allowed })).toBe(true);
    expect(verifyRequestOrigin({ method: 'post', origin: 'app://app', allowedOrigins: allowed })).toBe(true);
  });

  it.each([undefined, null, '', 'null', 'https://evil.example', 'https://app.example.com.evil.example', 'not a url'])(
    'refuses origin %j on an unsafe method',
    (origin) => {
      expect(verifyRequestOrigin({ method: 'POST', origin, allowedOrigins: allowed })).toBe(false);
    },
  );
});

describe('signed double-submit token', () => {
  const current = new TextEncoder().encode('current-secret-current-secret-00');
  const previous = new TextEncoder().encode('previous-secret-previous-secret-');

  it('verifies when cookie and header match and the binding is right', () => {
    const token = createCsrfToken(current, 'session-1');
    expect(verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 'session-1', secrets: [current] })).toBe(true);
  });

  it('refuses a token minted for another binding', () => {
    const token = createCsrfToken(current, 'session-1');
    expect(verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 'session-2', secrets: [current] })).toBe(false);
  });

  it('refuses when the header does not echo the cookie', () => {
    const token = createCsrfToken(current, 's');
    const other = createCsrfToken(current, 's');
    expect(verifyCsrfToken({ cookieToken: token, headerToken: other, binding: 's', secrets: [current] })).toBe(false);
    expect(verifyCsrfToken({ cookieToken: token, headerToken: undefined, binding: 's', secrets: [current] })).toBe(false);
  });

  it('accepts a previous secret during rollover and nothing after it is dropped', () => {
    const token = createCsrfToken(previous, 's');
    expect(verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 's', secrets: [current, previous] })).toBe(true);
    expect(verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 's', secrets: [current] })).toBe(false);
  });

  it('refuses malformed tokens', () => {
    for (const token of ['', '.', 'abc', 'abc.', '.abc', 'zz.zz']) {
      expect(verifyCsrfToken({ cookieToken: token, headerToken: token, binding: 's', secrets: [current] })).toBe(false);
    }
  });
});

describe('verifyFetchSite', () => {
  it('accepts same-origin unsafe requests and any safe request', () => {
    expect(verifyFetchSite({ method: 'POST', secFetchSite: 'same-origin' })).toBe(true);
    expect(verifyFetchSite({ method: 'GET', secFetchSite: 'cross-site' })).toBe(true);
  });

  it.each([undefined, null, '', 'cross-site', 'none', 'same-site'])('refuses %j on an unsafe method by default', (value) => {
    expect(verifyFetchSite({ method: 'DELETE', secFetchSite: value })).toBe(false);
  });

  it('accepts same-site only when asked', () => {
    expect(verifyFetchSite({ method: 'POST', secFetchSite: 'same-site', allowSameSite: true })).toBe(true);
  });
});
