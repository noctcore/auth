// A025: choosing your own client IP through the Nest adapter.
//
// The client writes X-Forwarded-For entries so the flows see an IP of its
// choosing (a fresh rate-limit bucket per request), or the app trusts every
// hop. Express's own `req.ip` follows whatever `trust proxy` says, including
// "true".
//
// Stopped by: auth-nestjs src/request.ts: RequestMeta comes from the core's
//   clientIp with the configured hop count, counted from the right, never from
//   req.ip. src/trust-proxy.ts: trustedHopsFromEnv refuses "true", anything
//   that is not a hop count or a valid proxy list, and an unset value in
//   production.
// Learn: Build, "Use with NestJS" (/auth/build/nestjs/); core attack A011
import { AuthConfigError } from '@noctcore/auth';
import { afterEach, describe, expect, it } from 'vitest';
import { trustedHopsFromEnv } from '../../src';
import { boot, Browser, type Booted } from '../support';

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

describe('A025: choosing your own client IP through the Nest adapter', () => {
  it('takes the address the one trusted proxy saw, whatever the client wrote before it', async () => {
    t = await boot({ options: { trustedHops: 1 } });

    for (const forged of ['198.51.100.11', '10.0.0.1, 198.51.100.88', 'unknown, ::1, 127.0.0.1']) {
      const browser = new Browser(t.app, `${forged}, 203.0.113.50`);

      await browser.signIn();

      expect((await browser.send('GET', '/api/meta')).body['ip']).toBe('203.0.113.50');
    }
  });

  it('ignores the header entirely with no trusted proxy', async () => {
    t = await boot({ options: { trustedHops: 0 } });
    const browser = new Browser(t.app, '198.51.100.11');

    await browser.signIn();
    const ip = (await browser.send('GET', '/api/meta')).body['ip'];

    expect(ip).not.toBe('198.51.100.11');
    expect(String(ip)).toMatch(/127\.0\.0\.1|::1/u);
  });

  it('refuses to trust every hop, and refuses to guess in production', () => {
    expect(() => trustedHopsFromEnv({ TRUST_PROXY: 'true' })).toThrow(AuthConfigError);
    expect(() => trustedHopsFromEnv({ NODE_ENV: 'production' })).toThrow(AuthConfigError);
  });
});
