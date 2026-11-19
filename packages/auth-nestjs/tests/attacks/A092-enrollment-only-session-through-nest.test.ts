// A092: using an enrollment-only session for more than enrollment, on Nest.
//
// Under the two-factor plugin's `enforcement`, a user who must set up a
// factor and is past the grace window still signs in, so the session can
// reach enrollment. If the guard does not read the session's standing, that
// session reaches every route, and the requirement means nothing.
//
// Stopped by: auth-nestjs src/session.guard.ts (an `enrollment-only` session
//   reaches only a route, or a controller, marked `@TwoFactorEnrollment()`;
//   anything else answers 403 `two_factor_enrollment_required`, read from the
//   standing validation computes on this request) and src/decorators.ts (the
//   marker opens nothing else: roles and fresh-auth still apply).
// Learn: Build, "Two-factor" (/auth/build/two-factor/)
import { Controller, Get, Post } from '@nestjs/common';
import type { SessionStanding, ValidatedSession } from '@noctcore/auth';
import { afterEach, describe, expect, it } from 'vitest';
import { CurrentSession, RequireFreshAuth, RequireRole, TwoFactorEnrollment } from '../../src';
import { AccountController, boot, Browser, type Booted } from '../support';

const MINUTE = 60 * 1000;

@TwoFactorEnrollment()
@Controller('mfa')
class EnrollmentController {
  @Get('status')
  status(@CurrentSession() session: ValidatedSession<unknown>) {
    return { standing: session.twoFactor ?? null };
  }

  @RequireRole('admin')
  @Get('admin')
  admin() {
    return { admin: true };
  }
}

@Controller('setup')
class SetupController {
  @TwoFactorEnrollment()
  @RequireFreshAuth()
  @Post('enroll')
  enroll() {
    return { enrolling: true };
  }

  @Get('other')
  other() {
    return { other: true };
  }
}

let t: Booted;

afterEach(async () => {
  await t.app.close();
});

async function signedIn(standing: { current: SessionStanding | undefined }) {
  t = await boot({
    controllers: [AccountController, EnrollmentController, SetupController],
    hooks: { sessionStanding: () => standing.current },
  });

  const browser = new Browser(t.app);

  await browser.signIn();

  return browser;
}

describe('A092: an enrollment-only session through Nest', () => {
  it('refuses every route not marked for enrollment', async () => {
    const browser = await signedIn({ current: { twoFactor: { state: 'enrollment-only' } } });

    for (const [method, path] of [
      ['GET', '/api/me'],
      ['GET', '/api/sessions'],
      ['POST', '/api/echo'],
      ['GET', '/setup/other'],
    ] as const) {
      expect(await browser.send(method, path, method === 'POST' ? {} : undefined)).toMatchObject({
        status: 403,
        body: { error: { code: 'two_factor_enrollment_required' } },
      });
    }
  });

  it('lets it reach the marked routes, which keep their own requirements', async () => {
    const browser = await signedIn({ current: { twoFactor: { state: 'enrollment-only' } } });

    expect(await browser.send('GET', '/mfa/status')).toMatchObject({
      status: 200,
      body: { standing: { state: 'enrollment-only' } },
    });

    expect((await browser.send('POST', '/setup/enroll', {})).status).toBe(201);
    expect((await browser.send('GET', '/mfa/admin')).status).toBe(403);

    t.clock.advance(11 * MINUTE);

    expect(await browser.send('POST', '/setup/enroll', {})).toMatchObject({
      status: 403,
      body: { error: { code: 'fresh_auth_required' } },
    });
  });

  it('reads the standing on every request, so a change applies without a new sign-in', async () => {
    const standing: { current: SessionStanding | undefined } = {
      current: { twoFactor: { state: 'grace', graceEndsAt: Date.now() + MINUTE } },
    };

    const browser = await signedIn(standing);

    expect((await browser.send('GET', '/api/me')).status).toBe(200);

    standing.current = { twoFactor: { state: 'enrollment-only' } };
    expect((await browser.send('GET', '/api/me')).status).toBe(403);

    standing.current = undefined;
    expect((await browser.send('GET', '/api/me')).status).toBe(200);
  });
});
