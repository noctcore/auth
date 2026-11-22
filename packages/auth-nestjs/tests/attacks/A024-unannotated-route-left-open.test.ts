// A024: a route left open because nobody marked it.
//
// A new controller ships without a guard (or with the guard on some routes
// and not others), and anyone can call it. Or a guard trusts a user id the
// client put in a header or the body.
//
// Stopped by: auth-nestjs src/session.guard.ts: SessionGuard is registered
//   globally by AuthModule with no switch to turn it off, and refuses every
//   route without @Public(); the user comes from the stored session only.
//   src/routes.ts: describeRoutes lists every route with its rule for a test.
// Learn: Build, "Use with NestJS" (/auth/build/nestjs/)
import { afterEach, describe, expect, it } from 'vitest';
import { Controller, Get, type Type } from '@nestjs/common';
import { AuthConfigError } from '@noctcore/auth';
import { describeRoutes, Public, RequireFreshAuth, RequireRole } from '../../src';
import { AccountController, boot, Browser, type Booted } from '../support';

let t: Booted;

describe('A024: a route left open because nobody marked it', () => {
  afterEach(async () => {
    await t.app.close();
  });

  it('refuses every route without @Public() when there is no session, found by walking them all', async () => {
    t = await boot();
    const routes = describeRoutes(t.app);

    expect(routes.length).toBeGreaterThan(10);

    for (const route of routes) {
      const browser = new Browser(t.app);

      // A page visit first, so unsafe requests carry a valid CSRF token and
      // the guard, not the CSRF layer, is what answers.
      await browser.send('GET', '/api/health');
      const method = route.method === 'GET' ? 'GET' : 'POST';
      const answer = await browser.send(method, route.path, method === 'GET' ? undefined : {});
      const label = `${route.method} ${route.path}`;
      const code = (answer.body['error'] as { code?: string } | undefined)?.code;

      // A public route may refuse for its own reasons (a wrong password); only
      // the guard answers 401 with `session_expired`.
      expect(answer.status === 401 && code === 'session_expired', label).toBe(!route.public);
    }
  });

  it('lists the rule of each route: open, roles, fresh auth', async () => {
    t = await boot();
    const routes = describeRoutes(t.app);

    const find = (path: string, method = 'GET') =>
      routes.find((route) => route.path === path && route.method === method);

    expect(find('/forgot')).toMatchObject({ public: false, controller: 'ForgottenController' });
    expect(find('/open')).toMatchObject({ public: true });
    expect(find('/api/health')).toMatchObject({ public: true, handler: 'health' });
    expect(find('/staff/payroll')?.roles).toEqual([['admin'], ['staff', 'admin']]);
    expect(find('/api/sensitive', 'POST')).toMatchObject({ freshAuth: true, public: false });
  });

  it('never takes the user from a header or the body', async () => {
    t = await boot();
    const browser = new Browser(t.app);

    await browser.send('GET', '/api/health');

    const forged = await browser.send(
      'POST',
      '/api/echo',
      { userId: t.userId, user: { id: t.userId } },
      { 'x-user-id': t.userId, authorization: `Bearer ${t.userId}` },
    );

    expect(forged.status).toBe(401);

    expect(
      (await browser.send('GET', '/api/whoami', undefined, { 'x-user-id': t.userId })).body,
    ).toEqual({
      user: null,
    });
  });
});

// A public controller whose handler asks for a role: the guard used to take
// the @Public() and skip the role check, handing admin data to anyone.
@Public()
@Controller('reports')
class PublicReportsWithAdminHandler {
  @RequireRole('admin')
  @Get('payroll')
  payroll() {
    return { salaries: 'everyone' };
  }
}

@Public()
@Controller('danger')
class PublicDangerWithFreshHandler {
  @RequireFreshAuth()
  @Get()
  zone() {
    return { done: true };
  }
}

describe('A024: a route both open and restricted, refused at boot', () => {
  it('refuses to boot when @Public() on a controller meets @RequireRole() on a handler', async () => {
    await expect(boot({ controllers: [PublicReportsWithAdminHandler] })).rejects.toThrow(
      /PublicReportsWithAdminHandler\.payroll \(GET \/reports\/payroll\) is @Public\(\)/u,
    );
  });

  it('refuses to boot when @Public() meets @RequireFreshAuth()', async () => {
    await expect(boot({ controllers: [PublicDangerWithFreshHandler] })).rejects.toThrow(
      AuthConfigError,
    );
  });

  it('refuses to boot with @RequireRole() and no roles option, instead of failing at request time', async () => {
    await expect(boot({ withoutRoles: true, controllers: [AccountController] })).rejects.toThrow(
      /uses @RequireRole\(\) but AuthModule has no `roles` option/u,
    );
  });
});

// Handlers a controller inherits from a base class or a mixin. Nest routes
// them (its MetadataScanner walks the prototype chain), so the route list and
// the boot check have to see them too, or an app's audit of open routes
// silently misses every inherited one.
class BaseHandlers {
  @Public()
  @Get('open')
  open() {
    return { open: true };
  }

  @Get('closed')
  closed() {
    return { closed: true };
  }

  @Public()
  @Get('was-open')
  replaced() {
    return { open: true };
  }

  @Get('undecorated-later')
  dropped() {
    return { dropped: false };
  }
}

@Controller('child')
class ChildController extends BaseHandlers {
  // The subclass wins: same name, new route and no @Public().
  @Get('now-closed')
  override replaced() {
    return { open: false };
  }

  // An override without a route decorator is no route in Nest.
  override dropped() {
    return { dropped: true };
  }
}

class MiddleHandlers extends BaseHandlers {
  @Get('middle')
  middle() {
    return { middle: true };
  }
}

@Controller('grand')
class GrandchildController extends MiddleHandlers {}

function WithStatus<T extends Type>(Base: T) {
  class Status extends Base {
    @Public()
    @Get('status')
    status() {
      return { up: true };
    }
  }

  return Status;
}

@Controller('mixed')
class MixedController extends WithStatus(class {}) {}

class OpenAndRestrictedBase {
  @Public()
  @RequireRole('admin')
  @Get('payroll')
  payroll() {
    return { salaries: 'everyone' };
  }
}

@Controller('inherited-reports')
class InheritedContradictionController extends OpenAndRestrictedBase {}

class RestrictedBase {
  @RequireRole('admin')
  @Get('payroll')
  payroll() {
    return { salaries: 'admins' };
  }
}

// Class-level metadata is read from the subclass, so a @Public() on it meets
// the role an inherited handler asks for.
@Public()
@Controller('public-child')
class PublicChildOfRestrictedBase extends RestrictedBase {}

describe('A024: inherited handlers are listed and checked like own ones', () => {
  afterEach(async () => {
    await t.app.close();
  });

  it('lists inherited routes once, with the override winning, and Nest serves the same set', async () => {
    t = await boot({ controllers: [ChildController, GrandchildController, MixedController] });
    const routes = describeRoutes(t.app);
    const listed = routes.map((route) => `${route.method} ${route.path}`);

    expect(listed).toEqual(expect.arrayContaining(['GET /child/open', 'GET /child/closed']));
    expect(new Set(listed).size).toBe(listed.length);
    expect(listed).not.toContain('GET /child/was-open');
    expect(listed).not.toContain('GET /child/undecorated-later');

    const find = (path: string) => routes.find((route) => route.path === path);

    expect(find('/child/open')).toMatchObject({
      controller: 'ChildController',
      handler: 'open',
      public: true,
    });

    expect(find('/child/now-closed')).toMatchObject({ handler: 'replaced', public: false });
    expect(find('/grand/open')).toMatchObject({ controller: 'GrandchildController', public: true });
    expect(find('/grand/middle')).toMatchObject({ public: false });
    expect(find('/grand/was-open')).toMatchObject({ public: true });
    expect(find('/mixed/status')).toMatchObject({ controller: 'MixedController', public: true });
    expect(routes.filter((route) => route.controller === 'ChildController')).toHaveLength(3);
    expect(routes.filter((route) => route.controller === 'GrandchildController')).toHaveLength(5);

    const browser = new Browser(t.app);

    for (const route of routes) {
      const answer = await browser.send('GET', route.path);

      expect(answer.status, route.path).toBe(route.public ? 200 : 401);
    }

    expect((await browser.send('GET', '/child/was-open')).status).toBe(404);
    expect((await browser.send('GET', '/child/undecorated-later')).status).toBe(404);
  });
});

describe('A024: an inherited handler both open and restricted, refused at boot', () => {
  it('refuses to boot on an inherited handler that is @Public() and asks for a role', async () => {
    await expect(boot({ controllers: [InheritedContradictionController] })).rejects.toThrow(
      /InheritedContradictionController\.payroll \(GET \/inherited-reports\/payroll\) is @Public\(\)/u,
    );
  });

  it('refuses to boot when a public subclass inherits a handler that asks for a role', async () => {
    await expect(boot({ controllers: [PublicChildOfRestrictedBase] })).rejects.toThrow(
      /PublicChildOfRestrictedBase\.payroll \(GET \/public-child\/payroll\) is @Public\(\)/u,
    );
  });
});
