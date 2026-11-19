/**
 * Every controller route with the access rule the guard will apply, so an
 * app's own test can walk them and fail on a route nobody meant to open (or
 * meant to open and forgot to mark). Closed by default makes a forgotten
 * `@Public()` a 401; this makes the list of open routes something a reviewer
 * reads in a test, not something they reconstruct from decorators.
 */
import { RequestMethod, type INestApplication } from '@nestjs/common';
import { DiscoveryService, Reflector } from '@nestjs/core';
import { FRESH_AUTH_KEY, PUBLIC_KEY, ROLES_KEY, TWO_FACTOR_ENROLLMENT_KEY } from './tokens';

// Nest's own metadata keys (@nestjs/common/constants), stable since Nest 6.
const PATH = 'path';
const METHOD = 'method';

export interface RouteAccess {
  /** `GET`, `POST`, ... or `ALL`. */
  readonly method: string;
  /** Controller path joined with the handler path, without a global prefix or version. */
  readonly path: string;
  readonly controller: string;
  readonly handler: string;
  readonly public: boolean;
  /** Each list must be satisfied (controller, then handler). */
  readonly roles: readonly (readonly string[])[];
  readonly freshAuth: boolean;
  /** Marked `@TwoFactorEnrollment()`: an enrollment-only session may reach it. */
  readonly twoFactorEnrollment: boolean;
}

/** Nest keeps a path as a string, or a list of them; the first one names the route. */
function firstPath(value: unknown): string {
  return String(Array.isArray(value) ? value[0] : value).replace(/^\/+|\/+$/gu, '');
}

function joinPath(...parts: readonly unknown[]): string {
  return `/${parts
    .map(firstPath)
    .filter((part) => part !== '')
    .join('/')}`;
}

/** Lists the routes of every controller in an initialised app (call after `app.init()`). */
export function describeRoutes(app: INestApplication): RouteAccess[] {
  return collectRoutes(app.get(DiscoveryService), app.get(Reflector));
}

export function collectRoutes(discovery: DiscoveryService, reflector: Reflector): RouteAccess[] {
  const routes: RouteAccess[] = [];

  for (const wrapper of discovery.getControllers()) {
    const controller = wrapper.metatype as new (...args: never[]) => object;
    const prototype = controller.prototype as object;

    for (const name of Object.getOwnPropertyNames(prototype)) {
      // The descriptor, not `prototype[name]`, so a getter is never run.
      const handler: unknown = Object.getOwnPropertyDescriptor(prototype, name)?.value;

      if (typeof handler !== 'function') continue;

      const method = reflector.get<RequestMethod | undefined>(METHOD, handler);

      if (method === undefined) continue;

      const targets = [handler, controller];

      const roles = targets
        .map((target) => reflector.get<readonly string[] | undefined>(ROLES_KEY, target))
        .filter((list): list is readonly string[] => list !== undefined);

      routes.push({
        method: RequestMethod[method],
        path: joinPath(
          reflector.get<unknown>(PATH, controller),
          reflector.get<unknown>(PATH, handler),
        ),
        controller: controller.name,
        handler: name,
        public: reflector.getAllAndOverride<boolean | undefined>(PUBLIC_KEY, targets) === true,
        roles,
        freshAuth: targets.some((target) => reflector.get(FRESH_AUTH_KEY, target) !== undefined),
        twoFactorEnrollment: targets.some(
          (target) => reflector.get(TWO_FACTOR_ENROLLMENT_KEY, target) === true,
        ),
      });
    }
  }

  return routes;
}
