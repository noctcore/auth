---
'@noctcore/auth-nestjs': minor
---

`describeRoutes` and the startup contradiction check now include the handlers a controller inherits from a base class or a mixin. They used to read only the controller's own prototype, so an inherited route (public ones included) was missing from the route list, and an inherited handler marked both `@Public()` and `@RequireRole()` (or `@RequireFreshAuth()`) was never checked. The chain is walked the way Nest's `MetadataScanner` finds routes: each method name is taken once at the nearest level, so an override in the subclass replaces the base handler, and an override without a route decorator is no route. The guard already failed closed at request time, so no route was open.

Behaviour change: an app whose controller inherits a handler that is `@Public()` and also requires a role or fresh auth (on the handler, or through a `@Public()` on the subclass) no longer starts, and `AuthModule` throws `AuthConfigError` naming the route. So does an inherited `@RequireRole()` without the `roles` option. Remove one of the contradicting decorators.
