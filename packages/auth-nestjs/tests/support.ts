// A real Nest app on Express with the module wired the way the docs say, over
// the core's in-memory stores, and a browser-like client that keeps cookies
// and sends Origin, Sec-Fetch-Site and the CSRF header like a page would.
import 'reflect-metadata';
import {
  Body,
  Controller,
  Get,
  HttpException,
  Inject,
  Post,
  Req,
  Res,
  type INestApplication,
  type Type,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  createAuth,
  toPublicError,
  type AuthUser,
  type RequestMeta,
  type StoredSession,
} from '@noctcore/auth';
import { manualClock, memoryStores, plainHasher, recordingMailer } from '@noctcore/auth/testing';
import request from 'supertest';
import {
  AUTH,
  AuthMeta,
  AuthModule,
  CurrentSession,
  CurrentUser,
  Public,
  RequireFreshAuth,
  RequireRole,
  SessionCookies,
  type AuthModuleOptions,
} from '../src';

export const ORIGIN = 'http://app.test';
export const EMAIL = 'ada@example.com';
export const PASSWORD = 'correct horse battery staple';
export const CSRF_SECRET = 'csrf-secret-that-is-at-least-32-bytes-long';

export function makeAuth() {
  const clock = manualClock();
  const stores = memoryStores(clock);
  const mailer = recordingMailer();

  const auth = createAuth({
    stores,
    clock,
    password: { hasher: plainHasher(), breachCheck: false },
    session: { cookie: { secure: false } },
    secret: 'auth-secret-that-is-at-least-32-bytes-long',
    urls: { resetPassword: (token) => `${ORIGIN}/reset#${token}` },
    mailer,
  });

  return { auth, clock, stores, mailer };
}

export type TestAuth = ReturnType<typeof makeAuth>['auth'];

function failure(result: Parameters<typeof toPublicError>[0], status = 401): never {
  throw new HttpException({ error: toPublicError(result) }, status);
}

@Controller('api')
export class AccountController {
  constructor(
    @Inject(AUTH) private readonly auth: TestAuth,
    @Inject(SessionCookies) private readonly cookies: SessionCookies,
  ) {}

  @Public()
  @Get('health')
  health() {
    return { ok: true };
  }

  @Public()
  @Get('whoami')
  whoami(@CurrentUser() user: AuthUser | null) {
    return { user: user?.id ?? null };
  }

  @Public()
  @Post('login')
  async login(
    @Body() body: { email?: string; password?: string },
    @AuthMeta() meta: RequestMeta,
    @Req() req: { headers: { cookie?: string } },
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.login({
      email: body.email ?? '',
      password: body.password ?? '',
      deviceToken: this.auth.readDeviceToken(req.headers.cookie),
      meta,
    });

    if (!result.ok) failure(result);
    if (result.value.kind !== 'session') throw new HttpException('challenge', 400);

    return this.cookies.set(res, result.value.session);
  }

  @Get('me')
  me(@CurrentUser() user: AuthUser, @CurrentSession() session: StoredSession) {
    return { user: user.id, email: user.email, session: session.userId === user.id };
  }

  @Get('meta')
  meta(@AuthMeta() meta: RequestMeta) {
    return meta;
  }

  @Post('echo')
  echo(@Body() body: unknown) {
    return { body };
  }

  @Post('reauthenticate')
  async reauthenticate(
    @Body() body: { password?: string },
    @CurrentSession() session: StoredSession<Record<string, never>>,
    @AuthMeta() meta: RequestMeta,
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.reauthenticate({
      session,
      password: body.password ?? '',
      meta,
    });

    if (!result.ok) failure(result);

    return this.cookies.set(res, result.value);
  }

  @RequireFreshAuth()
  @Post('sensitive')
  sensitive() {
    return { done: true };
  }

  @RequireFreshAuth('1m')
  @Post('very-sensitive')
  verySensitive() {
    return { done: true };
  }

  @RequireRole('admin')
  @Get('admin')
  admin() {
    return { admin: true };
  }

  @Public()
  @Post('logout')
  logout(@Req() req: unknown, @Res({ passthrough: true }) res: unknown) {
    return this.cookies.signOut(req, res);
  }
}

@RequireRole('staff', 'admin')
@Controller(['staff', 'team'])
export class StaffController {
  /** Not a route: describeRoutes must skip it without running it. */
  get label(): string {
    throw new Error('describeRoutes ran a getter');
  }

  /** Not a route either. */
  helper(): string {
    return 'helper';
  }

  @Get()
  list() {
    return { staff: true };
  }

  @RequireRole('admin')
  @Get('payroll')
  payroll() {
    return { payroll: true };
  }
}

@Public()
@Controller('open')
export class OpenController {
  @Get()
  index() {
    return { open: true };
  }

  @Post('webhook')
  webhook() {
    return { received: true };
  }
}

/** A controller with nothing on it: the closed default must hold for it. */
@Controller('forgot')
export class ForgottenController {
  @Get()
  index() {
    return { secret: 'nobody marked this route' };
  }

  @Post()
  write() {
    return { secret: 'nobody marked this route' };
  }
}

export interface BootOptions {
  readonly roles?: Map<string, readonly string[]>;
  readonly options?: Partial<AuthModuleOptions>;
  readonly async?: boolean;
  /** Leave out the `roles` option. */
  readonly withoutRoles?: boolean;
  /** Controllers in place of the default set. */
  readonly controllers?: readonly Type[];
  /** `app.setGlobalPrefix(prefix, { exclude })` before init. */
  readonly globalPrefix?: { readonly prefix: string; readonly exclude: string[] };
}

/** Under a global prefix: a handler at the prefix root, and a route excluded from the prefix. */
@Public()
@Controller()
export class PrefixRootController {
  @Get()
  index() {
    return { root: true };
  }

  @Post()
  write() {
    return { written: true };
  }

  @Get('inside')
  page() {
    return { page: true };
  }

  @Post('inside')
  inside() {
    return { written: true };
  }
}

@Public()
@Controller('health')
export class ExcludedController {
  @Post()
  ping() {
    return { pong: true };
  }
}

export async function boot(overrides: BootOptions = {}) {
  const env = makeAuth();
  const roles = overrides.roles ?? new Map<string, readonly string[]>();

  const base: AuthModuleOptions = {
    auth: env.auth,
    trustedHops: 1,
    csrf: { secrets: [CSRF_SECRET], allowedOrigins: [ORIGIN], exempt: ['/open/webhook'] },
    ...(overrides.withoutRoles ? {} : { roles: (user) => roles.get(user.id) ?? [] }),
  };

  const options: AuthModuleOptions = { ...base, ...overrides.options };

  const moduleRef = await Test.createTestingModule({
    imports: [
      overrides.async
        ? AuthModule.forRootAsync({ useFactory: async () => options })
        : AuthModule.forRoot(options),
    ],
    controllers: [
      ...(overrides.controllers ?? [
        AccountController,
        StaffController,
        OpenController,
        ForgottenController,
      ]),
    ],
  }).compile();

  const app = moduleRef.createNestApplication({ logger: false });

  if (overrides.globalPrefix) {
    app.setGlobalPrefix(overrides.globalPrefix.prefix, {
      exclude: overrides.globalPrefix.exclude,
    });
  }

  await app.init();

  const registered = await env.auth.register({
    email: EMAIL,
    password: PASSWORD,
    meta: { ip: '203.0.113.1' },
  });

  if (!registered.ok) throw new Error('could not register the test user');

  const user = await env.stores.users.findCredentialByEmail(EMAIL as never);

  return { ...env, app, roles, userId: user?.id ?? '' };
}

export type Booted = Awaited<ReturnType<typeof boot>>;

interface Answer {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly setCookies: readonly string[];
}

/** Keeps cookies, and sends what a same-origin page sends, unless told otherwise. */
export class Browser {
  readonly cookies = new Map<string, string>();

  constructor(
    private readonly app: INestApplication,
    private readonly ip = '198.51.100.7',
  ) {}

  get csrf(): string {
    return this.cookies.get('csrf') ?? '';
  }

  async send(
    method: 'GET' | 'POST',
    path: string,
    body?: object,
    override: Record<string, string | null> = {},
  ): Promise<Answer> {
    const headers: Record<string, string> = {
      origin: ORIGIN,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': this.csrf,
      'x-forwarded-for': this.ip,
      cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '),
    };

    for (const [key, value] of Object.entries(override)) {
      if (value === null) Reflect.deleteProperty(headers, key);
      else headers[key] = value;
    }

    const server = request(this.app.getHttpServer() as Parameters<typeof request>[0]);
    const pending = method === 'GET' ? server.get(path) : server.post(path);

    for (const [key, value] of Object.entries(headers)) void pending.set(key, value);

    const response = body === undefined ? await pending : await pending.send(body);
    const raw = response.headers['set-cookie'] as string[] | string | undefined;
    const setCookies = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];

    for (const line of setCookies) {
      const [pair = '', ...attributes] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const value = decodeURIComponent(pair.slice(eq + 1));

      if (attributes.some((a) => a.trim().toLowerCase() === 'max-age=0')) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }

    return { status: response.status, body: response.body as Record<string, unknown>, setCookies };
  }

  /** Visits a page (which hands out the CSRF cookie) and signs in. */
  async signIn(email = EMAIL, password = PASSWORD): Promise<Answer> {
    await this.send('GET', '/api/health');

    return this.send('POST', '/api/login', { email, password });
  }
}
