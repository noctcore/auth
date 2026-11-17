// The routes. Every one needs a session unless it says @Public().
import { Body, Controller, Get, Inject, Post, Req, Res } from '@nestjs/common';
import type { RequestMeta, StoredSession } from '@noctcore/auth';
import {
  AUTH,
  AuthMeta,
  CurrentSession,
  CurrentUser,
  Public,
  RequireFreshAuth,
  RequireRole,
  SessionCookies,
} from '@noctcore/auth-nestjs';
import type { AppAuth, AppUser } from './auth';
import { refusal } from './errors';

type Credentials = { email?: unknown; password?: unknown };
type Session = StoredSession<Record<string, never>>;

const str = (value: unknown): string => (typeof value === 'string' ? value : '');

@Controller('health')
export class HealthController {
  @Public()
  @Get()
  check() {
    return { ok: true };
  }
}

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AUTH) private readonly auth: AppAuth,
    @Inject(SessionCookies) private readonly cookies: SessionCookies,
  ) {}

  /** The page's first call: who is signed in, and (through the middleware) a CSRF cookie. */
  @Public()
  @Get('session')
  session(@CurrentUser() user: AppUser | null) {
    return { user: user ? { id: user.id, email: user.email } : null };
  }

  @Public()
  @Post('register')
  async register(@Body() body: Credentials, @AuthMeta() meta: RequestMeta) {
    const result = await this.auth.register({
      email: str(body.email),
      password: str(body.password),
      meta,
    });

    if (!result.ok) throw refusal(result);

    return { status: 'check-your-email' };
  }

  @Public()
  @Post('login')
  async login(
    @Body() body: Credentials & { rememberMe?: unknown },
    @AuthMeta() meta: RequestMeta,
    @Req() req: { headers: { cookie?: string } },
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.login({
      email: str(body.email),
      password: str(body.password),
      rememberMe: body.rememberMe === true,
      deviceToken: this.auth.readDeviceToken(req.headers.cookie),
      meta,
    });

    if (!result.ok) throw refusal(result);

    if (result.value.kind === 'challenge')
      return { challenge: result.value.challenge, methods: result.value.methods };

    return this.cookies.set(res, result.value.session);
  }

  /** Public, so a browser with an expired session can still clear its cookies. */
  @Public()
  @Post('logout')
  logout(@Req() req: unknown, @Res({ passthrough: true }) res: unknown) {
    return this.cookies.signOut(req, res);
  }
}

@Controller('account')
export class AccountController {
  constructor(
    @Inject(AUTH) private readonly auth: AppAuth,
    @Inject(SessionCookies) private readonly cookies: SessionCookies,
  ) {}

  @Get('me')
  me(@CurrentUser() user: AppUser) {
    return { user: { id: user.id, email: user.email, emailVerified: user.emailVerified } };
  }

  @Get('sessions')
  async sessions(@CurrentSession() session: Session) {
    return { sessions: await this.auth.sessions.list(session) };
  }

  /** Proves the password again: a new session (rotation) with a fresh credential proof. */
  @Post('reauthenticate')
  async reauthenticate(
    @Body() body: { password?: unknown },
    @CurrentSession() session: Session,
    @AuthMeta() meta: RequestMeta,
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.reauthenticate({ session, password: str(body.password), meta });

    if (!result.ok) throw refusal(result);

    return this.cookies.set(res, result.value);
  }

  @RequireFreshAuth()
  @Post('password')
  async changePassword(
    @Body() body: { currentPassword?: unknown; newPassword?: unknown },
    @CurrentSession() session: Session,
    @AuthMeta() meta: RequestMeta,
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.changePassword({
      session,
      currentPassword: str(body.currentPassword),
      newPassword: str(body.newPassword),
      meta,
    });

    if (!result.ok) throw refusal(result);

    return this.cookies.set(res, result.value);
  }
}

@RequireRole('admin')
@Controller('admin')
export class AdminController {
  @Get()
  dashboard(@CurrentUser() user: AppUser) {
    return { admin: user.id };
  }
}
