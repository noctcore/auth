import { Body, Controller, Get, HttpException, Inject, Post, Req, Res } from '@nestjs/common';
import { toPublicError, type AuthFailure, type AuthUser, type RequestMeta } from '@noctcore/auth';
import { AUTH, AuthMeta, CurrentUser, Public, SessionCookies } from '@noctcore/auth-nestjs';
import type { AppAuth } from '../node-server/auth';

// Only the public code goes over the wire; the reason is for audit rows.
function refusal(result: AuthFailure): HttpException {
  const error = toPublicError(result);

  return new HttpException({ error }, error.code === 'rate_limited' ? 429 : 401);
}

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AUTH) private readonly auth: AppAuth,
    @Inject(SessionCookies) private readonly cookies: SessionCookies,
  ) {}

  // The page's first call. Like every GET, it also hands out the CSRF cookie.
  @Public()
  @Get('session')
  session(@CurrentUser() user: AuthUser | null) {
    return { user: user && { id: user.id, email: user.email } };
  }

  @Public()
  @Post('login')
  async login(
    @Body() body: { email: string; password: string; rememberMe?: boolean },
    @AuthMeta() meta: RequestMeta,
    @Req() req: { headers: { cookie?: string } },
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.login({
      email: body.email,
      password: body.password,
      rememberMe: body.rememberMe === true,
      deviceToken: this.auth.readDeviceToken(req.headers.cookie),
      meta,
    });

    if (!result.ok) throw refusal(result);
    if (result.value.kind === 'challenge') return { methods: result.value.methods };

    // Session cookie, device cookie and a CSRF token bound to the new session.
    return this.cookies.set(res, result.value.session);
  }

  @Public()
  @Post('logout')
  logout(@Req() req: unknown, @Res({ passthrough: true }) res: unknown) {
    return this.cookies.signOut(req, res);
  }
}
