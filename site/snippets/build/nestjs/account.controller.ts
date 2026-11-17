import { Body, Controller, Get, HttpException, Inject, Post, Res } from '@nestjs/common';
import { toPublicError, type AuthUser, type RequestMeta, type StoredSession } from '@noctcore/auth';
import {
  AUTH,
  AuthMeta,
  CurrentSession,
  CurrentUser,
  RequireFreshAuth,
  RequireRole,
  SessionCookies,
} from '@noctcore/auth-nestjs';
import type { AppAuth } from '../node-server/auth';

type Session = StoredSession<Record<string, never>>;

// No @Public(): every route here needs a session.
@Controller('account')
export class AccountController {
  constructor(
    @Inject(AUTH) private readonly auth: AppAuth,
    @Inject(SessionCookies) private readonly cookies: SessionCookies,
  ) {}

  @Get('me')
  me(@CurrentUser() user: AuthUser) {
    return { id: user.id, email: user.email };
  }

  // Proving the password again rotates the session.
  @Post('reauthenticate')
  async reauthenticate(
    @Body() body: { password: string },
    @CurrentSession() session: Session,
    @AuthMeta() meta: RequestMeta,
    @Res({ passthrough: true }) res: unknown,
  ) {
    const result = await this.auth.reauthenticate({ session, password: body.password, meta });

    if (!result.ok) throw new HttpException({ error: toPublicError(result) }, 401);

    return this.cookies.set(res, result.value);
  }

  // A recent password proof, and at most 5 minutes old here.
  @RequireFreshAuth('5m')
  @Post('delete')
  async remove(@CurrentUser() user: AuthUser) {
    return { scheduled: user.id };
  }

  @RequireRole('admin')
  @Get('audit')
  audit() {
    return { rows: [] };
  }
}
