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

  // Each session is named by its public handle, never its store key.
  @Get('sessions')
  async sessions(@CurrentSession() session: Session) {
    return { sessions: await this.auth.sessions.list(session) };
  }

  // Signs out one device by the handle the list showed. Another device needs a
  // fresh password proof by default; a handle that names none of the caller's
  // sessions answers { revoked: false }.
  @Post('sessions/revoke')
  async revokeSession(
    @Body() body: { handle: string },
    @CurrentSession() session: Session,
    @AuthMeta() meta: RequestMeta,
  ) {
    const result = await this.auth.sessions.revoke({ session, handle: body.handle, meta });

    if (!result.ok) throw new HttpException({ error: toPublicError(result) }, 403);

    // result.value.sessionId is the store key: keep it on the server.
    return { revoked: result.value.revoked };
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
