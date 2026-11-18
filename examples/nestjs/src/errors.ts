// Flows return AuthResult values; only toPublicError goes over the wire,
// because the internal reason can tell a wrong password from an unknown account.
import { HttpException } from '@nestjs/common';
import { toPublicError, type AuthFailure } from '@noctcore/auth';

const STATUS: Record<string, number> = {
  invalid_credentials: 401,
  session_expired: 401,
  rate_limited: 429,
  account_locked: 423,
  fresh_auth_required: 403,
  forbidden: 403,
  captcha_unavailable: 503,
};

export function refusal(result: AuthFailure): HttpException {
  const error = toPublicError(result);

  return new HttpException({ error }, STATUS[error.code] ?? 400);
}
