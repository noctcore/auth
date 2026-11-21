import { toPublicError, type RequestMeta } from '@noctcore/auth';
import type { AppAuth } from '../build/node-server/auth';

interface LoginInput {
  email: string;
  password: string;
  cookieHeader: string | undefined;
  meta: RequestMeta;
}

export async function login(auth: AppAuth, input: LoginInput) {
  const result = await auth.login({
    email: input.email,
    password: input.password,
    rememberMe: false,
    // The owner's device cookie: it matters only under a lock,
    // and only for a correct password.
    deviceToken: auth.readDeviceToken(input.cookieHeader),
    meta: input.meta,
  });

  // A wrong password, a spent budget and a lock all answer
  // `invalid_credentials`. The `reason` that tells them apart
  // stays on the server.
  if (!result.ok) return { error: toPublicError(result) };

  return { signedIn: result.value };
}
