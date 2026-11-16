/**
 * Captcha verification as a three-way verdict, so a provider outage is not
 * reported to the user as a failed challenge. Both `reject` and `unavailable`
 * refuse the request (fail closed); they differ only in the code the client
 * sees.
 *
 * The Turnstile verifier also checks the `hostname` the token was solved on and
 * the `action` it was solved for, so a token from another site sharing the
 * sitekey, or from another form, is refused.
 *
 * Guide: Learn, "Captcha".
 */
export type CaptchaVerdict = 'pass' | 'reject' | 'unavailable';

/** The flow asking. With `checkAction`, the widget's action must equal it. */
export type CaptchaDoor = 'login' | 'register' | 'password-reset' | 'email-verification';

export interface CaptchaVerifier {
  verify(
    token: string | undefined,
    context: { ip?: string; door: CaptchaDoor },
  ): Promise<CaptchaVerdict>;
}

export interface TurnstileOptions {
  readonly secret: string;
  /** Hostnames the widget may be served from. Strongly recommended. */
  readonly expectedHostnames?: readonly string[];
  /** Require the widget's `action` to equal the door name (`login`, `register`, ...). */
  readonly checkAction?: boolean;
  /** Default 5000 ms. */
  readonly timeoutMs?: number;
  readonly fetch?: typeof fetch;
}

const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const MAX_TOKEN_LENGTH = 2048;

export function turnstile(options: TurnstileOptions): CaptchaVerifier {
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  return {
    async verify(token, context) {
      if (!token || token.length > MAX_TOKEN_LENGTH) return 'reject';
      const form = new URLSearchParams({ secret: options.secret, response: token });
      if (context.ip) form.set('remoteip', context.ip);
      let data: unknown;
      try {
        const response = await doFetch(SITEVERIFY, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form,
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) return 'unavailable';
        data = await response.json();
      } catch {
        return 'unavailable';
      }
      if (
        typeof data !== 'object' ||
        data === null ||
        typeof (data as { success?: unknown }).success !== 'boolean'
      ) {
        return 'unavailable';
      }
      const body = data as {
        success: boolean;
        hostname?: unknown;
        action?: unknown;
        'error-codes'?: unknown;
      };
      if (!body.success) {
        const codes = Array.isArray(body['error-codes']) ? body['error-codes'] : [];
        return codes.includes('internal-error') ? 'unavailable' : 'reject';
      }
      if (options.expectedHostnames && !options.expectedHostnames.includes(String(body.hostname)))
        return 'reject';
      if (options.checkAction && body.action !== context.door) return 'reject';
      return 'pass';
    },
  };
}
