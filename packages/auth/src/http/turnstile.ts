/**
 * The Cloudflare Turnstile verifier. Besides the token, it checks the
 * `hostname` the token was solved on and the `action` it was solved for, so a
 * token from another site sharing the sitekey, or from another form, is
 * refused. A provider outage or timeout is `unavailable`, never `pass`.
 */
import type { CaptchaVerifier } from '../ports/captcha';

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
