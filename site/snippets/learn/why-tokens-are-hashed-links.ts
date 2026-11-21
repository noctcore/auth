import type { ServerResponse } from 'node:http';
import type { AuthConfig, AuthUser } from '@noctcore/auth';

const origin = 'https://app.example';

// Hashing at rest does not protect a token in use. Put link tokens in the
// fragment, which a browser never sends to a server, so they stay out of
// access logs and Referer headers.
export const urls = {
  resetPassword: (token: string) => `${origin}/reset-password#${token}`,
  verifyEmail: (token: string) => `${origin}/verify#${token}`,
} satisfies AuthConfig<AuthUser, unknown, []>['urls'];

// The page the link opens reads the fragment and POSTs the token on a click.
export function sendLinkPage(res: ServerResponse, html: string): void {
  res.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'referrer-policy': 'no-referrer',
  });
  res.end(html);
}
