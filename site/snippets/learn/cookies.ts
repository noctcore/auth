import type { AuthConfig, AuthUser } from '@noctcore/auth';
import { createAuthContext } from '@noctcore/auth-trpc';
import { buildAuth } from '../build/node-server/auth';
import { config } from '../build/node-server/config';

const SHELL = 'app://desktop';

// The web app keeps Lax; the shell on its own scheme gets None (with Secure).
export const session = {
  cookie: {
    sameSite: (origin) => (origin === SHELL ? 'none' : 'lax'),
  },
} satisfies AuthConfig<AuthUser, unknown, []>['session'];

const auth = buildAuth({ send: async () => {} });

// None needs the rest of the CSRF defence: name the shell's exact origin.
export const authContext = createAuthContext({
  auth,
  trustedHops: config.trustedHops,
  csrf: {
    secrets: [config.csrfSecret],
    allowedOrigins: [config.origin],
    crossSiteOrigins: [SHELL],
  },
});
