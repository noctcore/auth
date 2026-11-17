import type { AppAuth } from '../node-server/auth.ts';
import { createAuthContext } from '@noctcore/auth-trpc';
import { fetchRequestHandler } from '@trpc/server/adapters/fetch';
import { createAppRouter } from './router.ts';

// On the fetch adapter (Bun, Deno, edge runtimes) a Request carries no peer
// address, so hand it over from your server. Without it, and with no trusted
// hops, every client shares one rate-limit bucket.
export function createFetchHandler(auth: AppAuth, settings: { csrfSecret: string; origin: string }) {
  const authContext = createAuthContext({
    auth,
    trustedHops: 0,
    csrf: { secrets: [settings.csrfSecret], allowedOrigins: [settings.origin] },
  });

  const router = createAppRouter(auth);

  return (req: Request, remoteAddress: string | undefined) =>
    fetchRequestHandler({
      endpoint: '/trpc',
      req,
      router,
      createContext: (opts) =>
        authContext.fetch(opts, remoteAddress === undefined ? {} : { remoteAddress }),
    });
}
