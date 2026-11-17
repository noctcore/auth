import type { AppRouter } from './router.ts';
import { createTRPCClient, httpBatchStreamLink, httpLink, splitLink } from '@trpc/client';

// The page reads the CSRF cookie and echoes it on every request; mutations
// are refused without it.
export function createClient(url: string, readCsrfCookie: () => string) {
  const headers = () => ({ 'x-csrf-token': readCsrfCookie() });

  return createTRPCClient<AppRouter>({
    links: [
      splitLink({
        // A streamed batch sends its headers before any procedure runs, so a
        // procedure that sets a cookie cannot go through it. Mutations go one
        // per request: two sign-ins in one batch would both run.
        condition: (op) => op.type === 'mutation',
        true: httpLink({ url, headers }),
        false: httpBatchStreamLink({ url, headers }),
      }),
    ],
  });
}
