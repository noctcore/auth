import { createAuthContext } from '@noctcore/auth-trpc';
import { createHTTPServer } from '@trpc/server/adapters/standalone';
import { buildAuth } from '../node-server/auth.ts';
import { config } from '../node-server/config.ts';
import { createAppRouter } from './router.ts';

const auth = buildAuth({
  async send(event) {
    process.stdout.write(`[mail] ${event.type} to ${event.to}\n`);
  },
});

// Checked once, here: a short CSRF secret, an empty origin list or a bad hop
// count stops the server before it listens.
const authContext = createAuthContext({
  auth,
  trustedHops: config.trustedHops,
  csrf: {
    // Not the auth secret. Add the previous one after it during a rollover.
    secrets: [config.csrfSecret],
    allowedOrigins: [config.origin],
  },
  // How long an open subscription may go on before its session is checked
  // again (the default; a number means seconds, 0 checks every event).
  revalidateSubscriptions: '30s',
});

createHTTPServer({
  router: createAppRouter(auth),
  basePath: '/trpc/',
  createContext: (opts) => authContext.node(opts),
}).listen(3000);
