import type { IncomingMessage } from 'node:http';
import { clientIp } from '@noctcore/auth';
import { config } from '../build/node-server/config';

/**
 * The IP every per-IP limit and audit row uses. Never the raw header, and
 * never a framework's own guess: the hop count or proxy list decides.
 */
export function requestIp(req: IncomingMessage): string {
  return (
    clientIp({
      remoteAddress: req.socket.remoteAddress,
      forwardedFor: req.headers['x-forwarded-for'],
      // From TRUST_PROXY: a hop count, or proxy addresses and ranges.
      trustedHops: config.trustedHops,
    }) ?? 'unknown'
  );
}
