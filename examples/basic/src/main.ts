// Runs the example against docker-compose.yml's Redis and PostgreSQL.
// Mail goes to stdout: this is a demo, not a mail setup.
import { Redis } from 'ioredis';
import { createApp } from './app';
import { createPrisma } from './db';

const secret = process.env.AUTH_SECRET;
const csrfSecret = process.env.CSRF_SECRET;
if (!secret || !csrfSecret) throw new Error('Set AUTH_SECRET and CSRF_SECRET (two different values, 32 bytes or more each)');
const prisma = createPrisma(process.env.DATABASE_URL ?? 'postgresql://auth:auth@localhost:5440/auth');
const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6390');
const port = Number(process.env.PORT ?? 3000);

const { server } = createApp({
  prisma,
  redis,
  secret,
  csrfSecret,
  origin: process.env.APP_ORIGIN ?? `http://localhost:${port}`,
  secureCookies: process.env.NODE_ENV === 'production',
  mailer: {
    async send(event) {
      process.stdout.write(`[mail] ${event.type} to ${event.to}\n`);
    },
  },
});
server.listen(port, () => process.stdout.write(`listening on http://localhost:${port}\n`));
