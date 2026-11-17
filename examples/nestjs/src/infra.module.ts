// The app's connections and its mailer, as providers, so the tests can swap
// the mailer and the auth module can inject all of them.
import {
  Global,
  Inject,
  Module,
  type DynamicModule,
  type OnApplicationShutdown,
} from '@nestjs/common';
import type { Mailer } from '@noctcore/auth';
import { Redis } from 'ioredis';
import { CONFIG, type AppConfig } from './config';
import { createPrisma } from './db';
import type { PrismaClient } from './generated/prisma/client';

export const PRISMA = Symbol('prisma');
export const REDIS = Symbol('redis');
export const MAILER = Symbol('mailer');

/** Mail goes to stdout: this is a demo, not a mail setup. */
const stdoutMailer: Mailer = {
  send(event) {
    process.stdout.write(`[mail] ${event.type} to ${event.to}\n`);

    return Promise.resolve();
  },
};

@Global()
@Module({})
export class InfraModule implements OnApplicationShutdown {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClient,
    @Inject(REDIS) private readonly redis: Redis,
  ) {}

  static withConfig(config: AppConfig): DynamicModule {
    return {
      module: InfraModule,
      providers: [
        { provide: CONFIG, useValue: config },
        {
          provide: PRISMA,
          useFactory: (c: AppConfig) => createPrisma(c.databaseUrl),
          inject: [CONFIG],
        },
        {
          provide: REDIS,
          // Lazy: nothing connects until the first command, so the app can be
          // compiled and its routes listed without a running Redis.
          useFactory: (c: AppConfig) => new Redis(c.redisUrl, { lazyConnect: true }),
          inject: [CONFIG],
        },
        { provide: MAILER, useValue: stdoutMailer },
      ],
      exports: [CONFIG, PRISMA, REDIS, MAILER],
    };
  }

  async onApplicationShutdown(): Promise<void> {
    await this.prisma.$disconnect();
    this.redis.disconnect();
  }
}
