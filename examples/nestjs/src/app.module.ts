// The whole app. tests/app.test.ts boots this module as it is, so a provider
// that cannot be resolved fails in CI instead of at deploy.
import { Module, type DynamicModule } from '@nestjs/common';
import type { Mailer } from '@noctcore/auth';
import { AuthModule } from '@noctcore/auth-nestjs';
import type { Redis } from 'ioredis';
import { buildAuth, type AppUser } from './auth';
import { CONFIG, type AppConfig } from './config';
import {
  AccountController,
  AdminController,
  AuthController,
  HealthController,
} from './controllers';
import type { PrismaClient } from './generated/prisma/client';
import { InfraModule, MAILER, PRISMA, REDIS } from './infra.module';

@Module({})
export class AppModule {
  static withConfig(config: AppConfig): DynamicModule {
    return {
      module: AppModule,
      imports: [
        InfraModule.withConfig(config),
        AuthModule.forRootAsync<AppUser>({
          inject: [CONFIG, PRISMA, REDIS, MAILER],
          useFactory: (c: AppConfig, prisma: PrismaClient, redis: Redis, mailer: Mailer) => ({
            auth: buildAuth(c, prisma, redis, mailer),
            trustedHops: c.trustedHops,
            csrf: { secrets: [c.csrfSecret], allowedOrigins: [c.origin] },
            roles: (user) => [user.role],
          }),
        }),
      ],
      controllers: [HealthController, AuthController, AccountController, AdminController],
    };
  }
}
