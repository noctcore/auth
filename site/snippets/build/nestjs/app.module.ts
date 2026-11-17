import { Module } from '@nestjs/common';
import { AuthModule, trustedHopsFromEnv } from '@noctcore/auth-nestjs';
import { buildAuth } from '../node-server/auth';
import { config } from '../node-server/config';
import { AccountController } from './account.controller';
import { AuthController } from './auth.controller';
import { MAILER, MailModule } from './mail.module';

@Module({
  imports: [
    MailModule,
    AuthModule.forRootAsync({
      inject: [MAILER],
      useFactory: (mailer: Parameters<typeof buildAuth>[0]) => ({
        auth: buildAuth(mailer),
        // Unset in production refuses to boot; "true" is refused anywhere.
        trustedHops: trustedHopsFromEnv(process.env),
        csrf: {
          // Not the auth secret. Add the previous one after it during a rollover.
          secrets: [config.csrfSecret],
          allowedOrigins: [config.origin],
          // A webhook that proves itself with a signature, not a cookie.
          exempt: ['/webhooks/billing'],
        },
        // Read on every request that needs a role, with the user just loaded.
        roles: (user) => ('role' in user ? [String(user.role)] : []),
      }),
    }),
  ],
  controllers: [AuthController, AccountController],
})
export class AppModule {}
