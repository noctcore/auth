import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { configureTrustProxy } from '@noctcore/auth-nestjs';
import { AppModule } from './app.module';

const app = await NestFactory.create(AppModule);

// Express's req.ip now counts the same hops as the auth flows.
configureTrustProxy(app, process.env);
app.enableShutdownHooks();

await app.listen(Number(process.env.PORT ?? 3000));
