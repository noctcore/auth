// Runs the example against docker-compose.yml's Redis and PostgreSQL.
import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { configureTrustProxy } from '@noctcore/auth-nestjs';
import { AppModule } from './app.module';
import { readConfig } from './config';

const config = readConfig(process.env);
const app = await NestFactory.create(AppModule.withConfig(config));

// Express's own req.ip follows the same hop count the auth flows use.
configureTrustProxy(app, process.env);
app.enableShutdownHooks();

const port = Number(process.env['PORT'] ?? 3000);

await app.listen(port);
process.stdout.write(`listening on http://localhost:${port}\n`);
