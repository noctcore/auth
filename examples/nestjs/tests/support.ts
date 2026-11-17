// Boots the real AppModule with test settings and a recording mailer, and a
// browser-like client that keeps cookies and sends what a same-origin page sends.
import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { recordingMailer } from '@noctcore/auth/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { readConfig } from '../src/config';
import { MAILER } from '../src/infra.module';

export const ORIGIN = 'http://app.test';

export async function bootApp(vars: Record<string, string | undefined> = {}) {
  const config = readConfig({
    AUTH_SECRET: 'example-auth-secret-at-least-32-bytes!',
    CSRF_SECRET: 'example-csrf-secret-at-least-32-bytes!',
    APP_ORIGIN: ORIGIN,
    TRUST_PROXY: '1',
    REDIS_PREFIX: `example-nestjs-test-${randomUUID()}:`,
    ...vars,
  });

  const mailer = recordingMailer();

  const moduleRef = await Test.createTestingModule({ imports: [AppModule.withConfig(config)] })
    .overrideProvider(MAILER)
    .useValue(mailer)
    .compile();

  const app = moduleRef.createNestApplication({ logger: false });

  await app.init();

  return { app, mailer, config };
}

export class Browser {
  readonly cookies = new Map<string, string>();

  constructor(
    private readonly app: INestApplication,
    private readonly ip = '203.0.113.10',
  ) {}

  async send(method: 'GET' | 'POST', path: string, body?: object) {
    const server = request(this.app.getHttpServer() as Parameters<typeof request>[0]);
    const pending = method === 'GET' ? server.get(path) : server.post(path);

    void pending
      .set('origin', ORIGIN)
      .set('sec-fetch-site', 'same-origin')
      .set('x-csrf-token', this.cookies.get('csrf') ?? '')
      .set('x-forwarded-for', this.ip)
      .set('cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '));

    const response = body === undefined ? await pending : await pending.send(body);
    const raw = response.headers['set-cookie'] as string[] | string | undefined;

    for (const line of raw === undefined ? [] : [raw].flat()) {
      const [pair = '', ...attributes] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);

      if (attributes.some((a) => a.trim().toLowerCase() === 'max-age=0')) this.cookies.delete(name);
      else this.cookies.set(name, decodeURIComponent(pair.slice(eq + 1)));
    }

    return { status: response.status, body: response.body as Record<string, unknown> };
  }
}
