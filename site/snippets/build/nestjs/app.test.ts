import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Test } from '@nestjs/testing';
import { describeRoutes } from '@noctcore/auth-nestjs';
import request from 'supertest';
import { AppModule } from './app.module';

// The routes meant to be reachable without a session.
const PUBLIC_ROUTES = ['GET /auth/session', 'POST /auth/login', 'POST /auth/logout'];

test('the whole app boots, and only the listed routes are open', async () => {
  // Fails on a provider Nest cannot resolve, here instead of at deploy.
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
  const app = moduleRef.createNestApplication();

  await app.init();

  const routes = describeRoutes(app);
  const open = routes.filter((r) => r.public).map((r) => `${r.method} ${r.path}`);

  assert.deepEqual(open.sort(), [...PUBLIC_ROUTES].sort());

  for (const route of routes.filter((r) => !r.public && r.method === 'GET')) {
    const answer = await request(app.getHttpServer()).get(route.path);

    assert.equal(answer.status, 401, `${route.method} ${route.path}`);
  }

  await app.close();
});
