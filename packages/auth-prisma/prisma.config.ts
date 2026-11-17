// Prisma CLI config for the integration tests' schema. Generating needs no
// database; `db push` uses DATABASE_URL (docker-compose.yml's by default).
import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: 'tests/prisma/schema.prisma',
  datasource: {
    url: process.env['DATABASE_URL'] ?? 'postgresql://auth:auth@localhost:5440/auth',
  },
});
