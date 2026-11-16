import { defineConfig } from 'prisma/config';

// The CLI reads the schema from the URL; the app passes it to the adapter (src/db.ts).
const url = new URL(process.env.DATABASE_URL ?? 'postgresql://auth:auth@localhost:5440/auth');
url.searchParams.set('schema', 'example');

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: { url: url.toString() },
});
