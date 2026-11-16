import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

// Project Pages for github.com/noctcore/auth serve from
// https://noctcore.github.io/auth/. A wrong `base` still builds green and 404s
// every asset, which is why scripts/check-build.ts reads the emitted HTML.
export default defineConfig({
  site: 'https://noctcore.github.io',
  base: '/auth',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: '@noctcore/auth',
      description: 'A small, readable auth library: every module is tied to the attack it stops.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/noctcore/auth' }],
      editLink: { baseUrl: 'https://github.com/noctcore/auth/edit/main/site/' },
      sidebar: [
        { label: 'Overview', link: '/' },
        { label: 'Learn', items: [{ label: 'Topics', link: '/learn/' }, { label: 'Sessions and expiry', link: '/learn/sessions-and-expiry/' }, { label: 'Revocation races and the epoch fence', link: '/learn/revocation-races/' }] },
        { label: 'Build', items: [{ label: 'Guides', link: '/build/' }] },
        { label: 'Reference', items: [{ label: 'Reference', link: '/reference/' }] },
        { label: 'Security', items: [{ label: 'Security defaults', link: '/security/' }] },
      ],
    }),
  ],
  vite: {
    // Starlight renders some Markdown through Satteri, whose native binding is an
    // optional dependency that Bun's isolated linker keeps next to `satteri` only.
    // Leave it external in Astro 7's prerender environment.
    environments: { prerender: { resolve: { external: ['satteri'] } } },
  },
});
