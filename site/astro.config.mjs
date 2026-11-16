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
      logo: {
        light: './src/assets/brand/mark-light.svg',
        dark: './src/assets/brand/mark-dark.svg',
      },
      customCss: ['./src/styles/tokens.css', './src/styles/theme.css'],
      expressiveCode: {
        themes: ['github-dark-default', 'github-light'],
        styleOverrides: {
          borderRadius: 'var(--nc-radius)',
          borderColor: 'var(--nc-line-soft)',
          codeBackground: 'var(--nc-code-bg)',
          codeFontFamily: 'var(--nc-font-mono)',
          uiFontFamily: 'var(--nc-font)',
          frames: {
            editorBackground: 'var(--nc-code-bg)',
            editorTabBarBackground: 'var(--nc-bg-raised)',
            editorActiveTabBackground: 'var(--nc-code-bg)',
            editorActiveTabIndicatorTopColor: 'var(--nc-accent)',
            editorActiveTabIndicatorBottomColor: 'transparent',
            editorTabBarBorderBottomColor: 'var(--nc-line-soft)',
            terminalBackground: 'var(--nc-code-bg)',
            terminalTitlebarBackground: 'var(--nc-bg-raised)',
            terminalTitlebarBorderBottomColor: 'var(--nc-line-soft)',
            frameBoxShadowCssValue: 'none',
          },
        },
      },
      description: 'A small, readable auth library: every module is tied to the attack it stops.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/noctcore/auth' }],
      editLink: { baseUrl: 'https://github.com/noctcore/auth/edit/main/site/' },
      sidebar: [
        { label: 'Overview', link: '/' },
        {
          label: 'Learn',
          items: [
            { label: 'Topics', link: '/learn/' },
            { label: 'Design choices', link: '/learn/design-choices/' },
            { label: 'Sessions and expiry', link: '/learn/sessions-and-expiry/' },
            { label: 'Revocation races and the epoch fence', link: '/learn/revocation-races/' },
            { label: 'Passwords', link: '/learn/passwords/' },
            { label: 'Enumeration', link: '/learn/enumeration/' },
            { label: 'Brute force and lockout', link: '/learn/brute-force-and-lockout/' },
            { label: 'Email verification', link: '/learn/email-verification/' },
            { label: 'Password reset', link: '/learn/password-reset/' },
            { label: 'CSRF', link: '/learn/csrf/' },
          ],
        },
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
