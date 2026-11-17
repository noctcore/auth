// A016: a plugin minting a session outside the seam.
//
// A plugin, or app code holding auth.context, mints a session directly and so
// skips the hooks, the epoch fence and the device cookie.
//
// Stopped by: core/plugin-context.ts and core/auth-core.ts: sessions are exposed without a
//   mint; every session goes through issueSession.
// Learn: Design choices (/auth/learn/design-choices/)
import { describe, expect, it } from 'vitest';

import { definePlugin } from '../../src';
import { setup } from './support';

describe('A016: a plugin minting a session outside the seam', () => {
  it('probe F: plugins and auth.context cannot mint a session outside issueSession', async () => {
    let seen: Record<string, unknown> | null = null;

    const spy = definePlugin({
      id: 'spy',
      flows: (context) => {
        seen = context as unknown as Record<string, unknown>;

        return {};
      },
    });

    const { auth } = setup({ plugins: [spy] });

    for (const context of [seen, auth.context as unknown as Record<string, unknown>]) {
      if (!context) throw new Error('plugin context not captured');

      const sessions = context['sessions'] as Record<string, unknown>;

      expect('mint' in sessions).toBe(false);
      expect(Object.isFrozen(sessions)).toBe(true);

      // Nothing reachable from the context's own properties exposes a mint.
      const mints = Object.values(context)
        .filter((value): value is { mint?: unknown } => !!value && typeof value === 'object')
        .filter((value) => typeof value.mint === 'function');

      expect(mints).toEqual([]);
    }
  });
});
