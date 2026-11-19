import type { DatabaseSync } from 'node:sqlite';
import { adoptLegacySessions, type LegacySession, type SessionStore } from '@noctcore/auth';

/** A row of the app's own session table from before the switch. */
interface OldSessionRow {
  readonly user_id: string;
  readonly created_at: number;
  readonly last_seen_at: number;
  readonly expires_at: number;
  readonly remember: number;
}

/**
 * Wraps the package's session store so the sessions in the old `sessions`
 * table keep working. The old table already keyed each row by the SHA-256 hex
 * of the cookie token, the package's own store key, and the cookie keeps its
 * name. Remove the wrapper 30 days after the switch: by then every old row has
 * been adopted or has expired.
 */
export function withOldSessions(store: SessionStore, db: DatabaseSync): SessionStore {
  // One statement reads and removes the row, so two requests on one cookie
  // cannot both get it.
  const takeRow = db.prepare(
    'DELETE FROM sessions WHERE token_hash = ? RETURNING user_id, created_at, last_seen_at, expires_at, remember',
  );

  return adoptLegacySessions(store, {
    maxTtl: '30d', // the app's session.rememberMeTtl
    take: async (id): Promise<LegacySession | null> => {
      const row = takeRow.get(id) as OldSessionRow | undefined;

      if (!row) return null;

      return {
        userId: row.user_id,
        createdAt: row.created_at,
        // Grants fresh-auth standing: the old table has no later sign-in time.
        authenticatedAt: row.created_at,
        lastActiveAt: row.last_seen_at,
        expiresAt: row.expires_at,
        idleTimeoutMs: row.remember ? 7 * 86_400_000 : 30 * 60_000,
        rememberMe: row.remember === 1,
      };
    },
  });
}
