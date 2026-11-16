/**
 * Test doubles for the injected collaborators: a clock you move by hand, a
 * mailer and an audit sink that record what they were given, and a fast
 * hasher. None of these belongs in production.
 */
import type { AuditSink, AuthEvent } from '../audit';
import type { Clock } from '../clock';
import { sha256Hex } from '../hash';
import type { AuthMailEvent, Mailer } from '../mail';
import type { RequestMeta } from '../meta';
import type { PasswordHasher } from '../password/hasher';

export interface ManualClock extends Clock {
  advance(ms: number): void;
  set(ms: number): void;
}

export function manualClock(start = Date.UTC(2026, 0, 1)): ManualClock {
  let current = start;
  return {
    now: () => current,
    advance: (ms) => {
      current += ms;
    },
    set: (ms) => {
      current = ms;
    },
  };
}

export interface RecordingMailer extends Mailer {
  readonly sent: AuthMailEvent[];
  /** The most recent event of a type. */
  last<T extends AuthMailEvent['type']>(type: T): Extract<AuthMailEvent, { type: T }> | undefined;
}

export function recordingMailer(): RecordingMailer {
  const sent: AuthMailEvent[] = [];
  return {
    sent,
    async send(event) {
      sent.push(event);
    },
    last(type) {
      for (let i = sent.length - 1; i >= 0; i--) {
        const event = sent[i];
        if (event?.type === type) return event as never;
      }
      return undefined;
    },
  };
}

export interface RecordingAudit extends AuditSink {
  readonly events: Array<AuthEvent & { meta?: RequestMeta | undefined }>;
  types(): string[];
}

export function recordingAudit(): RecordingAudit {
  const events: Array<AuthEvent & { meta?: RequestMeta | undefined }> = [];
  return {
    events,
    async emit(event, meta) {
      events.push({ ...event, meta });
    },
    types: () => events.map((e) => e.type),
  };
}

/**
 * A fast, deterministic hasher for unit tests. NOT a password hash: it is a
 * plain SHA-256. `version` lets a test simulate a parameter change for rehash.
 */
export function plainHasher(version = 1): PasswordHasher {
  const prefix = `plain$v${version}$`;
  return {
    hash: async (password) => `${prefix}${sha256Hex(password)}`,
    verify: async (hash, password) => {
      const at = hash.lastIndexOf('$');
      return at > 0 && hash.slice(at + 1) === sha256Hex(password);
    },
    needsRehash: (hash) => !hash.startsWith(prefix),
  };
}
