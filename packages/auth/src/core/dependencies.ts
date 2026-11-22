/**
 * Everything `AuthCore` is built from, resolved by `createAuth` from the
 * config. Kept in one object so the core can hold it in a native private field
 * that plugins and `auth.context` cannot reach.
 */
import type { BackgroundTasks } from './background';
import type { Door } from './config';
import type { HookLists } from './hooks';
import type { RandomSource } from '../crypto/random';
import type { SessionCookieConfig } from '../http/cookie';
import type { BreachChecker } from '../password/breach';
import type { PasswordHasher } from '../password/hasher';
import type { PasswordPolicy } from '../password/policy';
import type { AuditSink } from '../ports/audit';
import type { CaptchaVerifier } from '../ports/captcha';
import type { Clock } from '../ports/clock';
import type { Logger, Metrics } from '../ports/logger';
import type { Mailer } from '../ports/mail';
import type { AuthUser, UserStore } from '../ports/stores';
import type { SessionManager } from '../session/session-manager';
import type { AttributeSchema } from '../session/session-types';
import type { NormalizedEmail, ResolvedEmailNormalizer } from '../shared/email';
import type { RateLimitRule } from '../throttle/rules';
import type { Throttle } from '../throttle/throttle';
import type { OneTimeTokens } from '../tokens/one-time-tokens';

export interface CoreDependencies<U extends AuthUser, A> {
  readonly users: UserStore<U>;
  readonly sessions: SessionManager<A>;
  readonly tokens: OneTimeTokens;
  readonly throttle: Throttle;
  readonly hasher: PasswordHasher;
  readonly policy: PasswordPolicy;
  readonly breachCheck: BreachChecker | undefined;
  readonly captcha: CaptchaVerifier | undefined;
  readonly mailer: Mailer;
  readonly audit: AuditSink | undefined;
  readonly hooks: HookLists<U, A>;
  readonly doors: Readonly<Partial<Record<Door, RateLimitRule>>>;
  readonly cookie: SessionCookieConfig;
  readonly attributeSchema: AttributeSchema<A> | undefined;
  /** The normaliser resolved from `email.normalize`: every address goes through it. */
  readonly emails: ResolvedEmailNormalizer;
  /**
   * Keys for trusted-device tokens, derived from the server secret and from
   * each previous secret of a rotation: current first, the only one that signs.
   */
  readonly deviceKeys: readonly [Uint8Array, ...Uint8Array[]];
  /** Keys for the public session handles, current first, the only one that names a session. */
  readonly handleKeys: readonly [Uint8Array, ...Uint8Array[]];
  /** Roots of the per-purpose keys behind `keyedHash`, current first, the only one that stores. */
  readonly pluginKeys: readonly [Uint8Array, ...Uint8Array[]];
  /** How recent a credential proof must be for a sensitive action. */
  readonly freshAuthAgeMs: number;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly logger: Logger;
  readonly metrics: Metrics;
  /** Where `background` tasks run: the app's `waitUntil`, timeout and pending cap. */
  readonly background: BackgroundTasks;
  /**
   * Whether an address is held for the owner of an email change away from it
   * that can still be reverted. The rule lives with the email change flows
   * (`flows/email-reservation.ts`), which the core may not import.
   */
  readonly addressHeld: (email: NormalizedEmail) => Promise<boolean>;
}
