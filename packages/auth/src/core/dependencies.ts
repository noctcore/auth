/**
 * Everything `AuthCore` is built from, resolved by `createAuth` from the
 * config. Kept in one object so the core can hold it in a native private field
 * that plugins and `auth.context` cannot reach.
 */
import type { Door } from './config';
import type { HookLists } from './hooks';
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
import type { RandomSource } from '../crypto/random';
import type { AttributeSchema, SessionManager } from '../session/session-manager';
import type { RateLimitRule, Throttle } from '../throttle/throttle';
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
  /** Key for trusted-device tokens, derived from the server secret. */
  readonly deviceKey: Uint8Array;
  readonly clock: Clock;
  readonly random: RandomSource;
  readonly logger: Logger;
  readonly metrics: Metrics;
}
