/**
 * Single-use, purpose-bound tokens: email verification and password reset
 * links, short codes a person types, and the ticket a verified code is
 * exchanged for.
 *
 * - Links are 32 random bytes; only their SHA-256 is stored.
 * - Codes (6 to 9 digits) are stored as an HMAC under the server secret, bound
 *   to purpose and user, because a plain hash of a 6-digit code is reversed in
 *   milliseconds from a leaked table. During a secret rotation a code is
 *   checked under the current key and each previous one (all of them, every
 *   time), while a new code is only ever stored under the current key. Each code has an attempt cap enforced by
 *   an atomic increment BEFORE the comparison, so parallel guesses cannot
 *   exceed it. A correct code is exchanged for a short-lived link-style ticket,
 *   so the code itself is never what authorises the password write.
 * - One live token per user and purpose: issuing a new one replaces the old.
 * - Consumption is atomic: of many concurrent redemptions, exactly one wins.
 *
 * Guide: Learn, "Email verification" and "Password reset".
 */
import { hexDigestsEqual, hmacSha256Hex, sha256Hex } from '../crypto/hash';
import {
  generateNumericCode,
  generateToken,
  isTokenShape,
  type RandomSource,
} from '../crypto/random';
import type { Clock } from '../ports/clock';
import { NO_SUCH_USER_ID, type StoredToken, type TokenStore } from '../ports/stores';

/**
 * What a redemption found. Only `valid` carries `userId`; refusals that still
 * know the account carry it as `namedUserId`, so a careless caller cannot act
 * on a dead token's account (it is there for the audit row only).
 */
export type TokenRedemption =
  | {
      readonly status: 'valid';
      readonly userId: string;
      readonly data: Readonly<Record<string, string>>;
    }
  | {
      readonly status: 'expired' | 'consumed' | 'exhausted' | 'mismatch';
      readonly namedUserId: string;
    }
  | { readonly status: 'unknown' };

const CODE_PATTERN = /^\d{6,9}$/u;

export class OneTimeTokens {
  /** Current first; codes are stored under the first only. */
  private readonly keys: readonly Uint8Array[];

  constructor(
    private readonly store: TokenStore,
    private readonly clock: Clock,
    private readonly random: RandomSource,
    /**
     * Key for code HMACs, or the keys of a secret rotation, current first.
     * Codes are refused when it is absent.
     */
    secret: Uint8Array | readonly Uint8Array[] | undefined,
  ) {
    this.keys = secret === undefined ? [] : secret instanceof Uint8Array ? [secret] : [...secret];
  }

  private codeHash(purpose: string, userId: string, code: string, key = this.keys[0]): string {
    if (!key) throw new Error('A server secret is required for code tokens');

    return hmacSha256Hex(key, `${purpose}:${userId}:${code}`);
  }

  async issueLink(
    purpose: string,
    userId: string,
    ttlMs: number,
    data: Record<string, string> = {},
  ): Promise<{ token: string; expiresAt: number }> {
    const token = generateToken(this.random);
    const expiresAt = this.clock.now() + ttlMs;

    await this.store.put({ purpose, userId, hash: sha256Hex(token), expiresAt, attempts: 0, data });

    return { token, expiresAt };
  }

  /** Looks a link up without consuming it (cheap checks before expensive work). */
  async peekLink(purpose: string, token: unknown): Promise<TokenRedemption> {
    if (!isTokenShape(token)) return { status: 'unknown' };

    const found = await this.store.find(purpose, sha256Hex(token));

    return this.classify(found, found);
  }

  /** Consumes a link. Expiry is checked after the atomic consume, so an expired link is also gone. */
  async redeemLink(purpose: string, token: unknown): Promise<TokenRedemption> {
    if (!isTokenShape(token)) return { status: 'unknown' };

    const hash = sha256Hex(token);
    const found = await this.store.find(purpose, hash);

    if (!found) return { status: 'unknown' };

    const consumed = await this.store.consume(purpose, hash);

    return this.classify(found, consumed);
  }

  private classify(found: StoredToken | null, consumed: StoredToken | null): TokenRedemption {
    if (!found) return { status: 'unknown' };
    if (!consumed) return { status: 'consumed', namedUserId: found.userId };
    if (consumed.expiresAt <= this.clock.now())
      return { status: 'expired', namedUserId: consumed.userId };

    return { status: 'valid', userId: consumed.userId, data: consumed.data };
  }

  async issueCode(
    purpose: string,
    userId: string,
    ttlMs: number,
    digits: number,
    data: Record<string, string> = {},
  ): Promise<{ code: string; expiresAt: number }> {
    const code = generateNumericCode(digits, this.random);
    const expiresAt = this.clock.now() + ttlMs;

    await this.store.put({
      purpose,
      userId,
      hash: this.codeHash(purpose, userId, code),
      expiresAt,
      attempts: 0,
      data,
    });

    return { code, expiresAt };
  }

  /**
   * Checks a code for a user. The attempt is counted atomically before the
   * comparison; the code is deleted when it expires, is exhausted, or wins.
   */
  async redeemCode(
    purpose: string,
    userId: string | null,
    code: unknown,
    maxAttempts: number,
  ): Promise<TokenRedemption> {
    // An unknown user pays for the same HMAC and the same store lookup (under
    // an id no user can have), so neither the work nor the round trips depend
    // on whether the account exists.
    const candidate = typeof code === 'string' && CODE_PATTERN.test(code) ? code : '000000';
    const subject = userId ?? NO_SUCH_USER_ID;
    const expected = this.codeHash(purpose, subject, candidate);

    // The previous keys of a rotation, each paid for on every try.
    const previous = this.keys
      .slice(1)
      .map((key) => this.codeHash(purpose, subject, candidate, key));

    const found = await this.store.findByUser(purpose, subject);

    if (userId === null || typeof code !== 'string' || !CODE_PATTERN.test(code))
      return { status: 'unknown' };
    if (!found) return { status: 'unknown' };

    // A refused code is removed by the hash that was read, never by user and
    // purpose: a code resent meanwhile is another row and must survive.
    if (found.expiresAt <= this.clock.now()) {
      await this.store.consume(purpose, found.hash);

      return { status: 'expired', namedUserId: userId };
    }

    const attempt = await this.store.incrementAttempts(purpose, userId, maxAttempts);

    if (attempt === null) {
      await this.store.consume(purpose, found.hash);

      return { status: 'exhausted', namedUserId: userId };
    }

    // Every candidate is compared, so the time does not say which key matched.
    const matches = [expected, ...previous].map((hash) => hexDigestsEqual(found.hash, hash));

    if (!matches.includes(true)) {
      if (attempt >= maxAttempts) await this.store.consume(purpose, found.hash);

      return { status: 'mismatch', namedUserId: userId };
    }

    const consumed = await this.store.consume(purpose, found.hash);

    if (!consumed) return { status: 'consumed', namedUserId: userId };

    return { status: 'valid', userId, data: consumed.data };
  }

  /**
   * The data and expiry of the user's unexpired token of that purpose, without
   * consuming it; null when there is none. For tokens whose presence is the
   * point (a live revert link, a block), never to check a secret.
   */
  async findLive(
    purpose: string,
    userId: string,
  ): Promise<{
    readonly data: Readonly<Record<string, string>>;
    readonly expiresAt: number;
  } | null> {
    const found = await this.store.findByUser(purpose, userId);

    if (!found || found.expiresAt <= this.clock.now()) return null;

    return { data: found.data, expiresAt: found.expiresAt };
  }

  /**
   * Stores a marker under `userId` that is found by `key` instead of by a
   * secret: the row holds the SHA-256 of the key, so a lookup by key needs no
   * user id. A marker of another user under the same key is removed first.
   * Not for secrets: anyone who knows the key can find the marker.
   */
  async putKeyed(
    purpose: string,
    userId: string,
    key: string,
    ttlMs: number,
    data: Record<string, string> = {},
  ): Promise<void> {
    const hash = sha256Hex(key);

    await this.store.consume(purpose, hash);

    await this.store.put({
      purpose,
      userId,
      hash,
      expiresAt: this.clock.now() + ttlMs,
      attempts: 0,
      data,
    });
  }

  /** The owner and data of the unexpired marker filed under `key`, or null. */
  async findKeyed(
    purpose: string,
    key: string,
  ): Promise<{ readonly userId: string; readonly data: Readonly<Record<string, string>> } | null> {
    const found = await this.store.find(purpose, sha256Hex(key));

    if (!found || found.expiresAt <= this.clock.now()) return null;

    return { userId: found.userId, data: found.data };
  }

  /**
   * Moves a live link's expiry out to `expiresAt`; never shortens it. Unknown
   * or expired links stay as they are, and so does a link spent between the
   * read and the write: the extend never writes a link back.
   */
  async extendLink(purpose: string, token: unknown, expiresAt: number): Promise<void> {
    if (!isTokenShape(token)) return;

    const hash = sha256Hex(token);
    const found = await this.store.find(purpose, hash);

    if (!found || found.expiresAt <= this.clock.now() || found.expiresAt >= expiresAt) return;

    if (this.store.extendExpiry) {
      await this.store.extendExpiry(purpose, hash, expiresAt);

      return;
    }

    // A store without extendExpiry: only the caller that takes the link puts
    // it back, so a link spent meanwhile is not taken and stays spent.
    const taken = await this.store.consume(purpose, hash);

    if (taken) await this.store.put({ ...taken, expiresAt });
  }

  revokeAll(userId: string, purposes: readonly string[]): Promise<void> {
    return this.store.deleteByUser(userId, purposes);
  }
}
