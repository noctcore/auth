/**
 * An in-memory TokenStore with the guarantees the conformance suite asks of
 * real adapters. For unit tests and prototypes only.
 */
import type { StoredToken, TokenStore } from '../../ports/stores';

export class MemoryTokenStore implements TokenStore {
  private readonly tokens = new Map<string, StoredToken>();

  private key(purpose: string, hash: string): string {
    return `${purpose}\u0000${hash}`;
  }

  async put(token: StoredToken): Promise<void> {
    // No await between the delete and the set: the replacement must be atomic.
    this.removeByUser(token.userId, [token.purpose]);
    this.tokens.set(this.key(token.purpose, token.hash), { ...token, data: { ...token.data } });
  }

  async find(purpose: string, hash: string): Promise<StoredToken | null> {
    const token = this.tokens.get(this.key(purpose, hash));

    return token ? { ...token } : null;
  }

  async findByUser(purpose: string, userId: string): Promise<StoredToken | null> {
    for (const token of this.tokens.values()) {
      if (token.purpose === purpose && token.userId === userId) return { ...token };
    }

    return null;
  }

  async consume(purpose: string, hash: string): Promise<StoredToken | null> {
    const key = this.key(purpose, hash);
    const token = this.tokens.get(key);

    if (!token) return null;

    this.tokens.delete(key);

    return token;
  }

  async extendExpiry(purpose: string, hash: string, expiresAt: number): Promise<boolean> {
    const key = this.key(purpose, hash);
    const token = this.tokens.get(key);

    if (!token) return false;

    this.tokens.set(key, { ...token, expiresAt });

    return true;
  }

  async incrementAttempts(purpose: string, userId: string, max: number): Promise<number | null> {
    for (const [key, token] of this.tokens) {
      if (token.purpose === purpose && token.userId === userId) {
        if (token.attempts >= max) return null;

        const attempts = token.attempts + 1;

        this.tokens.set(key, { ...token, attempts });

        return attempts;
      }
    }

    return null;
  }

  async deleteByUser(userId: string, purposes?: readonly string[]): Promise<void> {
    this.removeByUser(userId, purposes);
  }

  private removeByUser(userId: string, purposes?: readonly string[]): void {
    for (const [key, token] of this.tokens) {
      if (token.userId === userId && (!purposes || purposes.includes(token.purpose)))
        this.tokens.delete(key);
    }
  }
}
