/**
 * @noctcore/auth-prisma: Prisma user and one-time token stores for @noctcore/auth.
 *
 * The stores take your client's model delegates (`prisma.user`,
 * `prisma.authToken`), not a client type, because Prisma 7 generates the client
 * into your app. Any model with the mapped fields works; the token model to
 * copy is `prisma/auth.prisma` in this package.
 *
 * Every write that must not happen twice is a single conditional statement:
 * unique violations become `null` (never thrown), guarded updates use
 * `updateMany` with the guard in `where`, consume is a delete that returns the
 * row, and the attempt cap is an update whose `where` carries the cap.
 */
import type { AuthUser, NormalizedEmail, StoredToken, TokenStore, UserStore, WithPasswordHash } from '@noctcore/auth';

/* eslint-disable @typescript-eslint/no-explicit-any -- Prisma delegates are generic per model; these are the structural shapes the stores call. */
export interface PrismaUserDelegate {
  findFirst(args: any): PromiseLike<any>;
  create(args: any): PromiseLike<any>;
  updateMany(args: any): PromiseLike<{ count: number }>;
}

export interface PrismaAuthTokenDelegate {
  upsert(args: any): PromiseLike<any>;
  findUnique(args: any): PromiseLike<any>;
  delete(args: any): PromiseLike<any>;
  update(args: any): PromiseLike<any>;
  deleteMany(args: any): PromiseLike<{ count: number }>;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

/** Column names on your user model. */
export interface UserFields {
  readonly id?: string;
  readonly email?: string;
  readonly emailVerified?: string;
  readonly passwordHash?: string;
  /** A nullable timestamp marking soft deletion; null to disable soft deletion. Default `deletedAt`. */
  readonly deletedAt?: string | null;
}

export interface PrismaUserStoreOptions<U extends AuthUser> {
  /** `prisma.user`, or whichever model holds your accounts. */
  readonly delegate: PrismaUserDelegate;
  readonly fields?: UserFields;
  /** Extra columns to read for your user type. */
  readonly select?: Readonly<Record<string, true>>;
  /** Maps a row (mapped fields plus `select`) to your user type. Default: the four auth fields. */
  readonly toUser?: (row: Record<string, unknown>) => U;
  /** Extra values for required columns of a new user (a tenant, a display name). */
  readonly createData?: (input: { email: NormalizedEmail }) => Record<string, unknown>;
}

const P2002 = 'P2002';
const P2025 = 'P2025';

function prismaCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null && 'code' in error ? String((error as { code: unknown }).code) : undefined;
}

/** The `UserStore` on a Prisma model. */
export class PrismaUserStore<U extends AuthUser = AuthUser> implements UserStore<U> {
  private readonly f: Required<Omit<UserFields, 'deletedAt'>> & { deletedAt: string | null };
  private readonly selectWithHash: Record<string, true>;
  private readonly selectUser: Record<string, true>;

  constructor(private readonly options: PrismaUserStoreOptions<U>) {
    const fields = options.fields ?? {};
    this.f = {
      id: fields.id ?? 'id',
      email: fields.email ?? 'email',
      emailVerified: fields.emailVerified ?? 'emailVerified',
      passwordHash: fields.passwordHash ?? 'passwordHash',
      deletedAt: fields.deletedAt === undefined ? 'deletedAt' : fields.deletedAt,
    };
    this.selectUser = { ...options.select, [this.f.id]: true, [this.f.email]: true, [this.f.emailVerified]: true };
    this.selectWithHash = { ...this.selectUser, [this.f.passwordHash]: true };
  }

  private live(where: Record<string, unknown>): Record<string, unknown> {
    return this.f.deletedAt ? { ...where, [this.f.deletedAt]: null } : where;
  }

  private toUser(row: Record<string, unknown>): U {
    if (this.options.toUser) return this.options.toUser(row);
    return {
      id: String(row[this.f.id]),
      email: String(row[this.f.email]),
      emailVerified: Boolean(row[this.f.emailVerified]),
    } as U;
  }

  private withHash(row: Record<string, unknown> | null): WithPasswordHash<U> | null {
    if (!row) return null;
    const hash = row[this.f.passwordHash];
    return { ...this.toUser(row), passwordHash: typeof hash === 'string' ? hash : null };
  }

  async findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<U> | null> {
    return this.withHash(await this.options.delegate.findFirst({ where: this.live({ [this.f.email]: email }), select: this.selectWithHash }));
  }

  async findCredentialById(id: string): Promise<WithPasswordHash<U> | null> {
    return this.withHash(await this.options.delegate.findFirst({ where: this.live({ [this.f.id]: id }), select: this.selectWithHash }));
  }

  async findById(id: string): Promise<U | null> {
    const row = await this.options.delegate.findFirst({ where: this.live({ [this.f.id]: id }), select: this.selectUser });
    return row ? this.toUser(row) : null;
  }

  async create(input: { email: NormalizedEmail; passwordHash: string }): Promise<U | null> {
    try {
      const row = await this.options.delegate.create({
        data: { ...this.options.createData?.(input), [this.f.email]: input.email, [this.f.passwordHash]: input.passwordHash },
        select: this.selectUser,
      });
      return this.toUser(row);
    } catch (error) {
      if (prismaCode(error) === P2002) return null;
      throw error;
    }
  }

  async setPasswordHash(id: string, passwordHash: string, options: { readonly expected?: string | null } = {}): Promise<boolean> {
    // With `expected`, the hash check is part of the same UPDATE: a compare-and-set.
    const guard = options.expected === undefined ? {} : { [this.f.passwordHash]: options.expected };
    const { count } = await this.options.delegate.updateMany({
      where: this.live({ [this.f.id]: id, ...guard }),
      data: { [this.f.passwordHash]: passwordHash },
    });
    return count > 0;
  }

  async markEmailVerified(id: string, email: NormalizedEmail): Promise<boolean> {
    const { count } = await this.options.delegate.updateMany({
      where: this.live({ [this.f.id]: id, [this.f.email]: email }),
      data: { [this.f.emailVerified]: true },
    });
    return count > 0;
  }
}

interface TokenRow {
  purpose: string;
  userId: string;
  hash: string;
  expiresAt: Date;
  attempts: number;
  data: unknown;
}

function toToken(row: TokenRow | null): StoredToken | null {
  if (!row) return null;
  const data = row.data && typeof row.data === 'object' && !Array.isArray(row.data) ? (row.data as Record<string, string>) : {};
  return { purpose: row.purpose, userId: row.userId, hash: row.hash, expiresAt: row.expiresAt.getTime(), attempts: row.attempts, data };
}

/** The `TokenStore` on the `AuthToken` model from `prisma/auth.prisma`. */
export class PrismaTokenStore implements TokenStore {
  constructor(private readonly delegate: PrismaAuthTokenDelegate) {}

  async put(token: StoredToken): Promise<void> {
    const values = { hash: token.hash, expiresAt: new Date(token.expiresAt), attempts: token.attempts, data: { ...token.data } };
    const args = {
      where: { userId_purpose: { userId: token.userId, purpose: token.purpose } },
      create: { userId: token.userId, purpose: token.purpose, ...values },
      update: values,
    };
    try {
      await this.delegate.upsert(args);
    } catch (error) {
      // Two concurrent first puts can both try to insert; the loser updates instead.
      if (prismaCode(error) !== P2002) throw error;
      await this.delegate.upsert(args);
    }
  }

  async find(purpose: string, hash: string): Promise<StoredToken | null> {
    return toToken(await this.delegate.findUnique({ where: { purpose_hash: { purpose, hash } } }));
  }

  async findByUser(purpose: string, userId: string): Promise<StoredToken | null> {
    return toToken(await this.delegate.findUnique({ where: { userId_purpose: { userId, purpose } } }));
  }

  async consume(purpose: string, hash: string): Promise<StoredToken | null> {
    try {
      return toToken(await this.delegate.delete({ where: { purpose_hash: { purpose, hash } } }));
    } catch (error) {
      if (prismaCode(error) === P2025) return null;
      throw error;
    }
  }

  async incrementAttempts(purpose: string, userId: string, max: number): Promise<number | null> {
    try {
      const row = (await this.delegate.update({
        where: { userId_purpose: { userId, purpose }, attempts: { lt: max } },
        data: { attempts: { increment: 1 } },
        select: { attempts: true },
      })) as { attempts: number };
      return row.attempts;
    } catch (error) {
      if (prismaCode(error) === P2025) return null;
      throw error;
    }
  }

  async deleteByUser(userId: string, purposes?: readonly string[]): Promise<void> {
    await this.delegate.deleteMany({ where: purposes ? { userId, purpose: { in: [...purposes] } } : { userId } });
  }
}

/** Both Prisma stores. */
export function prismaStores<U extends AuthUser = AuthUser>(options: PrismaUserStoreOptions<U> & { readonly tokenDelegate: PrismaAuthTokenDelegate }) {
  return { users: new PrismaUserStore<U>(options), tokens: new PrismaTokenStore(options.tokenDelegate) };
}
