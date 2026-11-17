/**
 * The `UserStore` on a Prisma model. Guarded writes put the guard in the
 * `where` of one `updateMany`, so a compare-and-set is a single statement.
 */
import type {
  AuthUser,
  EmailChangeResult,
  Logger,
  NormalizedEmail,
  UserStore,
  WithPasswordHash,
} from '@noctcore/auth';
import type { PrismaUserDelegate } from './delegates';
import { isValidationError, P2002, prismaCode } from './prisma-errors';

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
  /**
   * Told once, as a warning, when Prisma refuses the skipped insert and the
   * store switches to `create` for good (SQLite, a nested `createData`). Pass
   * the logger you give `createAuth`. Default: silent.
   */
  readonly logger?: Pick<Logger, 'warn'>;
}

/** A user row as selected: the mapped auth columns plus your `select`. */
type UserRow = Record<string, unknown>;

/** The `UserStore` on a Prisma model. */
export class PrismaUserStore<U extends AuthUser = AuthUser> implements UserStore<U> {
  private readonly f: Required<Omit<UserFields, 'deletedAt'>> & { deletedAt: string | null };
  private readonly selectWithHash: Record<string, true>;
  /** False once Prisma refused the bulk insert (SQLite, nested `createData`). */
  private bulkInsert = true;
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

    this.selectUser = {
      ...options.select,
      [this.f.id]: true,
      [this.f.email]: true,
      [this.f.emailVerified]: true,
    };

    this.selectWithHash = { ...this.selectUser, [this.f.passwordHash]: true };
  }

  private live(where: Record<string, unknown>): Record<string, unknown> {
    return this.f.deletedAt ? { ...where, [this.f.deletedAt]: null } : where;
  }

  private toUser(row: UserRow): U {
    if (this.options.toUser) return this.options.toUser(row);

    return {
      id: String(row[this.f.id]),
      email: String(row[this.f.email]),
      emailVerified: Boolean(row[this.f.emailVerified]),
    } as U;
  }

  private withHash(row: UserRow | null): WithPasswordHash<U> | null {
    if (!row) return null;

    const hash = row[this.f.passwordHash];

    return { ...this.toUser(row), passwordHash: typeof hash === 'string' ? hash : null };
  }

  async findCredentialByEmail(email: NormalizedEmail): Promise<WithPasswordHash<U> | null> {
    const row = (await this.options.delegate.findFirst({
      where: this.live({ [this.f.email]: email }),
      select: this.selectWithHash,
    })) as UserRow | null;

    return this.withHash(row);
  }

  async findCredentialById(id: string): Promise<WithPasswordHash<U> | null> {
    const row = (await this.options.delegate.findFirst({
      where: this.live({ [this.f.id]: id }),
      select: this.selectWithHash,
    })) as UserRow | null;

    return this.withHash(row);
  }

  async findById(id: string): Promise<U | null> {
    const row = (await this.options.delegate.findFirst({
      where: this.live({ [this.f.id]: id }),
      select: this.selectUser,
    })) as UserRow | null;

    return row ? this.toUser(row) : null;
  }

  /**
   * Inserts the user, or answers null when the address (or another unique
   * column) is taken.
   *
   * Where Prisma accepts `createManyAndReturn` with `skipDuplicates`
   * (PostgreSQL and CockroachDB), a taken address is an insert that skips the
   * duplicate and returns no row, not a failed statement. A failed statement
   * makes the driver's next query on that pool slower (about 3 ms measured on
   * PostgreSQL through `@prisma/adapter-pg`), and at sign-up that next query
   * would tell a taken address from a new one.
   *
   * Everywhere else it uses `create` and reads a unique violation (P2002) as
   * taken: on a delegate without `createManyAndReturn` (MySQL, SQL Server),
   * and when Prisma refuses the bulk insert with a validation error, which it
   * does on SQLite (no `skipDuplicates`) and for a `createData` with nested
   * writes or relation fields (a bulk insert takes plain columns only). That
   * refusal happens in the client, before any statement, and the store
   * remembers it, so later sign-ups go straight to `create`.
   */
  async create(input: { email: NormalizedEmail; passwordHash: string }): Promise<U | null> {
    const data = {
      ...this.options.createData?.(input),
      [this.f.email]: input.email,
      [this.f.passwordHash]: input.passwordHash,
    };

    if (this.bulkInsert && this.options.delegate.createManyAndReturn) {
      try {
        const rows = (await this.options.delegate.createManyAndReturn({
          data: [data],
          skipDuplicates: true,
          select: this.selectUser,
        })) as UserRow[];

        const [row] = rows;

        return row ? this.toUser(row) : null;
      } catch (error) {
        if (!isValidationError(error)) throw error;

        this.bulkInsert = false;

        // No error text: a Prisma validation message prints the whole call,
        // the new user's password hash included.
        this.options.logger?.warn(
          'Prisma user store: the skipped insert was refused, so sign-up uses create from now on',
        );
      }
    }

    try {
      const row = (await this.options.delegate.create({
        data,
        select: this.selectUser,
      })) as UserRow;

      return this.toUser(row);
    } catch (error) {
      if (prismaCode(error) === P2002) return null;

      throw error;
    }
  }

  async setPasswordHash(
    id: string,
    passwordHash: string,
    options: { readonly expected?: string | null } = {},
  ): Promise<boolean> {
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

  async changeEmail(
    id: string,
    change: {
      readonly from: NormalizedEmail;
      readonly to: NormalizedEmail;
      readonly clearPassword?: boolean;
    },
  ): Promise<EmailChangeResult> {
    // The old address is in the WHERE of the same UPDATE (a compare-and-set),
    // and the unique index on the email column refuses a taken address.
    try {
      const { count } = await this.options.delegate.updateMany({
        where: this.live({ [this.f.id]: id, [this.f.email]: change.from }),
        data: {
          [this.f.email]: change.to,
          [this.f.emailVerified]: true,
          ...(change.clearPassword ? { [this.f.passwordHash]: null } : {}),
        },
      });

      return count > 0 ? 'changed' : 'stale';
    } catch (error) {
      if (prismaCode(error) === P2002) return 'taken';

      throw error;
    }
  }
}
