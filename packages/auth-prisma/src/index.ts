/**
 * @noctcore/auth-prisma: Prisma user, one-time token and two-factor stores for @noctcore/auth.
 *
 * The stores take your client's model delegates (`prisma.user`,
 * `prisma.authToken`), not a client type, because Prisma 7 generates the client
 * into your app. Any model with the mapped fields works; the token model (and
 * the two-factor plugin's tables) to copy are in `prisma/auth.prisma`.
 *
 * Every write that must not happen twice is a single conditional statement:
 * unique violations become `null` (never thrown), guarded updates use
 * `updateMany` with the guard in `where`, consume is a delete that returns the
 * row, and the attempt cap is an update whose `where` carries the cap.
 */
import type { AuthUser } from '@noctcore/auth';
import type { PrismaAuthTokenDelegate } from './delegates';
import { PrismaTokenStore } from './token-store';
import { PrismaUserStore, type PrismaUserStoreOptions } from './user-store';

export type {
  PrismaAuthTokenDelegate,
  PrismaTwoFactorDelegates,
  PrismaUserDelegate,
} from './delegates';
export { PrismaTokenStore } from './token-store';
export { PrismaTwoFactorStore } from './two-factor-store';
export { PrismaUserStore, type PrismaUserStoreOptions, type UserFields } from './user-store';

/** Both Prisma stores. */
export function prismaStores<U extends AuthUser = AuthUser>(
  options: PrismaUserStoreOptions<U> & { readonly tokenDelegate: PrismaAuthTokenDelegate },
) {
  return {
    users: new PrismaUserStore<U>(options),
    tokens: new PrismaTokenStore(options.tokenDelegate),
  };
}
