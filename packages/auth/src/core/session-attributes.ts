/**
 * The attributes a new session is stamped with: the ones it inherits (on a
 * step-up), merged with what every `sessionAttributes` hook adds, in order,
 * then checked against the app's schema.
 */
import type { HookLists } from './hooks';
import type { IssueOptions } from './plugin-context';
import type { Logger } from '../ports/logger';
import type { AuthUser } from '../ports/stores';
import { describeError } from '../shared/describe-error';
import { fail, ok, type AuthResult } from '../shared/errors';
import type { AttributeSchema } from '../session/session-manager';

export interface AttributeSources<U extends AuthUser, A> {
  readonly hooks: HookLists<U, A>;
  readonly schema: AttributeSchema<A> | undefined;
  readonly logger: Logger;
}

export async function resolveSessionAttributes<U extends AuthUser, A>(
  sources: AttributeSources<U, A>,
  user: U,
  options: IssueOptions<A>,
): Promise<AuthResult<A>> {
  const inherited = options.inherit?.attributes;
  let merged: Record<string, unknown> = { ...(inherited as Record<string, unknown> | undefined) };

  for (const hook of sources.hooks.sessionAttributes) {
    const added = await hook({ user, via: options.via, inherited });

    merged = { ...merged, ...added };
  }

  try {
    return ok(sources.schema ? sources.schema.parse(merged) : (merged as A));
  } catch (error) {
    // A hook produced attributes the schema refuses: a bug in the app, never
    // something to mint a half-stamped session for.
    sources.logger.error('Session attributes failed the schema at issue time', {
      userId: user.id,
      error: describeError(error),
    });

    return fail('forbidden', 'invalid_session_attributes');
  }
}
