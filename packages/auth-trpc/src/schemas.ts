/**
 * Zod input and output schemas for the auth procedures, one pair per flow.
 *
 * - Outputs are plain `z.object`s, which strip every key they do not name, so
 *   a field added to the user record later (a password hash, a token hash, an
 *   internal flag) can never reach the client through a procedure that
 *   declares its output. nestjs-trpc requires `output:`; give plain tRPC
 *   procedures one too.
 * - Inputs check shape and size only, and leave the meaning to the core:
 *   whether an email is valid, a password long enough or a code right is the
 *   flow's answer, with its public code. Sizes are capped so a giant string is
 *   refused before any work is done.
 * - The sign-up, sign-in and reset-request answers have one shape whatever
 *   the account's state, so the schema cannot be what tells them apart.
 * - Every input that carries a secret (a password, a code, a token) belongs
 *   to a mutation; `assertNoSecretQueries` checks the router for it.
 */
import { z } from 'zod';

const email = z.string().max(320);
const password = z.string().min(1).max(4096);
const token = z.string().min(1).max(512);
const code = z.string().min(1).max(64);
// `exactOptional` (Zod 4.3+): absent, never `undefined`, so the inferred type
// fits the core's inputs under `exactOptionalPropertyTypes`.
const captchaToken = z.string().max(4096).exactOptional();

export const registerInput = z.object({ email, password, captchaToken });
export const loginInput = z.object({
  email,
  password,
  rememberMe: z.boolean().exactOptional(),
  captchaToken,
});
export const requestPasswordResetInput = z.object({ email, captchaToken });
export const verifyPasswordResetCodeInput = z.object({ email, code });
export const resetPasswordInput = z.object({
  token,
  password,
  secondFactor: code.exactOptional(),
});
export const changePasswordInput = z.object({
  currentPassword: password,
  newPassword: password,
  secondFactor: code.exactOptional(),
});
export const reauthenticateInput = z.object({ password });
export const verifyEmailCodeInput = z.object({ code });
export const verifyEmailLinkInput = z.object({ token });
/** Revoking one session: its public `handle` from the session list, never a store key. */
export const revokeSessionInput = z.object({ handle: z.string().min(1).max(128) });

/** The user as the client sees it: these three keys and nothing else. */
export const userOutput = z.object({
  id: z.string(),
  email: z.string(),
  emailVerified: z.boolean(),
});

/**
 * One of the user's sessions, for a "where you're signed in" page. `handle`
 * is the public handle `sessions.revoke` takes; the store key is not a field,
 * so the output schema strips it even if a procedure returns it.
 */
export const sessionSummaryOutput = z.object({
  handle: z.string(),
  current: z.boolean(),
  createdAt: z.number(),
  lastActiveAt: z.number(),
  expiresAt: z.number(),
  ip: z.string(),
  userAgent: z.string(),
});

export const sessionListOutput = z.array(sessionSummaryOutput);

/** A new session or pre-session: the CSRF token bound to it, for the next mutation. */
export const csrfTokenOutput = z.object({ csrfToken: z.string() });

/** Sign-in: a session, or a second-factor challenge. */
export const loginOutput = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('session'), csrfToken: z.string() }),
  z.object({
    kind: z.literal('challenge'),
    challenge: z.string(),
    methods: z.array(z.string()).readonly(),
  }),
]);

/**
 * Sign-up and reset request: the same answer for a new address and a taken
 * one. `csrfToken` is set only when the app opted into `autoLogin`.
 */
export const acceptedOutput = z.object({
  status: z.literal('accepted'),
  csrfToken: z.string().exactOptional(),
});

export const resetTicketOutput = z.object({ ticket: z.string(), expiresAt: z.number() });
export const revokedOutput = z.object({ revoked: z.boolean() });
export const verificationRequestOutput = z.object({ sent: z.boolean() });
