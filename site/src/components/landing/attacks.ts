/** The attack to module pairs the landing page shows, each linked to the page that argues it. */
export interface AttackRow {
  readonly attack: string;
  readonly answer: string;
  readonly module: string;
  readonly href: string;
}

export const ATTACKS: readonly AttackRow[] = [
  {
    attack: 'Forging a request from another site',
    answer: 'An Origin allowlist, Sec-Fetch-Site and a signed double-submit token.',
    module: 'http/csrf.ts',
    href: '/auth/learn/csrf/',
  },
  {
    attack: 'Guessing passwords against one account',
    answer: 'Two attempt budgets, reserved before the hash runs. Locks are capped at an hour.',
    module: 'throttle/',
    href: '/auth/learn/brute-force-and-lockout/',
  },
  {
    attack: 'Locking the owner out on purpose',
    answer: "A signed device cookie lets the owner's correct password through a lock.",
    module: 'throttle/device-token.ts',
    href: '/auth/learn/brute-force-and-lockout/',
  },
  {
    attack: 'Finding out who has an account',
    answer: 'The same answer after the same work, for known and unknown addresses.',
    module: 'flows/login.ts',
    href: '/auth/learn/enumeration/',
  },
  {
    attack: 'Cracking a leaked password table',
    answer: 'Argon2id at 19 MiB and t=3, rehashed on login when the parameters change.',
    module: 'password/argon2.ts',
    href: '/auth/learn/passwords/',
  },
  {
    attack: 'Keeping a stolen session after a password change',
    answer: 'A revocation epoch fences out every session issued before it.',
    module: 'session/',
    href: '/auth/learn/revocation-races/',
  },
  {
    attack: 'Claiming an address before its owner signs up',
    answer: 'Verification codes bound to the address they were sent to.',
    module: 'flows/email-verification.ts',
    href: '/auth/learn/email-verification/',
  },
];
