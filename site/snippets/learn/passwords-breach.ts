import { pwnedPasswords, type Logger } from '@noctcore/auth';
import { argon2id } from '@noctcore/auth/argon2';
import { hashing, policy } from './passwords';

const logger: Logger = {
  warn: (message, context) => console.warn(message, context),
  error: (message, context) => console.error(message, context),
};

// Fails open: an unavailable check accepts the password. onResult says why,
// so a timeout shows apart from a changed response format. The outcome
// never holds the password, its hash or the five-character prefix.
const breachCheck = pwnedPasswords({
  onResult(outcome) {
    if (outcome.verdict === 'unavailable') {
      logger.warn('Breach check unavailable', { reason: outcome.reason });
    }
  },
  // Where a hook that throws is reported. Silent by default.
  logger,
});

export const password = { hasher: argon2id(hashing), policy, breachCheck };
