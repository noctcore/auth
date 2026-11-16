/**
 * Time source, injectable so tests move time instead of sleeping and so every
 * expiry decision in a request reads the same clock.
 */
export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };
