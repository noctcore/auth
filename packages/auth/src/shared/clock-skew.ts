/**
 * How far in the future a device token's `issuedAt` may lie and still verify:
 * a minute of clock skew between servers. Anything that bounds such a token's
 * life (the session store's epoch TTL) needs this much margin on top of the
 * max age, and so does a trusted device, whose expiry comes from the clock of
 * the server that trusted it.
 */
export const DEVICE_CLOCK_SKEW_MS = 60_000;
