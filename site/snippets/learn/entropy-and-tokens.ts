import { randomUUID } from 'node:crypto';
import { generateToken, isTokenShape } from '@noctcore/auth';

// Every bearer secret the package mints: 32 bytes from
// crypto.getRandomValues, written as 64 lowercase hex characters.
export const token = generateToken();

// A filter, not a check: the wrong shape is unknown without a store lookup.
export const shapes = {
  token: isTokenShape(token), // true
  upperCase: isTokenShape(token.toUpperCase()), // false
  uuid: isTokenShape(randomUUID()), // false: an identifier, not a secret
};

// The server secret is counted in bytes, not randomness. Generate it from a
// secure source, once, and keep it out of the repository:
//   openssl rand -hex 32
const value = process.env.AUTH_SECRET;

if (!value) throw new Error('Set AUTH_SECRET');

export const secret = value;
