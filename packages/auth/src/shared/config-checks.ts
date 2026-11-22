/**
 * Startup checks for option values that often come from the environment as
 * strings or as `Number(undefined)`. A string "false" is truthy and a `NaN`
 * limit fails every comparison, so each would quietly turn a check off. A
 * value left out (undefined or null) passes: the caller's `??` gives the
 * default.
 */
import { AuthConfigError } from './errors';

/** Refuses anything but `true` or `false` (or a value left out). */
export function assertBoolean(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== 'boolean') throw new AuthConfigError(`${name} must be true or false`);
}

/** Refuses anything but a safe integer of at least 1 (or a value left out). */
export function assertCount(name: string, value: unknown): void {
  if (value === undefined || value === null) return;

  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new AuthConfigError(`${name} must be a whole number of at least 1`);
}
