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

/**
 * Refuses anything but a list (or a value left out). A single string from
 * the environment would otherwise be read character by character.
 */
export function assertList(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value)) throw new AuthConfigError(`${name} must be a list`);
}

/** Refuses anything but a list of strings (or a value left out). */
export function assertStringList(name: string, value: unknown): void {
  assertList(name, value);

  if (Array.isArray(value) && value.some((entry) => typeof entry !== 'string'))
    throw new AuthConfigError(`${name} must be a list of strings`);
}

/** Refuses anything but a string (or a value left out). */
export function assertString(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== 'string') throw new AuthConfigError(`${name} must be a string`);
}

/** Refuses anything but a safe integer of at least 1 (or a value left out). */
export function assertCount(name: string, value: unknown): void {
  if (value === undefined || value === null) return;

  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new AuthConfigError(`${name} must be a whole number of at least 1`);
}
