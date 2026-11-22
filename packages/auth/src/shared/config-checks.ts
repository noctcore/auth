/**
 * Startup checks for option values that often come from the environment as
 * strings or as `Number(undefined)`. A string "false" is truthy and a `NaN`
 * limit fails every comparison, so each would quietly turn a check off. A
 * value left out (undefined or null) passes: the caller's `??` gives the
 * default.
 */
import { toMilliseconds, type Duration } from './duration';
import { AuthConfigError } from './errors';

/** Refuses a required option that was left out (undefined or null). */
export function assertRequired(name: string, value: unknown): void {
  if (value === undefined || value === null) throw new AuthConfigError(`${name} is required`);
}

/** Refuses anything but `true` or `false` (or a value left out). */
export function assertBoolean(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== 'boolean') throw new AuthConfigError(`${name} must be true or false`);
}

/**
 * Refuses anything but a list without empty slots (or a value left out). A
 * single string from the environment would otherwise be read character by
 * character, and `.some`, `.every` and `.map` skip an empty slot, so a check
 * written with them would pass a hole that a later loop reads as undefined.
 */
export function assertList(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value)) throw new AuthConfigError(`${name} must be a list`);

  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index))
      throw new AuthConfigError(`${name} must not have empty slots`);
  }
}

/** Refuses anything but a list of strings (or a value left out). */
export function assertStringList(name: string, value: unknown): void {
  assertList(name, value);

  if (Array.isArray(value) && !Array.from(value).every((entry) => typeof entry === 'string'))
    throw new AuthConfigError(`${name} must be a list of strings`);
}

/** Refuses anything but a string (or a value left out). */
export function assertString(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== 'string') throw new AuthConfigError(`${name} must be a string`);
}

/** Refuses anything but a function (or a value left out). */
export function assertFunction(name: string, value: unknown): void {
  if (value === undefined || value === null) return;
  if (typeof value !== 'function') throw new AuthConfigError(`${name} must be a function`);
}

/** Refuses anything but one of `allowed` (or a value left out). */
export function assertOneOf(name: string, value: unknown, allowed: readonly string[]): void {
  if (value === undefined || value === null) return;
  if (typeof value === 'string' && allowed.includes(value)) return;

  throw new AuthConfigError(`${name} must be ${allowed.map((entry) => `'${entry}'`).join(' or ')}`);
}

/** Refuses anything but a safe integer of at least 1 (or a value left out). */
export function assertCount(name: string, value: unknown): void {
  if (value === undefined || value === null) return;

  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1)
    throw new AuthConfigError(`${name} must be a whole number of at least 1`);
}

/** Refuses anything but a finite number above zero (or a value left out). */
export function assertPositive(name: string, value: unknown): void {
  if (value === undefined || value === null) return;

  if (typeof value !== 'number' || !Number.isFinite(value) || !(value > 0))
    throw new AuthConfigError(`${name} must be a number above zero`);
}

/**
 * The option in milliseconds, or `fallback` when it is left out (undefined
 * or null). A value that is not a `Duration` (a typo such as `'15 min'`,
 * `NaN`, a negative number) is refused with the option's name instead of
 * the parser's bare `TypeError`.
 */
export function configMilliseconds(name: string, value: unknown, fallback: Duration): number {
  const duration = value === undefined || value === null ? fallback : value;

  try {
    return toMilliseconds(duration as Duration);
  } catch {
    throw new AuthConfigError(`${name} must be a duration, such as '15m' or a number of seconds`);
  }
}
