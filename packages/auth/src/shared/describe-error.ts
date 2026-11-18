/**
 * One line of text for a caught error, for log fields. Only the message: a
 * stack or an error object could carry request data into the app's logs.
 * Never throws, so it is safe inside a catch: a value without a usable
 * `toString` (a null-prototype object, a throwing getter) reads as a fixed
 * placeholder.
 */
export function describeError(error: unknown): string {
  try {
    return error instanceof Error ? error.message : String(error);
  } catch {
    return 'unprintable error';
  }
}
