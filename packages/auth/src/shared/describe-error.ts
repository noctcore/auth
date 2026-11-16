/**
 * One line of text for a caught error, for log fields. Only the message: a
 * stack or an error object could carry request data into the app's logs.
 */
export function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
