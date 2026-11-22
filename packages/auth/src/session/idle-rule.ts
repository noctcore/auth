/**
 * The rule between a session's idle timeout and the touch interval, shared by
 * the session manager (startup and mint) and the legacy session wrapper
 * (adoption), so both read it the same way.
 */
import { AuthConfigError } from '../shared/errors';

/**
 * A session must be touched before it can go idle: with an idle timeout no
 * longer than the touch interval, a session used steadily is never touched and
 * is refused as idle while its user is active.
 */
export const idleOutlastsTouch = (idleMs: number, touchIntervalMs: number): boolean =>
  idleMs > touchIntervalMs;

/** Throws the configuration error for an idle timeout that breaks `idleOutlastsTouch`. */
export function assertIdleOutlastsTouch(idleMs: number, touchIntervalMs: number): void {
  if (!idleOutlastsTouch(idleMs, touchIntervalMs)) {
    throw new AuthConfigError('session.touchInterval must be shorter than the idle timeout');
  }
}
