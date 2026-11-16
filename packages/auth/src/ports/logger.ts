/**
 * Where the package reports what it cannot return: a breach check that could
 * not run, an audit sink that threw, a stored hash that will not parse. The app
 * decides where these land. Messages and context never carry secrets (tokens,
 * passwords, codes); they may carry user ids.
 */
export interface Logger {
  warn(message: string, context?: Record<string, unknown>): void;
  error(message: string, context?: Record<string, unknown>): void;
}

export const silentLogger: Logger = {
  warn: () => undefined,
  error: () => undefined,
};

/**
 * Counters for outcomes the app should be able to graph: how often the breach
 * check was unavailable, how often each door refused. Names are constants in
 * the package; labels never carry user input.
 */
export interface Metrics {
  count(name: string, labels?: Readonly<Record<string, string>>): void;
}

export const noopMetrics: Metrics = { count: () => undefined };
