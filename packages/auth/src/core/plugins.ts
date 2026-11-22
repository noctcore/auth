/**
 * Plugins: how they are declared, checked at startup and exposed. Each plugin's
 * flows live under its own id (`auth.twoFactor.verify`), so two plugins, or a
 * plugin and a core flow, can never shadow one another.
 */
import type { AuthPlugin } from './config';
import type { PluginContext } from './plugin-context';
import type { AuthUser } from '../ports/stores';
import { assertFunction, assertList, assertStringList } from '../shared/config-checks';
import { AuthConfigError } from '../shared/errors';

type UnionToIntersection<T> = (T extends unknown ? (value: T) => void : never) extends (
  value: infer I,
) => void
  ? I
  : never;

/** `{ [plugin id]: plugin flows }` for the configured plugins. */
export type PluginFlows<P extends readonly AuthPlugin[]> = UnionToIntersection<
  P[number] extends infer Plugin
    ? Plugin extends AuthPlugin<infer Id, infer F>
      ? { readonly [K in Id]: F }
      : never
    : never
>;

/** Defines a plugin with its id and flows typed. */
export function definePlugin<const Id extends string, F extends object>(
  plugin: AuthPlugin<Id, F>,
): AuthPlugin<Id, F> {
  return plugin;
}

/**
 * Refuses a `plugins` that is not a list, an entry that is not a plugin,
 * duplicate ids and plugins whose required config is missing.
 */
export function checkPlugins(
  plugins: readonly AuthPlugin[],
  available: { readonly captcha: boolean },
): void {
  assertList('plugins', plugins);

  const seen = new Set<string>();

  for (const entry of plugins as readonly unknown[]) {
    if (typeof entry !== 'object' || entry === null)
      throw new AuthConfigError('plugins must hold plugins, such as twoFactor({ ... })');

    const plugin = entry as AuthPlugin;

    if (typeof plugin.id !== 'string' || plugin.id.length === 0)
      throw new AuthConfigError('Every plugin needs an id');

    assertFunction(`Plugin ${plugin.id} flows`, plugin.flows);
    assertStringList(`Plugin ${plugin.id} requires`, plugin.requires);

    if (seen.has(plugin.id)) throw new AuthConfigError(`Duplicate plugin id: ${plugin.id}`);

    seen.add(plugin.id);

    if (plugin.requires?.includes('captcha') && !available.captcha)
      throw new AuthConfigError(`Plugin ${plugin.id} requires a captcha`);
  }
}

/** Each plugin's flows, keyed by its id; an id that names a core flow is refused. */
export function namespacePluginFlows<U extends AuthUser, A>(
  plugins: readonly AuthPlugin[],
  coreFlows: object,
  context: PluginContext<U, A>,
): Record<string, object> {
  const namespaced: Record<string, object> = {};

  for (const plugin of plugins) {
    if (plugin.id in coreFlows)
      throw new AuthConfigError(`Plugin id ${plugin.id} collides with a core flow`);
    if (plugin.flows) namespaced[plugin.id] = plugin.flows(context);
  }

  return namespaced;
}
