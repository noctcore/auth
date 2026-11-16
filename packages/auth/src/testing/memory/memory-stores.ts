/**
 * In-memory stores with the same guarantees the conformance suite asks of real
 * adapters (they pass it, see tests/conformance.test.ts). For unit tests and
 * prototypes only: nothing survives a restart and nothing is shared between
 * processes.
 */
import { MemoryCounterStore } from './counter-store';
import { MemorySessionStore } from './session-store';
import { MemoryTokenStore } from './token-store';
import { MemoryUserStore } from './user-store';
import { systemClock, type Clock } from '../../ports/clock';

export interface MemoryStores {
  readonly users: MemoryUserStore;
  readonly sessions: MemorySessionStore;
  readonly tokens: MemoryTokenStore;
  readonly counters: MemoryCounterStore;
}

export function memoryStores(clock: Clock = systemClock): MemoryStores {
  return {
    users: new MemoryUserStore(clock),
    sessions: new MemorySessionStore(clock),
    tokens: new MemoryTokenStore(),
    counters: new MemoryCounterStore(clock),
  };
}
