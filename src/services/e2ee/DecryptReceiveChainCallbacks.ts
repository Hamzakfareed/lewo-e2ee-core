interface ConversationStateLike {
  chainKeyReceive: string;
  receiveCounter: number;
  lastUpdated: number;
  x3dhEphemeralKey?: string;
  x3dhUsedOPKId?: number;
}

export interface AdvanceReceiveDeps<TState extends ConversationStateLike> {
  state: TState;
  isFutureMessage: boolean;
  chainKeyToUse: string;
  messageCounter: number;
  conversationId: string;
  setState: (cid: string, st: TState) => void;
  saveStates: () => Promise<void>;
  deriveNextChainKey: (k: string) => string;
  /**
   * Force the skipped-key store to disk. `prepareFutureMessage` parks the gap
   * keys through the store's DEBOUNCED save, but `saveStates()` below persists
   * the advanced receive chain immediately. Anything that drops in-memory state
   * inside that window — process kill, account switch, a reload from storage —
   * leaves the chain past counters whose keys were never written, and chains
   * only derive forward: those messages are then unrecoverable.
   *
   * Same invariant the group lane enforces: keys must be durable BEFORE the
   * chain advances.
   */
  flushSkippedKeys?: () => Promise<void>;
}

/**
 * Returns an `advanceReceiveAndPersist` closure: on a successful
 * decrypt, advance the receive chain forward (either from
 * `chainKeyToUse` for a future-message decrypt, or from the current
 * `state.chainKeyReceive` for the in-order case), bump the receive
 * counter, refresh `lastUpdated`, opportunistically clear stale
 * X3DH liveness fields once the responder side has consumed at
 * least one in-band message, and persist.
 *
 * Pulled out of `E2EEncryptionService.decryptMessage` so the
 * orchestrator stays focused on cipher branching; the chain
 * advancement bookkeeping lives here.
 */
export function makeAdvanceReceiveAndPersist<TState extends ConversationStateLike>(
  deps: AdvanceReceiveDeps<TState>,
): () => Promise<void> {
  return async () => {
    if (deps.isFutureMessage) {
      // Ordering is load-bearing: park durably, THEN advance. A crash between the
      // two is idempotent — the chain has not moved, so a retry re-derives the
      // identical keys. The reverse order loses them for good.
      await deps.flushSkippedKeys?.();
      deps.state.chainKeyReceive = deps.deriveNextChainKey(deps.chainKeyToUse);
      deps.state.receiveCounter = deps.messageCounter + 1;
    } else {
      deps.state.chainKeyReceive = deps.deriveNextChainKey(deps.state.chainKeyReceive);
      deps.state.receiveCounter++;
    }
    deps.state.lastUpdated = Date.now();
    if (
      (deps.state.x3dhEphemeralKey || deps.state.x3dhUsedOPKId) &&
      deps.state.receiveCounter > 1
    ) {
      deps.state.x3dhEphemeralKey = undefined;
      deps.state.x3dhUsedOPKId = undefined;
    }
    deps.setState(deps.conversationId, deps.state);
    await deps.saveStates();
  };
}
