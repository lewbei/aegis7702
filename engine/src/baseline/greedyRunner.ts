import {
  PublicClient,
  Address,
  Hex,
  Hash
} from "viem";
import { Action, Capability } from "../capability/types.js";
import {
  ActionProvider,
  InvariantOracle,
  ERC20LossOracle,
  BuiltinCapabilityActionProvider
} from "../search/explorer.js";

export interface AnvilRpcClient {
  request: (args: { method: string; params?: any[] }) => Promise<any>;
}

export interface BaselineRunMetrics {
  status: "FOUND_LOSS" | "NO_MODELED_LOSS" | "REVERT_ERROR" | "UNMODELED";
  depth: number;
  visitedStates: number;
  evmCalls: number;
  snapshotCount: number;
  revertCount: number;
  elapsedMs: number;
  lossFound?: bigint;
  trace: Action[];
  error?: string;
}

/**
 * Baseline B1: State-Aware Greedy Linear Forward Runner (No Backtracking)
 *
 * Fully understands capability semantics (EIP-7702 Type-4 relay, Permit2),
 * but executes candidate actions linearly forward without EVM state snapshots
 * (evm_snapshot / evm_revert) or depth-first search backtracking.
 */
export class StateAwareGreedyRunner {
  private visitedStates: number = 0;
  private evmCalls: number = 0;

  constructor(
    private publicClient: PublicClient,
    private rpcClient: AnvilRpcClient,
    private actionProvider: ActionProvider = new BuiltinCapabilityActionProvider(),
    private invariantOracle: InvariantOracle = new ERC20LossOracle(),
    private maxDepth: number = 3
  ) {}

  async run(capability: Capability, actor: Address): Promise<BaselineRunMetrics> {
    const startTime = Date.now();
    this.visitedStates = 0;
    this.evmCalls = 0;
    const initialContext = await this.invariantOracle.snapshotInitial(capability, this.publicClient);

    const trace: Action[] = [];
    let currentDepth = 0;

    while (currentDepth < this.maxDepth) {
      this.visitedStates++;
      const enumeration = await this.actionProvider.enumerateActions(capability, this.publicClient, actor);

      if (enumeration.status === "UNMODELED") {
        return {
          status: "UNMODELED",
          depth: currentDepth,
          visitedStates: this.visitedStates,
          evmCalls: this.evmCalls,
          snapshotCount: 0,
          revertCount: 0,
          elapsedMs: Date.now() - startTime,
          trace,
          error: enumeration.reason
        };
      }

      if (enumeration.actions.length === 0) {
        return {
          status: "NO_MODELED_LOSS",
          depth: currentDepth,
          visitedStates: this.visitedStates,
          evmCalls: this.evmCalls,
          snapshotCount: 0,
          revertCount: 0,
          elapsedMs: Date.now() - startTime,
          trace
        };
      }

      // Greedy linear choice: pick the first candidate action without backtracking capability
      const action = enumeration.actions[0];
      trace.push(action);
      this.evmCalls++;

      try {
        await this.executeAction(action);
      } catch (err: any) {
        // Forward-only linear execution has NO snapshot rollback.
        // If the candidate action reverts, the greedy execution halts immediately.
        return {
          status: "REVERT_ERROR",
          depth: currentDepth + 1,
          visitedStates: this.visitedStates,
          evmCalls: this.evmCalls,
          snapshotCount: 0,
          revertCount: 0,
          elapsedMs: Date.now() - startTime,
          trace,
          error: err.message || String(err)
        };
      }

      // Check invariant
      const violation = await this.invariantOracle.evaluate(initialContext, capability, this.publicClient);
      if (violation && violation.lossAmount > 0n) {
        return {
          status: "FOUND_LOSS",
          depth: currentDepth + 1,
          visitedStates: this.visitedStates,
          evmCalls: this.evmCalls,
          snapshotCount: 0,
          revertCount: 0,
          elapsedMs: Date.now() - startTime,
          lossFound: violation.lossAmount,
          trace
        };
      }

      currentDepth++;
    }

    return {
      status: "NO_MODELED_LOSS",
      depth: currentDepth,
      visitedStates: this.visitedStates,
      evmCalls: this.evmCalls,
      snapshotCount: 0,
      revertCount: 0,
      elapsedMs: Date.now() - startTime,
      trace
    };
  }

  // Single-Trace Replay Verifier: Replays the specific historical exploit trace against post-recovery state s_R
  async replayTrace(
    trace: Action[],
    initialContext: any,
    capability: Capability
  ): Promise<{ status: "TRACE_BLOCKED" | "TRACE_EXPLOIT_SUCCEEDED"; error?: string }> {
    try {
      for (const action of trace) {
        this.evmCalls++;
        await this.executeAction(action);
      }
      const violation = await this.invariantOracle.evaluate(initialContext, capability, this.publicClient);
      if (violation && violation.lossAmount > 0n) {
        return { status: "TRACE_EXPLOIT_SUCCEEDED" };
      }
      return { status: "TRACE_BLOCKED" };
    } catch (err: any) {
      return { status: "TRACE_BLOCKED", error: err.message || String(err) };
    }
  }

  private async executeAction(action: Action): Promise<void> {
    await this.rpcClient.request({ method: "anvil_impersonateAccount", params: [action.actor] });
    await this.rpcClient.request({ method: "anvil_setBalance", params: [action.actor, "0xde0b6b3a7640000"] });

    const txParams: any = {
      from: action.actor,
      to: action.target,
      data: action.calldata,
      gas: "0x100000"
    };
    if (action.authorizationList && action.authorizationList.length > 0) {
      txParams.authorizationList = action.authorizationList;
    }

    const txHash: Hash = await this.rpcClient.request({
      method: "eth_sendTransaction",
      params: [txParams]
    });

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
    if (receipt.status !== "success") {
      throw new Error(`Transaction ${action.id} reverted on-chain (status: ${receipt.status})`);
    }
  }
}
