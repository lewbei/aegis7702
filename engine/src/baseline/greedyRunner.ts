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
  BuiltinCapabilityActionProvider,
  SearchTelemetry,
  TransactionRevertedError,
  isEvmRevertError
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
  telemetry: SearchTelemetry;
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
    const telemetry: SearchTelemetry = {
      candidateCountsByDepth: {},
      maxBranchingFactor: 0,
      totalGeneratedActions: 0,
      successfulActions: 0,
      revertingActions: 0
    };
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
          telemetry,
          error: enumeration.reason
        };
      }

      telemetry.candidateCountsByDepth[currentDepth] = (telemetry.candidateCountsByDepth[currentDepth] ?? 0) + enumeration.actions.length;
      telemetry.maxBranchingFactor = Math.max(telemetry.maxBranchingFactor, enumeration.actions.length);
      telemetry.totalGeneratedActions += enumeration.actions.length;

      if (enumeration.actions.length === 0) {
        return {
          status: "NO_MODELED_LOSS",
          depth: currentDepth,
          visitedStates: this.visitedStates,
          evmCalls: this.evmCalls,
          snapshotCount: 0,
          revertCount: 0,
          elapsedMs: Date.now() - startTime,
          trace,
          telemetry
        };
      }

      // Greedy linear choice: pick the first candidate action without backtracking capability
      const action = enumeration.actions[0];
      trace.push(action);
      this.evmCalls++;

      try {
        await this.executeAction(action);
        telemetry.successfulActions++;
      } catch (err: any) {
        telemetry.revertingActions++;
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
          telemetry,
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
          trace,
          telemetry
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
      trace,
      telemetry
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
      if (err instanceof TransactionRevertedError || isEvmRevertError(err)) {
        return { status: "TRACE_BLOCKED", error: err.message || String(err) };
      }
      throw err; // Fail-closed on infrastructure / RPC failure
    }
  }

  private async executeAction(action: Action): Promise<void> {
    try {
      await this.rpcClient.request({ method: "anvil_impersonateAccount", params: [action.actor] });
      await this.rpcClient.request({ method: "anvil_setBalance", params: [action.actor, "0xde0b6b3a7640000"] });
    } catch (err: any) {
      throw new Error(`RPC infrastructure error during actor preparation for [${action.id}]: ${err.message || err}`);
    }

    const txParams: any = {
      from: action.actor,
      to: action.target,
      data: action.calldata,
      gas: "0x1c9c380" // 30M gas (standard Anvil block gas limit)
    };
    if (action.authorizationList && action.authorizationList.length > 0) {
      txParams.authorizationList = action.authorizationList;
    }

    let txHash: Hash;
    try {
      txHash = await this.rpcClient.request({
        method: "eth_sendTransaction",
        params: [txParams]
      });
    } catch (err: any) {
      if (isEvmRevertError(err)) {
        throw new TransactionRevertedError(action.id, "reverted", err.message);
      }
      throw new Error(`RPC transport failure dispatching transaction for [${action.id}]: ${err.message || err}`);
    }

    let receipt: any;
    try {
      receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });
    } catch (err: any) {
      throw new Error(`RPC timeout or transport error waiting for receipt [${action.id}]: ${err.message || err}`);
    }

    if (receipt.status !== "success") {
      throw new TransactionRevertedError(action.id, receipt.status);
    }
  }
}
