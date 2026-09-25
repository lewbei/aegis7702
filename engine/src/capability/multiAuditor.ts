import { Address, Hex, PublicClient } from "viem";
import { Capability } from "./types.js";
import { ReachabilityExplorer, ExploreResult, ActionProvider, InvariantOracle } from "../search/explorer.js";
import { AnvilRpcClient } from "../baseline/greedyRunner.js";

export type CapabilitySet = Capability[];

export interface MultiAuditMetrics {
  totalEvaluated: number;
  totalVisitedStates: number;
  totalEvmCalls: number;
  totalSnapshots: number;
  totalBacktracks: number;
  elapsedMs: number;
}

export type MultiAuditResult =
  | {
      status: "PORTFOLIO_NO_MODELED_LOSS";
      evaluatedCount: number;
      metrics: MultiAuditMetrics;
      message: string;
    }
  | {
      status: "FOUND_RESIDUAL_LOSS";
      evaluatedCount: number;
      violatingCapability: Capability;
      counterexample: ExploreResult & { status: "FOUND_LOSS" };
      metrics: MultiAuditMetrics;
      message: string;
    }
  | {
      status: "PORTFOLIO_INCOMPLETE";
      evaluatedCount: number;
      unmodeledCapabilities: Capability[];
      unmodeledReasons: string[];
      metrics: MultiAuditMetrics;
      message: string;
    };

/**
 * MultiCapabilityAuditor evaluates an account's complete portfolio of capabilities
 * on a given EVM state (e.g. state s_R reached after executing a primary recovery plan).
 *
 * Each capability is evaluated within an isolated EVM snapshot to prevent state
 * mutations of one verification from contaminating subsequent evaluations.
 *
 * Strict Invariant:
 *   - Empty capabilityPortfolio => PORTFOLIO_INCOMPLETE (Zero capabilities verified != SAFE)
 *   - Any capability yielding FOUND_LOSS => FOUND_RESIDUAL_LOSS
 *   - Else any capability yielding UNMODELED => PORTFOLIO_INCOMPLETE (UNMODELED != SAFE)
 *   - Else (all modeled and explore without loss) => PORTFOLIO_NO_MODELED_LOSS
 */
export class MultiCapabilityAuditor {
  constructor(
    private publicClient: PublicClient,
    private rpcClient: AnvilRpcClient
  ) {}

  async audit(
    capabilityPortfolio: CapabilitySet,
    attacker: Address,
    options?: {
      maxDepth?: number;
      actionProviderFactory?: (cap: Capability) => ActionProvider | undefined;
      invariantOracleFactory?: (cap: Capability) => InvariantOracle | undefined;
    }
  ): Promise<MultiAuditResult> {
    const startTime = Date.now();

    if (capabilityPortfolio.length === 0) {
      return {
        status: "PORTFOLIO_INCOMPLETE",
        evaluatedCount: 0,
        unmodeledCapabilities: [],
        unmodeledReasons: [
          "Capability portfolio is empty; no security verification was performed"
        ],
        metrics: {
          totalEvaluated: 0,
          totalVisitedStates: 0,
          totalEvmCalls: 0,
          totalSnapshots: 0,
          totalBacktracks: 0,
          elapsedMs: Date.now() - startTime
        },
        message:
          "Portfolio audit incomplete: no capabilities were supplied for verification"
      };
    }

    let totalVisited = 0;
    let totalCalls = 0;
    let totalSnapshots = 0;
    let totalBacktracks = 0;

    const wrappedRpc: AnvilRpcClient = {
      request: async (args: { method: string; params?: any[] }) => {
        if (args.method === "eth_sendTransaction") totalCalls++;
        if (args.method === "evm_snapshot") totalSnapshots++;
        if (args.method === "evm_revert") totalBacktracks++;
        return await this.rpcClient.request(args as any);
      }
    };

    let evaluatedCount = 0;
    const unmodeledCaps: Capability[] = [];
    const unmodeledReasons: string[] = [];

    for (const capability of capabilityPortfolio) {
      evaluatedCount++;
      const snap = (await this.rpcClient.request({ method: "evm_snapshot" } as any)) as Hex;

      try {
        const actionProvider = options?.actionProviderFactory ? options.actionProviderFactory(capability) : undefined;
        const invariantOracle = options?.invariantOracleFactory ? options.invariantOracleFactory(capability) : undefined;

        const explorer = new ReachabilityExplorer(
          this.publicClient,
          wrappedRpc,
          {
            maxDepth: options?.maxDepth ?? 3,
            actionProvider,
            invariantOracle
          }
        );

        const effectiveActor =
          capability.kind === "PERMIT2_ALLOWANCE" || capability.kind === "PERMIT2_SIGNATURE"
            ? capability.spender
            : attacker;

        const exploreResult = await explorer.explore(capability, effectiveActor);
        totalVisited += exploreResult.visitedStates;

        if (exploreResult.status === "FOUND_LOSS") {
          return {
            status: "FOUND_RESIDUAL_LOSS",
            evaluatedCount,
            violatingCapability: capability,
            counterexample: exploreResult,
            metrics: {
              totalEvaluated: evaluatedCount,
              totalVisitedStates: totalVisited,
              totalEvmCalls: totalCalls,
              totalSnapshots,
              totalBacktracks,
              elapsedMs: Date.now() - startTime
            },
            message: `Account portfolio audit discovered reachable residual loss in capability (${capability.kind}) under state s_R`
          };
        }

        if (exploreResult.status === "UNMODELED") {
          unmodeledCaps.push(capability);
          unmodeledReasons.push(exploreResult.reason);
        }
      } finally {
        await this.rpcClient.request({ method: "evm_revert", params: [snap] } as any);
      }
    }

    if (unmodeledCaps.length > 0) {
      return {
        status: "PORTFOLIO_INCOMPLETE",
        evaluatedCount,
        unmodeledCapabilities: unmodeledCaps,
        unmodeledReasons,
        metrics: {
          totalEvaluated: evaluatedCount,
          totalVisitedStates: totalVisited,
          totalEvmCalls: totalCalls,
          totalSnapshots,
          totalBacktracks,
          elapsedMs: Date.now() - startTime
        },
        message: `Account portfolio audit incomplete: ${unmodeledCaps.length} capability(ies) have unmodeled action semantics and could not be verified on current state`
      };
    }

    return {
      status: "PORTFOLIO_NO_MODELED_LOSS",
      evaluatedCount,
      metrics: {
        totalEvaluated: evaluatedCount,
        totalVisitedStates: totalVisited,
        totalEvmCalls: totalCalls,
        totalSnapshots,
        totalBacktracks,
        elapsedMs: Date.now() - startTime
      },
      message: `Account portfolio audit completed: no modeled loss paths discovered across all ${evaluatedCount} verified capability(ies) on current state`
    };
  }
}
