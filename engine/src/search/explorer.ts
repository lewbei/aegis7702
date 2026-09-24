import {
  PublicClient,
  formatUnits,
  Hex,
  Hash
} from "viem";
import { Action, Counterexample, Capability, CapabilityKind, EIP7702Capability } from "../capability/types.js";
import { Permit2AllowanceSemantics } from "../semantics/permit2Allowance.js";
import { Permit2SignatureSemantics } from "../semantics/permit2Signature.js";
import { EIP7702Semantics } from "../semantics/eip7702.js";
import { ERC20_ABI } from "../capability/abis.js";

export interface AnvilRpcClient {
  request(args: { method: string; params?: any[] }): Promise<any>;
}

export type ActionEnumeration =
  | {
      status: "MODELED";
      actions: Action[];
    }
  | {
      status: "UNMODELED";
      reason: string;
    };

export interface ActionProvider {
  enumerateActions(
    capability: Capability,
    publicClient: PublicClient,
    attacker: `0x${string}`
  ): Promise<ActionEnumeration>;
}

export interface InvariantViolation {
  lossAmount: bigint;
  token?: `0x${string}`;
  symbol: string;
  amount: string;
  formatted: string;
  currentBalanceFormatted?: string;
}

export type LossObservation = InvariantViolation;

export interface InvariantOracle<TContext = any> {
  snapshotInitial(
    capability: Capability,
    publicClient: PublicClient
  ): Promise<TContext>;

  evaluate(
    initialContext: TContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<InvariantViolation | null>;

  formatCurrentState?(
    initialContext: TContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<string>;
}

export type LossOracle<TContext = any> = InvariantOracle<TContext>;

export interface ERC20LossContext {
  token: `0x${string}`;
  symbol: string;
  decimals: number;
  initialBalance: bigint;
}

/**
 * Built-in Capability Action Provider: encapsulates frozen action generation
 * for PERMIT2_ALLOWANCE, PERMIT2_SIGNATURE, and EIP-7702 canonical selector families.
 * Formally distinguishes between modeled interfaces and explicit UNMODELED abstentions.
 */
export class BuiltinCapabilityActionProvider implements ActionProvider {
  async enumerateActions(
    capability: Capability,
    publicClient: PublicClient,
    attacker: `0x${string}`
  ): Promise<ActionEnumeration> {
    if (capability.kind === "PERMIT2_ALLOWANCE") {
      const actions = await Permit2AllowanceSemantics.enumerateActions(capability, publicClient, attacker);
      return { status: "MODELED", actions };
    }

    if (capability.kind === "PERMIT2_SIGNATURE") {
      const actions = await Permit2SignatureSemantics.enumerateActions(capability, publicClient, attacker);
      return { status: "MODELED", actions };
    }

    if (capability.kind === "EIP7702") {
      return EIP7702Semantics.enumerateActions(capability as EIP7702Capability, publicClient, attacker);
    }

    return {
      status: "UNMODELED",
      reason: `Unsupported capability kind: ${(capability as any).kind}`
    };
  }
}

/**
 * Canonical ERC-20 Loss Oracle: detects whether a victim account's tracked token balance
 * strictly decreases following an executed action path.
 */
export class ERC20LossOracle implements InvariantOracle<ERC20LossContext> {
  async snapshotInitial(
    capability: Capability,
    publicClient: PublicClient
  ): Promise<ERC20LossContext> {
    const owner = capability.owner;
    const token = this.getTokenFromCapability(capability);

    const initialBalance: bigint = await publicClient.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [owner]
    });

    const symbol: string = await publicClient.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: "symbol"
    });

    const decimals: number = await publicClient.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: "decimals"
    });

    return { token, symbol, decimals, initialBalance };
  }

  async evaluate(
    initialContext: ERC20LossContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<InvariantViolation | null> {
    const currentBalance: bigint = await publicClient.readContract({
      address: initialContext.token,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [capability.owner]
    });

    if (currentBalance < initialContext.initialBalance) {
      const lossAmount = initialContext.initialBalance - currentBalance;
      return {
        lossAmount,
        token: initialContext.token,
        symbol: initialContext.symbol,
        amount: lossAmount.toString(),
        formatted: formatUnits(lossAmount, initialContext.decimals),
        currentBalanceFormatted: `${formatUnits(currentBalance, initialContext.decimals)} ${initialContext.symbol}`
      };
    }
    return null;
  }

  async formatCurrentState(
    initialContext: ERC20LossContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<string> {
    const currentBalance: bigint = await publicClient.readContract({
      address: initialContext.token,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [capability.owner]
    });
    return `${formatUnits(currentBalance, initialContext.decimals)} ${initialContext.symbol}`;
  }

  private getTokenFromCapability(capability: Capability): `0x${string}` {
    if (capability.kind === "PERMIT2_ALLOWANCE") {
      return capability.details.token;
    } else if (capability.kind === "PERMIT2_SIGNATURE") {
      return capability.permitted.token;
    } else if (capability.kind === "EIP7702") {
      if (!capability.targetToken) {
        throw new Error("EIP7702Capability requires targetToken for reachability verification");
      }
      return capability.targetToken;
    }
    throw new Error(`Unsupported capability kind: ${(capability as any).kind}`);
  }
}

export interface ExplorerOptions {
  maxDepth?: number;
  actionProvider?: ActionProvider;
  lossOracle?: InvariantOracle;
  invariantOracle?: InvariantOracle;
}

export type ExploreResult =
  | {
      status: "FOUND_LOSS";
      counterexample: Counterexample;
      visitedStates: number;
      capability: CapabilityKind;
      owner: `0x${string}`;
      attacker: `0x${string}`;
      depth: number;
      trace: Action[];
      loss: {
        token: `0x${string}`;
        symbol: string;
        amount: string;
        formatted: string;
      };
    }
  | {
      status: "NO_MODELED_LOSS";
      visitedStates: number;
    }
  | {
      status: "UNMODELED";
      reason: string;
      visitedStates: number;
    };

/**
 * Protocol-agnostic reachability verifier kernel.
 * Searches bounded EVM state transitions using an externally injectable ActionProvider
 * and evaluates safety invariants via an externally injectable InvariantOracle.
 */
export class ReachabilityExplorer {
  private maxDepth: number;
  private actionProvider: ActionProvider;
  private invariantOracle: InvariantOracle;
  private visitedStates: number = 0;

  constructor(
    private publicClient: PublicClient,
    private rpcClient: AnvilRpcClient,
    optionsOrMaxDepth: number | ExplorerOptions = 3,
    legacyActionProvider?: ActionProvider,
    legacyLossOracle?: InvariantOracle
  ) {
    if (typeof optionsOrMaxDepth === "number") {
      this.maxDepth = optionsOrMaxDepth;
      this.actionProvider = legacyActionProvider ?? new BuiltinCapabilityActionProvider();
      this.invariantOracle = legacyLossOracle ?? new ERC20LossOracle();
    } else {
      this.maxDepth = optionsOrMaxDepth.maxDepth ?? 3;
      this.actionProvider = optionsOrMaxDepth.actionProvider ?? new BuiltinCapabilityActionProvider();
      this.invariantOracle = optionsOrMaxDepth.invariantOracle ?? optionsOrMaxDepth.lossOracle ?? new ERC20LossOracle();
    }
  }

  async explore(
    capability: Capability,
    attacker: `0x${string}`
  ): Promise<ExploreResult> {
    this.visitedStates = 0;
    const initialContext = await this.invariantOracle.snapshotInitial(capability, this.publicClient);
    const searchOutcome = await this.dfs(0, [], initialContext, capability, attacker);

    if (searchOutcome.status === "FOUND_LOSS") {
      const ce = searchOutcome.counterexample;
      return {
        status: "FOUND_LOSS",
        counterexample: ce,
        visitedStates: this.visitedStates,
        capability: ce.capability,
        owner: ce.owner,
        attacker: ce.attacker,
        depth: ce.depth,
        trace: ce.trace,
        loss: ce.loss
      };
    }

    if (searchOutcome.status === "UNMODELED") {
      return {
        status: "UNMODELED",
        reason: searchOutcome.reason,
        visitedStates: this.visitedStates
      };
    }

    return {
      status: "NO_MODELED_LOSS",
      visitedStates: this.visitedStates
    };
  }

  private async dfs(
    depth: number,
    trace: Action[],
    initialContext: any,
    capability: Capability,
    attacker: `0x${string}`
  ): Promise<{ status: "FOUND_LOSS"; counterexample: Counterexample } | { status: "UNMODELED"; reason: string } | { status: "NO_MODELED_LOSS" }> {
    this.visitedStates++;
    if (depth >= this.maxDepth) {
      return { status: "NO_MODELED_LOSS" };
    }

    const owner = capability.owner;

    // Enumerate candidate actions from decoupled ActionProvider
    const enumeration = await this.actionProvider.enumerateActions(
      capability,
      this.publicClient,
      attacker
    );

    if (enumeration.status === "UNMODELED") {
      return { status: "UNMODELED", reason: enumeration.reason };
    }

    const actions = enumeration.actions;
    console.log(`     [Explorer Depth ${depth}] Discovered ${actions.length} legal action(s): ${actions.map(a => a.id).join(", ")}`);

    let unmodeledReason: string | undefined;

    for (const action of actions) {
      // 1. Take snapshot for backtrack
      const snapshot: Hex = await this.rpcClient.request({ method: "evm_snapshot" });

      try {
        // 2. Execute candidate action
        await this.executeAction(action);

        // 3. Inspect state after action execution via injected InvariantOracle
        const violation = await this.invariantOracle.evaluate(
          initialContext,
          capability,
          this.publicClient
        );

        if (this.invariantOracle.formatCurrentState) {
          const stateStr = await this.invariantOracle.formatCurrentState(initialContext, capability, this.publicClient);
          console.log(`       -> Executed [${action.id}]. Victim state: ${stateStr}`);
        } else {
          console.log(`       -> Executed [${action.id}]. Invariant violation: ${violation ? violation.formatted : "none"}`);
        }

        // Check if invariant broken
        if (violation) {
          // Counterexample found!
          await this.rpcClient.request({ method: "evm_revert", params: [snapshot] });

          return {
            status: "FOUND_LOSS",
            counterexample: {
              capability: (capability as any).kind || "GENERIC_CAPABILITY",
              owner,
              attacker,
              depth: depth + 1,
              trace: [...trace, action],
              loss: {
                token: violation.token ?? ("0x0000000000000000000000000000000000000000" as `0x${string}`),
                symbol: violation.symbol,
                amount: violation.amount,
                formatted: violation.formatted
              }
            }
          };
        }

        // 4. Recurse deeper
        const deeperResult = await this.dfs(
          depth + 1,
          [...trace, action],
          initialContext,
          capability,
          attacker
        );

        // 5. Backtrack
        await this.rpcClient.request({ method: "evm_revert", params: [snapshot] });

        if (deeperResult.status === "FOUND_LOSS") {
          return deeperResult;
        }
        if (deeperResult.status === "UNMODELED") {
          unmodeledReason = deeperResult.reason;
        }
      } catch (err: any) {
        console.log(`       -> Action [${action.id}] reverted: ${err.message || err}`);
        await this.rpcClient.request({ method: "evm_revert", params: [snapshot] });
      }
    }

    if (unmodeledReason) {
      return { status: "UNMODELED", reason: unmodeledReason };
    }

    return { status: "NO_MODELED_LOSS" };
  }

  private async executeAction(action: Action): Promise<void> {
    // Impersonate the actor on Anvil
    await this.rpcClient.request({
      method: "anvil_impersonateAccount",
      params: [action.actor]
    });

    // Fund actor with 1 ETH for gas if needed
    await this.rpcClient.request({
      method: "anvil_setBalance",
      params: [action.actor, "0xde0b6b3a7640000"] // 1 ETH
    });

    // Send transaction
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
