import {
  PublicClient,
  formatUnits,
  Hex,
  Hash
} from "viem";
import { Action, Counterexample, Capability } from "../capability/types.js";
import { Permit2AllowanceSemantics } from "../semantics/permit2Allowance.js";
import { Permit2SignatureSemantics } from "../semantics/permit2Signature.js";
import { EIP7702Semantics } from "../semantics/eip7702.js";
import { ERC20_ABI } from "../capability/abis.js";

export interface AnvilRpcClient {
  request(args: { method: string; params?: any[] }): Promise<any>;
}

export interface ActionProvider {
  enumerateActions(
    capability: Capability,
    publicClient: PublicClient,
    attacker: `0x${string}`
  ): Promise<Action[]>;
}

export interface LossObservation {
  lossAmount: bigint;
  token?: `0x${string}`;
  symbol: string;
  amount: string;
  formatted: string;
  currentBalanceFormatted?: string;
}

export interface LossOracle<TContext = any> {
  snapshotInitial(
    capability: Capability,
    publicClient: PublicClient
  ): Promise<TContext>;

  evaluate(
    initialContext: TContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<LossObservation | null>;

  formatCurrentState?(
    initialContext: TContext,
    capability: Capability,
    publicClient: PublicClient
  ): Promise<string>;
}

export interface ERC20LossContext {
  token: `0x${string}`;
  symbol: string;
  decimals: number;
  initialBalance: bigint;
}

/**
 * Canonical ERC-20 Loss Oracle: detects whether a victim account's tracked token balance
 * strictly decreases following an executed action path.
 */
export class ERC20LossOracle implements LossOracle<ERC20LossContext> {
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
  ): Promise<LossObservation | null> {
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
  lossOracle?: LossOracle;
}

/**
 * Protocol-agnostic reachability verifier kernel.
 * Searches bounded EVM state transitions using an externally injectable ActionProvider
 * and evaluates safety invariants via an externally injectable LossOracle.
 */
export class ReachabilityExplorer {
  private maxDepth: number;
  private customActionProvider?: ActionProvider;
  private lossOracle: LossOracle;

  constructor(
    private publicClient: PublicClient,
    private rpcClient: AnvilRpcClient,
    optionsOrMaxDepth: number | ExplorerOptions = 3,
    legacyActionProvider?: ActionProvider,
    legacyLossOracle?: LossOracle
  ) {
    if (typeof optionsOrMaxDepth === "number") {
      this.maxDepth = optionsOrMaxDepth;
      this.customActionProvider = legacyActionProvider;
      this.lossOracle = legacyLossOracle ?? new ERC20LossOracle();
    } else {
      this.maxDepth = optionsOrMaxDepth.maxDepth ?? 3;
      this.customActionProvider = optionsOrMaxDepth.actionProvider;
      this.lossOracle = optionsOrMaxDepth.lossOracle ?? new ERC20LossOracle();
    }
  }

  async explore(
    capability: Capability,
    attacker: `0x${string}`
  ): Promise<Counterexample | null> {
    const initialContext = await this.lossOracle.snapshotInitial(capability, this.publicClient);
    return this.dfs(0, [], initialContext, capability, attacker);
  }

  private async dfs(
    depth: number,
    trace: Action[],
    initialContext: any,
    capability: Capability,
    attacker: `0x${string}`
  ): Promise<Counterexample | null> {
    if (depth >= this.maxDepth) return null;

    const owner = capability.owner;

    // Enumerate candidate actions from semantic models or decoupled custom action provider
    let actions: Action[] = [];
    if (this.customActionProvider) {
      actions = await this.customActionProvider.enumerateActions(
        capability,
        this.publicClient,
        attacker
      );
    } else if (capability.kind === "PERMIT2_ALLOWANCE") {
      actions = await Permit2AllowanceSemantics.enumerateActions(
        capability,
        this.publicClient,
        attacker
      );
    } else if (capability.kind === "PERMIT2_SIGNATURE") {
      actions = await Permit2SignatureSemantics.enumerateActions(
        capability,
        this.publicClient,
        attacker
      );
    } else if (capability.kind === "EIP7702") {
      actions = await EIP7702Semantics.enumerateActions(
        capability,
        this.publicClient,
        attacker
      );
    }

    console.log(`     [Explorer Depth ${depth}] Discovered ${actions.length} legal action(s): ${actions.map(a => a.id).join(", ")}`);

    for (const action of actions) {
      // 1. Take snapshot for backtrack
      const snapshot: Hex = await this.rpcClient.request({ method: "evm_snapshot" });

      try {
        // 2. Execute candidate action
        await this.executeAction(action);

        // 3. Inspect state after action execution via injected LossOracle
        const lossObs = await this.lossOracle.evaluate(
          initialContext,
          capability,
          this.publicClient
        );

        if (this.lossOracle.formatCurrentState) {
          const stateStr = await this.lossOracle.formatCurrentState(initialContext, capability, this.publicClient);
          console.log(`       -> Executed [${action.id}]. Victim state: ${stateStr}`);
        } else {
          console.log(`       -> Executed [${action.id}]. Loss observed: ${lossObs ? lossObs.formatted : "none"}`);
        }

        // Check if invariant broken
        if (lossObs) {
          // Counterexample found!
          await this.rpcClient.request({ method: "evm_revert", params: [snapshot] });

          return {
            capability: capability.kind,
            owner,
            attacker,
            depth: depth + 1,
            trace: [...trace, action],
            loss: {
              token: lossObs.token ?? ("0x0000000000000000000000000000000000000000" as `0x${string}`),
              symbol: lossObs.symbol,
              amount: lossObs.amount,
              formatted: lossObs.formatted
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

        if (deeperResult) {
          return deeperResult;
        }
      } catch (err: any) {
        console.log(`       -> Action [${action.id}] reverted: ${err.message || err}`);
        await this.rpcClient.request({ method: "evm_revert", params: [snapshot] });
      }
    }

    return null;
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
