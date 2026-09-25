import { PublicClient, Address, Hex } from "viem";
import { EIP7702Capability } from "../capability/types.js";

export interface EIP7702RecoveryAction {
  strategy: "ADVANCE_NONCE" | "CLEAR_DELEGATION" | "FUTURE_NONCE_MULTI_ADVANCE" | "RECOVERY_INFEASIBLE" | "NOOP";
  description: string;
  target: Address;
  calldata: Hex;
  actor: Address;
  requiredAdvances?: number;
  estimatedGas?: bigint;
  transactions?: Array<{ to: Address; value: bigint; data: Hex }>;
  recoveryDelegation?: {
    address: Address;
    chainId: number;
    nonce: number;
  };
}

export class EIP7702RecoveryPlanner {
  static async plan(
    capability: EIP7702Capability,
    client: PublicClient
  ): Promise<EIP7702RecoveryAction> {
    const owner = capability.owner;
    const currentNonce = await client.getTransactionCount({ address: owner });
    const currentBytecode = await client.getBytecode({ address: owner });

    const hasDelegation =
      currentBytecode &&
      currentBytecode.length >= 48 &&
      currentBytecode.toLowerCase().startsWith("0xef0100");

    // Case 1: Active delegation on victim EOA -> Clear delegation by setting address(0)
    if (hasDelegation) {
      return {
        strategy: "CLEAR_DELEGATION",
        description: `Owner broadcasts Type-4 recovery transaction with authorization for address(0) to reset code to standard EOA`,
        target: owner,
        calldata: "0x",
        actor: owner,
        recoveryDelegation: {
          address: "0x0000000000000000000000000000000000000000",
          chainId: Number(capability.chainId),
          nonce: currentNonce + 1
        }
      };
    }

    // Case 2: Unconsumed authorization -> Check nonce relationship
    const capNonce = BigInt(capability.nonce);
    const currNonce = BigInt(currentNonce);

    if (currNonce > capNonce) {
      return {
        strategy: "NOOP",
        description: `Stolen authorization already invalidated by higher account nonce (${currNonce} > ${capNonce}); no active delegation detected`,
        target: owner,
        calldata: "0x",
        actor: owner
      };
    }

    if (currNonce === capNonce) {
      return {
        strategy: "ADVANCE_NONCE",
        description: `Owner executes self-transaction to increment account nonce from ${currNonce} to ${currNonce + 1n}, invalidating stolen authorization via nonce mismatch`,
        target: owner,
        calldata: "0x",
        actor: owner,
        requiredAdvances: 1,
        transactions: [{ to: owner, value: 0n, data: "0x" }]
      };
    }

    // currNonce < capNonce: Future nonce requires advancing to capNonce + 1
    const needed = Number(capNonce - currNonce + 1n);
    const MAX_NONCE_ADVANCES = 100;

    if (needed > MAX_NONCE_ADVANCES) {
      return {
        strategy: "RECOVERY_INFEASIBLE",
        description: `Future-nonce authorization target (${capNonce}) requires ${needed} self-transactions, exceeding safe automated execution limit (${MAX_NONCE_ADVANCES}). Automated recovery infeasible due to gas cost / execution length.`,
        target: owner,
        calldata: "0x",
        actor: owner,
        requiredAdvances: needed,
        estimatedGas: BigInt(needed) * 21000n
      };
    }

    const txs: Array<{ to: Address; value: bigint; data: Hex }> = [];
    for (let i = 0; i < needed; i++) {
      txs.push({ to: owner, value: 0n, data: "0x" });
    }

    return {
      strategy: "FUTURE_NONCE_MULTI_ADVANCE",
      description: `Future-nonce authorization detected (current: ${currNonce}, target: ${capNonce}). Synthesized ${needed} nonce-advancing self-transaction(s) to advance account nonce to ${capNonce + 1n} to permanently neutralize`,
      target: owner,
      calldata: "0x",
      actor: owner,
      requiredAdvances: needed,
      transactions: txs,
      estimatedGas: BigInt(needed) * 21000n
    };
  }
}
