import { encodeFunctionData, PublicClient, Hex, Address } from "viem";
import { Permit2AllowanceCapability } from "../capability/types.js";
import { PERMIT2_ABI } from "../capability/abis.js";

export interface Permit2RecoveryTx {
  to: Address;
  data: Hex;
  value: bigint;
  targetNonce?: number;
}

export interface RecoveryAction {
  strategy: "INVALIDATE_NONCE" | "LOCKDOWN_ALLOWANCE" | "NOOP" | "RECOVERY_INFEASIBLE";
  description: string;
  target: Address;
  calldata: Hex;
  actor: Address; // Must be owner because Permit2 checks msg.sender
  transactions?: Permit2RecoveryTx[];
  totalChunks?: number;
}

export class Permit2RecoveryPlanner {
  static async plan(
    capability: Permit2AllowanceCapability,
    client: PublicClient
  ): Promise<RecoveryAction> {
    const owner = capability.owner;
    const token = capability.details.token;
    const spender = capability.spender;
    const permit2 = capability.permit2Address;

    const [allowedAmount, , currentNonce] = await client.readContract({
      address: permit2,
      abi: PERMIT2_ABI,
      functionName: "allowance",
      args: [owner, token, spender]
    });

    // Case A: Pending/unconsumed permit (current or future signed nonce)
    if (capability.details.nonce >= currentNonce) {
      const targetNonce = capability.details.nonce + 1;
      const MAX_DELTA = 65535; // type(uint16).max limit in Permit2 AllowanceTransfer.sol
      const delta = targetNonce - currentNonce;

      // Bound future-nonce recovery chunks to prevent unbounded memory/execution overhead
      const MAX_CHUNKS = 100;
      const estimatedChunks = Math.ceil(delta / MAX_DELTA);
      if (estimatedChunks > MAX_CHUNKS) {
        return {
          strategy: "RECOVERY_INFEASIBLE",
          description: `Permit2 recovery requires ${estimatedChunks} chunked invalidation transactions (exceeding maximum feasible batch threshold of ${MAX_CHUNKS}). Manual intervention or token contract revocation required.`,
          target: permit2,
          calldata: "0x",
          actor: owner,
          totalChunks: estimatedChunks
        };
      }

      const txs: Permit2RecoveryTx[] = [];
      let stepNonce = currentNonce;

      while (stepNonce < targetNonce) {
        stepNonce = Math.min(stepNonce + MAX_DELTA, targetNonce);
        const calldata = encodeFunctionData({
          abi: PERMIT2_ABI,
          functionName: "invalidateNonces",
          args: [token, spender, stepNonce]
        });
        txs.push({
          to: permit2,
          data: calldata,
          value: 0n,
          targetNonce: stepNonce
        });
      }

      const totalChunks = txs.length;
      const description =
        totalChunks > 1
          ? `Target nonce (${targetNonce}) exceeds Permit2 max single-step delta (65,535). Generated ${totalChunks} sequential chunked invalidation transactions to safely advance nonce to ${targetNonce} without triggering ExcessiveInvalidation revert`
          : `Owner calls invalidateNonces(token, spender, ${targetNonce}) advancing nonce past signed nonce (${capability.details.nonce}) to prevent permit consumption`;

      return {
        strategy: "INVALIDATE_NONCE",
        description,
        target: permit2,
        calldata: txs[0].data,
        actor: owner,
        transactions: txs,
        totalChunks
      };
    }

    // Case B: Consumed permit, allowance is active
    if (allowedAmount > 0n) {
      const calldata = encodeFunctionData({
        abi: PERMIT2_ABI,
        functionName: "lockdown",
        args: [[{ token, spender }]]
      });

      return {
        strategy: "LOCKDOWN_ALLOWANCE",
        description: `Owner calls lockdown([{ token, spender }]) to immediately zero out the compromised allowance`,
        target: permit2,
        calldata,
        actor: owner,
        transactions: [{ to: permit2, data: calldata, value: 0n }]
      };
    }

    return {
      strategy: "NOOP",
      description: "No active risk or capability already neutralized",
      target: permit2,
      calldata: "0x",
      actor: owner,
      transactions: []
    };
  }
}
