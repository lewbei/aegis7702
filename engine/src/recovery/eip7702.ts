import { PublicClient, Address, Hex } from "viem";
import { EIP7702Capability } from "../capability/types.js";

export interface EIP7702RecoveryAction {
  strategy: "ADVANCE_NONCE" | "CLEAR_DELEGATION" | "FUTURE_NONCE_MULTI_ADVANCE" | "NOOP";
  description: string;
  target: Address;
  calldata: Hex;
  actor: Address;
  requiredAdvances?: number;
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
          nonce: currentNonce
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
        requiredAdvances: 1
      };
    }

    // currNonce < capNonce: Future nonce requires advancing to capNonce + 1
    const needed = Number(capNonce - currNonce + 1n);
    return {
      strategy: "FUTURE_NONCE_MULTI_ADVANCE",
      description: `Future-nonce authorization detected (current: ${currNonce}, target: ${capNonce}). Requires advancing account nonce by ${needed} to ${capNonce + 1n} to permanently neutralize`,
      target: owner,
      calldata: "0x",
      actor: owner,
      requiredAdvances: needed
    };
  }
}
