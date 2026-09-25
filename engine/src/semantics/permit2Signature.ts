import { encodeFunctionData, PublicClient } from "viem";
import { Action, ActionEnumeration, Permit2SignatureCapability } from "../capability/types.js";
import { PERMIT2_ABI, ERC20_ABI } from "../capability/abis.js";

export class Permit2SignatureSemantics {
  static async enumerateActions(
    capability: Permit2SignatureCapability,
    client: PublicClient,
    attacker: `0x${string}`
  ): Promise<ActionEnumeration> {
    // Only the authorized spender can execute the resulting transfer
    if (attacker.toLowerCase() !== capability.spender.toLowerCase()) {
      return { status: "MODELED", actions: [] };
    }

    const actions: Action[] = [];
    const token = capability.permitted.token;
    const owner = capability.owner;
    const permit2 = capability.permit2Address;
    const nonce = capability.nonce;

    // Calculate wordPos and bitPos
    const wordPos = nonce >> 8n;
    const bitPos = Number(nonce & 255n);
    const bit = 1n << BigInt(bitPos);

    // 1. Read on-chain unordered nonce bitmap
    let currentWord = 0n;
    try {
      currentWord = await client.readContract({
        address: permit2,
        abi: PERMIT2_ABI,
        functionName: "nonceBitmap",
        args: [owner, wordPos]
      });
    } catch {
      return { status: "UNMODELED", reason: `Permit2 contract at ${permit2} not deployed or unavailable` };
    }

    // If bit is already set (flipped), the nonce is already spent or invalidated
    const isNonceAvailable = (currentWord & bit) === 0n;

    // 2. Read victim's ERC20 balance and allowance to Permit2
    const victimBalance: bigint = await client.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: "balanceOf",
      args: [owner]
    }).catch(() => 0n);

    const tokenApprovalToPermit2: bigint = await client.readContract({
      address: token,
      abi: ERC20_ABI,
      functionName: "allowance",
      args: [owner, permit2]
    }).catch(() => 0n);

    // Action: permitTransferFrom
    if (isNonceAvailable && victimBalance > 0n && tokenApprovalToPermit2 > 0n) {
      let drainAmount = capability.permitted.amount;
      if (victimBalance < drainAmount) drainAmount = victimBalance;
      if (tokenApprovalToPermit2 < drainAmount) drainAmount = tokenApprovalToPermit2;

      if (drainAmount > 0n) {
        const calldata = encodeFunctionData({
          abi: PERMIT2_ABI,
          functionName: "permitTransferFrom",
          args: [
            {
              permitted: {
                token: capability.permitted.token,
                amount: capability.permitted.amount
              },
              nonce: capability.nonce,
              deadline: capability.deadline
            },
            {
              to: attacker,
              requestedAmount: drainAmount
            },
            owner,
            capability.signature
          ]
        });

        actions.push({
          id: "Permit2.permitTransferFrom",
          description: `Attacker executes permitTransferFrom to drain ${drainAmount} tokens via unordered nonce ${nonce}`,
          target: permit2,
          calldata,
          value: 0n,
          actor: attacker
        });
      }
    }

    return {
      status: "MODELED",
      actions
    };
  }
}
