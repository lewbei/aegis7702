import { Address, getAddress, verifyTypedData } from "viem";
import { recoverAuthorizationAddress } from "viem/experimental";
import { Capability } from "./types.js";

export interface CapabilityValidationResult {
  valid: boolean;
  signer?: Address;
  reason?: string;
}

export class CapabilityValidator {
  /**
   * Cryptographically validates the capability's digital signature and authority.
   * - For EIP-7702: recovers the authority address from the signed tuple (chainId, address, nonce, yParity, r, s)
   *   and verifies it matches the claimed owner.
   * - For Permit2 Allowance: verifies the EIP-712 PermitSingle signature against claimed owner.
   * - For Permit2 Signature: verifies the EIP-712 PermitTransferFrom signature against claimed owner.
   */
  static async validate(capability: Capability): Promise<CapabilityValidationResult> {
    try {
      if (capability.kind === "EIP7702") {
        const auth = {
          address: capability.delegateAddress,
          chainId: Number(capability.chainId),
          nonce: Number(capability.nonce),
          yParity: capability.yParity,
          r: capability.r,
          s: capability.s
        };

        const recovered = await recoverAuthorizationAddress({ authorization: auth });
        const recoveredOwner = getAddress(recovered);
        const claimedOwner = getAddress(capability.owner);

        if (recoveredOwner !== claimedOwner) {
          return {
            valid: false,
            signer: recoveredOwner,
            reason: `Cryptographic authority mismatch: recovered signer ${recoveredOwner} does not match claimed owner ${claimedOwner}`
          };
        }

        return {
          valid: true,
          signer: recoveredOwner
        };
      }

      if (capability.kind === "PERMIT2_ALLOWANCE") {
        const domain = {
          name: "Permit2",
          chainId: Number(capability.chainId),
          verifyingContract: capability.permit2Address
        };

        const types = {
          PermitDetails: [
            { name: "token", type: "address" },
            { name: "amount", type: "uint160" },
            { name: "expiration", type: "uint48" },
            { name: "nonce", type: "uint48" }
          ],
          PermitSingle: [
            { name: "details", type: "PermitDetails" },
            { name: "spender", type: "address" },
            { name: "sigDeadline", type: "uint256" }
          ]
        };

        const message = {
          details: {
            token: capability.details.token,
            amount: capability.details.amount,
            expiration: capability.details.expiration,
            nonce: capability.details.nonce
          },
          spender: capability.spender,
          sigDeadline: capability.sigDeadline
        };

        const isValid = await verifyTypedData({
          address: capability.owner,
          domain,
          types,
          primaryType: "PermitSingle",
          message,
          signature: capability.signature
        });

        if (!isValid) {
          return {
            valid: false,
            reason: `Cryptographic signature verification failed: invalid PermitSingle EIP-712 signature for owner ${capability.owner}`
          };
        }

        return {
          valid: true,
          signer: capability.owner
        };
      }

      if (capability.kind === "PERMIT2_SIGNATURE") {
        const domain = {
          name: "Permit2",
          chainId: Number(capability.chainId),
          verifyingContract: capability.permit2Address
        };

        const types = {
          TokenPermissions: [
            { name: "token", type: "address" },
            { name: "amount", type: "uint256" }
          ],
          PermitTransferFrom: [
            { name: "permitted", type: "TokenPermissions" },
            { name: "spender", type: "address" },
            { name: "nonce", type: "uint256" },
            { name: "deadline", type: "uint256" }
          ]
        };

        const message = {
          permitted: {
            token: capability.permitted.token,
            amount: capability.permitted.amount
          },
          spender: capability.spender,
          nonce: capability.nonce,
          deadline: capability.deadline
        };

        const isValid = await verifyTypedData({
          address: capability.owner,
          domain,
          types,
          primaryType: "PermitTransferFrom",
          message,
          signature: capability.signature
        });

        if (!isValid) {
          return {
            valid: false,
            reason: `Cryptographic signature verification failed: invalid PermitTransferFrom EIP-712 signature for owner ${capability.owner}`
          };
        }

        return {
          valid: true,
          signer: capability.owner
        };
      }

      return {
        valid: false,
        reason: `Unsupported capability kind: ${(capability as any).kind}`
      };
    } catch (err: any) {
      return {
        valid: false,
        reason: `Cryptographic validation exception: ${err?.message || String(err)}`
      };
    }
  }
}
