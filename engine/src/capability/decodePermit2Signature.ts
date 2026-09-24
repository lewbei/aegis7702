import { Address, Hex, getAddress } from "viem";
import { Permit2SignatureCapability } from "./types.js";
import { EIP712Domain } from "./decodePermit2Allowance.js";

export interface Permit2SignatureMessage {
  permitted: {
    token: Address;
    amount: bigint | string | number;
  };
  spender: Address;
  nonce: bigint | string | number;
  deadline: bigint | string | number;
}

export interface RawPermit2SignatureInput {
  owner: Address;
  domain: EIP712Domain;
  types?: Record<string, any>;
  message: Permit2SignatureMessage;
  signature: Hex;
}

/**
 * Decodes raw wallet EIP-712 PermitTransferFrom signing payload into a typed Permit2SignatureCapability.
 */
export function decodePermit2Signature(input: RawPermit2SignatureInput): Permit2SignatureCapability {
  if (!input.domain?.verifyingContract) {
    throw new Error("Invalid Permit2 EIP-712 domain: missing verifyingContract");
  }
  if (!input.message?.permitted?.token || !input.message?.spender) {
    throw new Error("Invalid Permit2 PermitTransferFrom message: missing token or spender");
  }

  const chainId = BigInt(input.domain.chainId ?? 1);
  const permit2Address = getAddress(input.domain.verifyingContract);
  const owner = getAddress(input.owner);
  const spender = getAddress(input.message.spender);
  const token = getAddress(input.message.permitted.token);

  return {
    kind: "PERMIT2_SIGNATURE",
    owner,
    chainId,
    permit2Address,
    permitted: {
      token,
      amount: BigInt(input.message.permitted.amount)
    },
    spender,
    nonce: BigInt(input.message.nonce),
    deadline: BigInt(input.message.deadline),
    signature: input.signature
  };
}
