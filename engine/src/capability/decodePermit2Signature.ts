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
export function decodePermit2Signature(input: any): Permit2SignatureCapability {
  const domain = input.domain ?? {
    verifyingContract: input.permit2Address,
    chainId: input.chainId
  };
  const message = input.message ?? {
    permitted: input.permitted,
    spender: input.spender,
    nonce: input.nonce,
    deadline: input.deadline
  };

  if (!domain?.verifyingContract) {
    throw new Error("Invalid Permit2 EIP-712 domain: missing verifyingContract");
  }
  if (!message?.permitted?.token || !message?.spender) {
    throw new Error("Invalid Permit2 PermitTransferFrom message: missing token or spender");
  }

  const rawChainId = domain?.chainId ?? input.chainId;
  if (rawChainId === undefined || rawChainId === null || rawChainId === "") {
    throw new Error("Invalid Permit2 capability: missing required chainId in domain or input");
  }
  const chainId = BigInt(rawChainId);
  const permit2Address = getAddress(domain.verifyingContract);
  const owner = getAddress(input.owner);
  const spender = getAddress(message.spender);
  const token = getAddress(message.permitted.token);

  return {
    kind: "PERMIT2_SIGNATURE",
    owner,
    chainId,
    permit2Address,
    permitted: {
      token,
      amount: BigInt(message.permitted.amount)
    },
    spender,
    nonce: BigInt(message.nonce),
    deadline: BigInt(message.deadline),
    signature: input.signature
  };
}
