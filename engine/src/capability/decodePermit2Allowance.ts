import { Address, Hex, getAddress } from "viem";
import { Permit2AllowanceCapability } from "./types.js";

export interface EIP712Domain {
  name?: string;
  version?: string;
  chainId?: number | bigint | string;
  verifyingContract?: Address;
  salt?: Hex;
}

export interface Permit2AllowanceMessage {
  details: {
    token: Address;
    amount: bigint | string | number;
    expiration: number | string;
    nonce: number | string;
  };
  spender: Address;
  sigDeadline: bigint | string | number;
}

export interface RawPermit2AllowanceInput {
  owner: Address;
  domain: EIP712Domain;
  types?: Record<string, any>;
  message: Permit2AllowanceMessage;
  signature: Hex;
}

/**
 * Decodes raw wallet EIP-712 PermitSingle signing payload into a typed Permit2AllowanceCapability.
 */
export function decodePermit2Allowance(input: any): Permit2AllowanceCapability {
  const domain = input.domain ?? {
    verifyingContract: input.permit2Address,
    chainId: input.chainId
  };
  const message = input.message ?? {
    details: input.details,
    spender: input.spender,
    sigDeadline: input.sigDeadline
  };

  if (!domain?.verifyingContract) {
    throw new Error("Invalid Permit2 EIP-712 domain: missing verifyingContract");
  }
  if (!message?.details?.token || !message?.spender) {
    throw new Error("Invalid Permit2 PermitSingle message: missing token or spender");
  }

  const chainId = BigInt(domain.chainId ?? input.chainId ?? 1);
  const permit2Address = getAddress(domain.verifyingContract);
  const owner = getAddress(input.owner);
  const spender = getAddress(message.spender);
  const token = getAddress(message.details.token);

  return {
    kind: "PERMIT2_ALLOWANCE",
    owner,
    chainId,
    permit2Address,
    details: {
      token,
      amount: BigInt(message.details.amount),
      expiration: Number(message.details.expiration),
      nonce: Number(message.details.nonce)
    },
    spender,
    sigDeadline: BigInt(message.sigDeadline),
    signature: input.signature
  };
}
