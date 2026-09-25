import { Address, Hex, getAddress } from "viem";
import { EIP7702Capability } from "./types.js";

export interface RawEIP7702AuthorizationInput {
  owner: Address;
  chainId: number | bigint | string;
  address?: Address; // Standard EIP-7702 delegation target address
  contractAddress?: Address; // Viem authorization object field
  nonce: number | bigint | string;
  yParity?: number;
  v?: number | bigint | string;
  r: Hex;
  s: Hex;
  targetToken?: Address;
}

/**
 * Decodes raw wallet EIP-7702 signed authorization tuple into a typed EIP7702Capability.
 */
export function decode7702(input: RawEIP7702AuthorizationInput & { delegateAddress?: Address }): EIP7702Capability {
  const rawTarget = input.address ?? input.contractAddress ?? input.delegateAddress;
  if (!rawTarget) {
    throw new Error("Invalid EIP-7702 authorization: missing delegate address");
  }
  if (!input.r || !input.s) {
    throw new Error("Invalid EIP-7702 authorization: missing r, s signature components");
  }

  const owner = getAddress(input.owner);
  const delegateAddress = getAddress(rawTarget);
  const chainId = BigInt(input.chainId);
  const nonce = BigInt(input.nonce);

  if (input.yParity === undefined && input.v === undefined) {
    throw new Error("Invalid EIP-7702 authorization: missing required yParity or v signature component");
  }

  let yParity: number;
  if (input.yParity !== undefined) {
    yParity = Number(input.yParity);
  } else {
    const vNum = Number(input.v);
    yParity = vNum >= 27 ? vNum - 27 : vNum;
  }

  if (yParity !== 0 && yParity !== 1) {
    throw new Error(`Invalid EIP-7702 authorization: yParity must be 0 or 1, got ${yParity}`);
  }

  const targetToken = input.targetToken ? getAddress(input.targetToken) : undefined;

  return {
    kind: "EIP7702",
    owner,
    chainId,
    delegateAddress,
    nonce,
    yParity,
    r: input.r,
    s: input.s,
    targetToken,
    authorizationObject: {
      chainId: Number(chainId),
      address: delegateAddress,
      nonce: Number(nonce),
      yParity,
      r: input.r,
      s: input.s
    }
  };
}
