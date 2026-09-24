import { Capability } from "./types.js";
import { decodePermit2Allowance, RawPermit2AllowanceInput } from "./decodePermit2Allowance.js";
import { decodePermit2Signature, RawPermit2SignatureInput } from "./decodePermit2Signature.js";
import { decode7702, RawEIP7702AuthorizationInput } from "./decode7702.js";

export type RawCapabilityInput =
  | { type: "PERMIT2_ALLOWANCE"; payload: RawPermit2AllowanceInput }
  | { type: "PERMIT2_SIGNATURE"; payload: RawPermit2SignatureInput }
  | { type: "EIP7702"; payload: RawEIP7702AuthorizationInput }
  | { [key: string]: any };

/**
 * Universal Capability Decoder:
 * Translates raw signing payloads (EIP-712 typed data messages or EIP-7702 authorization tuples)
 * into strongly-typed internal Capability abstractions for reachability analysis.
 */
export function decodeCapability(input: RawCapabilityInput): Capability {
  // Explicit discriminator
  if ("type" in input) {
    if (input.type === "PERMIT2_ALLOWANCE") {
      return decodePermit2Allowance(input.payload);
    }
    if (input.type === "PERMIT2_SIGNATURE") {
      return decodePermit2Signature(input.payload);
    }
    if (input.type === "EIP7702") {
      return decode7702(input.payload);
    }
  }

  // Heuristic detection based on payload shape
  // EIP-7702 tuple
  if ("address" in input && "r" in input && "s" in input && ("yParity" in input || "v" in input)) {
    return decode7702(input as RawEIP7702AuthorizationInput);
  }

  // EIP-712 message
  if ("domain" in input && "message" in input && "signature" in input) {
    const msg = input.message;
    if ("details" in msg && "token" in msg.details) {
      return decodePermit2Allowance(input as RawPermit2AllowanceInput);
    }
    if ("permitted" in msg && "token" in msg.permitted) {
      return decodePermit2Signature(input as RawPermit2SignatureInput);
    }
  }

  throw new Error("Unable to decode capability: unrecognized payload format");
}

export * from "./decodePermit2Allowance.js";
export * from "./decodePermit2Signature.js";
export * from "./decode7702.js";
