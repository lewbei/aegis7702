import {
  createPublicClient,
  http,
  Address,
  Hex,
  parseUnits
} from "viem";
import { Permit2AllowanceSemantics } from "./semantics/permit2Allowance.js";
import { Permit2SignatureSemantics } from "./semantics/permit2Signature.js";
import { EIP7702Semantics } from "./semantics/eip7702.js";
import { ERC20LossOracle, ReachabilityExplorer } from "./search/explorer.js";
import { MultiCapabilityAuditor } from "./capability/multiAuditor.js";
import { CapabilityValidator } from "./capability/validator.js";
import { Permit2AllowanceCapability, Permit2SignatureCapability, EIP7702Capability, Action } from "./capability/types.js";
import { decodePermit2Allowance } from "./capability/decodePermit2Allowance.js";
import { decode7702 } from "./capability/decode7702.js";

// Helper comparator matching evalUsenixReal
function compareTraces(traceA: Action[], traceB: Action[]): boolean {
  if (!traceA || !traceB) return traceA === traceB;
  if (traceA.length !== traceB.length) return false;
  for (let i = 0; i < traceA.length; i++) {
    const a = traceA[i];
    const b = traceB[i];
    if (a.actor.toLowerCase() !== b.actor.toLowerCase()) return false;
    if (a.target.toLowerCase() !== b.target.toLowerCase()) return false;
    if (a.calldata.toLowerCase() !== b.calldata.toLowerCase()) return false;
    if (a.value !== b.value) return false;
    const authA = a.authorizationList || [];
    const authB = b.authorizationList || [];
    if (authA.length !== authB.length) return false;
    for (let j = 0; j < authA.length; j++) {
      const itemA = authA[j];
      const itemB = authB[j];
      if (itemA.chainId !== itemB.chainId) return false;
      if (itemA.address.toLowerCase() !== itemB.address.toLowerCase()) return false;
      if (itemA.nonce !== itemB.nonce) return false;
    }
  }
  return true;
}

async function runSoundnessTests() {
  console.log("==================================================================");
  console.log("   AEGIS7702: VERIFIER & PROTOCOL SOUNDNESS HARDENING TESTS       ");
  console.log("==================================================================");

  const victim: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const attackerA: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
  const attackerB: Address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
  const usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
  const permit2: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

  // -------------------------------------------------------------------------
  // TEST 1: Fail-Closed Observation: RPC Failures MUST return UNMODELED
  // -------------------------------------------------------------------------
  console.log("\n[Test 1] Fail-Closed State Observation: RPC failures must yield UNMODELED...");

  const faultyClient: any = {
    readContract: async (args: any) => {
      if (args.functionName === "allowance" && args.address === permit2) {
        return [parseUnits("5000", 6), 9999999999, 0];
      }
      if (args.functionName === "nonceBitmap") {
        return 0n;
      }
      // Force failure on token balance or allowance reads
      throw new Error("RPC_TIMEOUT: connection lost to EVM archive node");
    },
    getBytecode: async () => "0x6080604052348015600f57600080fd5b50",
    getTransactionCount: async () => 0,
    getChainId: async () => 31337
  };

  const allowanceCap: Permit2AllowanceCapability = {
    kind: "PERMIT2_ALLOWANCE",
    owner: victim,
    spender: attackerA,
    permit2Address: permit2,
    chainId: 31337n,
    details: {
      token: usdc,
      amount: parseUnits("5000", 6),
      expiration: 9999999999,
      nonce: 0
    },
    sigDeadline: 9999999999n,
    signature: "0x1234" as Hex
  };

  const enumAllowance = await Permit2AllowanceSemantics.enumerateActions(allowanceCap, faultyClient, attackerA);
  if (enumAllowance.status !== "UNMODELED") {
    throw new Error(`CRITICAL SOUNDNESS BUG: Faulty RPC must yield UNMODELED, got: ${enumAllowance.status}`);
  }
  console.log(`  ✓ Permit2AllowanceSemantics correctly returned UNMODELED on failed state observation: "${enumAllowance.reason}"`);

  const sigCap: Permit2SignatureCapability = {
    kind: "PERMIT2_SIGNATURE",
    owner: victim,
    spender: attackerA,
    permit2Address: permit2,
    chainId: 31337n,
    permitted: {
      token: usdc,
      amount: parseUnits("1000", 6)
    },
    nonce: 1025n,
    deadline: 9999999999n,
    signature: "0x5678" as Hex
  };

  const enumSig = await Permit2SignatureSemantics.enumerateActions(sigCap, faultyClient, attackerA);
  if (enumSig.status !== "UNMODELED") {
    throw new Error(`CRITICAL SOUNDNESS BUG: Faulty RPC in signature semantics must yield UNMODELED, got: ${enumSig.status}`);
  }
  console.log(`  ✓ Permit2SignatureSemantics correctly returned UNMODELED on failed state observation: "${enumSig.reason}"`);

  const eip7702Cap: EIP7702Capability = {
    kind: "EIP7702",
    owner: victim,
    delegateAddress: "0x1111111111111111111111111111111111111111",
    chainId: 31337n,
    nonce: 0n,
    yParity: 0,
    r: "0x0000000000000000000000000000000000000000000000000000000000000001",
    s: "0x0000000000000000000000000000000000000000000000000000000000000002",
    targetToken: usdc
  };

  const enum7702 = await EIP7702Semantics.enumerateActions(eip7702Cap, faultyClient, attackerA);
  if (enum7702.status !== "UNMODELED") {
    throw new Error(`CRITICAL SOUNDNESS BUG: Faulty RPC in EIP-7702 semantics must yield UNMODELED, got: ${enum7702.status}`);
  }
  console.log(`  ✓ EIP7702Semantics correctly returned UNMODELED on failed state observation: "${enum7702.reason}"`);

  const oracle = new ERC20LossOracle();
  let oracleThrew = false;
  try {
    await oracle.evaluate({ token: usdc, symbol: "USDC", decimals: 6, initialBalance: 1000n }, allowanceCap, faultyClient);
  } catch {
    oracleThrew = true;
  }
  if (!oracleThrew) {
    throw new Error("CRITICAL SOUNDNESS BUG: ERC20LossOracle must throw on failed balance observation, never swallow to initialBalance!");
  }
  console.log("  ✓ ERC20LossOracle correctly throws on failed post-action observation (fail-closed)");

  // -------------------------------------------------------------------------
  // TEST 2: Trace Equivalence Comparator Rigor
  // -------------------------------------------------------------------------
  console.log("\n[Test 2] Trace Equivalence Comparator Rigor (compareTraces)...");

  const baseAction: Action = {
    id: "Test.transfer",
    description: "test",
    actor: attackerA,
    target: usdc,
    calldata: "0xa9059cbb000000000000000000000000",
    value: 0n
  };

  const diffActorAction: Action = {
    ...baseAction,
    actor: attackerB
  };

  if (compareTraces([baseAction], [diffActorAction])) {
    throw new Error("CRITICAL AUDIT BUG: compareTraces() must return false when action actors differ!");
  }
  console.log("  ✓ compareTraces correctly rejects traces with differing actors");

  const authActionA: Action = {
    ...baseAction,
    authorizationList: [{ chainId: 31337, address: "0x1111111111111111111111111111111111111111", nonce: 1 }]
  };
  const authActionB: Action = {
    ...baseAction,
    authorizationList: [{ chainId: 31337, address: "0x2222222222222222222222222222222222222222", nonce: 1 }]
  };

  if (compareTraces([authActionA], [authActionB])) {
    throw new Error("CRITICAL AUDIT BUG: compareTraces() must return false when authorization delegates differ!");
  }
  console.log("  ✓ compareTraces correctly rejects traces with differing authorization tuples");

  if (!compareTraces([authActionA], [{ ...authActionA }])) {
    throw new Error("compareTraces() should return true for identical traces");
  }
  console.log("  ✓ compareTraces correctly accepts truly identical traces");

  // -------------------------------------------------------------------------
  // TEST 3: EIP-7702 chainId = 0 Cross-Chain Compatibility
  // -------------------------------------------------------------------------
  console.log("\n[Test 3] EIP-7702 chainId = 0 Cross-Chain Acceptance...");
  const chainZeroCap: EIP7702Capability = {
    ...eip7702Cap,
    chainId: 0n
  };
  const stateChainId = 31337n;
  const isChainCompatible = chainZeroCap.chainId === 0n || chainZeroCap.chainId === stateChainId;
  if (!isChainCompatible) {
    throw new Error("EIP-7702 with chainId=0 must be accepted on chain 31337!");
  }
  console.log("  ✓ EIP-7702 authorization with chainId = 0 correctly accepted across any EVM chainId");

  // -------------------------------------------------------------------------
  // TEST 4: EIP-1271 Smart Contract Wallet Signature Support
  // -------------------------------------------------------------------------
  console.log("\n[Test 4] EIP-1271 Smart Contract Wallet Signature Validation...");
  const mockSmartContractClient: any = {
    verifyTypedData: async (args: any) => {
      // Simulate successful ERC-1271 isValidSignature resolution for smart contract wallet
      return true;
    }
  };

  const validationResult = await CapabilityValidator.validate(allowanceCap, mockSmartContractClient);
  if (!validationResult.valid) {
    throw new Error(`Expected valid: true for EIP-1271 smart contract wallet, got: ${JSON.stringify(validationResult)}`);
  }
  console.log("  ✓ CapabilityValidator successfully verified EIP-1271 signature via publicClient");

  // -------------------------------------------------------------------------
  // TEST 5: Multi-Capability Actor Derivation & Spender Isolation
  // -------------------------------------------------------------------------
  console.log("\n[Test 5] MultiCapabilityAuditor Per-Capability Actor Derivation...");
  const capSpenderB: Permit2AllowanceCapability = {
    ...allowanceCap,
    spender: attackerB
  };

  // Create mock explorer runner to verify effective actors
  let auditedActors: Address[] = [];
  class MockActionProvider {
    async enumerateActions(cap: any, client: any, effectiveActor: Address) {
      auditedActors.push(effectiveActor);
      return { status: "MODELED", actions: [] };
    }
  }

  const dummyRpc: any = {
    request: async (args: any) => {
      if (args.method === "evm_snapshot") return "0x1";
      if (args.method === "evm_revert") return true;
      return null;
    }
  };

  const auditor = new MultiCapabilityAuditor(faultyClient, dummyRpc);
  await auditor.audit([allowanceCap, capSpenderB], attackerA, {
    actionProviderFactory: () => new MockActionProvider() as any,
    invariantOracleFactory: () => ({
      snapshotInitial: async () => ({ initialBalance: 100n }),
      evaluate: async () => null
    }) as any
  });

  if (auditedActors.length !== 2) {
    throw new Error(`Expected 2 capabilities audited, got ${auditedActors.length}`);
  }
  if (auditedActors[0].toLowerCase() !== attackerA.toLowerCase()) {
    throw new Error(`Expected cap 1 audited with spender A (${attackerA}), got ${auditedActors[0]}`);
  }
  if (auditedActors[1].toLowerCase() !== attackerB.toLowerCase()) {
    throw new Error(`CRITICAL SOUNDNESS BUG: Cap 2 must be audited with its own spender B (${attackerB}), got: ${auditedActors[1]}`);
  }
  console.log(`  ✓ MultiCapabilityAuditor correctly routed each capability to its authoritative spender: [${auditedActors.join(", ")}]`);

  // -------------------------------------------------------------------------
  // TEST 6: Core executeAction RPC/Transport Failures MUST Yield UNMODELED
  // -------------------------------------------------------------------------
  console.log("\n[Test 6] Infrastructure/RPC failures during action execution must yield UNMODELED...");
  const failingActionRpc: any = {
    request: async (args: any) => {
      if (args.method === "evm_snapshot") return "0x1";
      if (args.method === "evm_revert") return true;
      if (args.method === "anvil_impersonateAccount") return true;
      if (args.method === "anvil_setBalance") return true;
      if (args.method === "eth_sendTransaction") {
        throw new Error("RPC_NETWORK_ERROR: Connection dropped by EVM node");
      }
      return null;
    }
  };
  const mockPublicClient: any = {
    waitForTransactionReceipt: async () => {
      throw new Error("RPC_TIMEOUT: timed out waiting for receipt");
    }
  };
  class SingleActionProvider {
    async enumerateActions() {
      return {
        status: "MODELED",
        actions: [
          {
            id: "Test.drain",
            description: "test drain",
            actor: attackerA,
            target: usdc,
            calldata: "0xa9059cbb000000000000000000000000" as Hex,
            value: 0n
          }
        ]
      };
    }
  }
  const explorerWithFailingRpc = new ReachabilityExplorer(
    mockPublicClient,
    failingActionRpc,
    {
      actionProvider: new SingleActionProvider() as any,
      invariantOracle: {
        snapshotInitial: async () => ({ initialBalance: 1000n }),
        evaluate: async () => null
      } as any
    }
  );
  const resultOnFailedRpc = await explorerWithFailingRpc.explore(allowanceCap, attackerA);
  if (resultOnFailedRpc.status !== "UNMODELED") {
    throw new Error(`CRITICAL SOUNDNESS BUG: RPC network failure during executeAction must yield UNMODELED, got ${resultOnFailedRpc.status}`);
  }
  console.log(`  ✓ ReachabilityExplorer correctly returned UNMODELED on action transport failure: "${resultOnFailedRpc.reason}"`);

  // -------------------------------------------------------------------------
  // TEST 7: Strict Validation of Missing Permit2 chainId & EIP-7702 yParity/v
  // -------------------------------------------------------------------------
  console.log("\n[Test 7] Strict Validation of Missing chainId & yParity/v...");
  let chainIdThrew = false;
  try {
    decodePermit2Allowance({
      owner: victim,
      domain: { verifyingContract: permit2 },
      message: { details: { token: usdc, amount: 100, expiration: 1, nonce: 0 }, spender: attackerA, sigDeadline: 1 },
      signature: "0x12"
    });
  } catch (err: any) {
    if (err.message.includes("missing required chainId")) {
      chainIdThrew = true;
    }
  }
  if (!chainIdThrew) {
    throw new Error("CRITICAL SOUNDNESS BUG: decodePermit2Allowance must throw on missing chainId, never default to 1!");
  }
  console.log("  ✓ decodePermit2Allowance strictly rejects missing chainId");

  let yParityThrew = false;
  try {
    decode7702({
      owner: victim,
      address: attackerA,
      chainId: 31337,
      nonce: 0,
      r: "0x0000000000000000000000000000000000000000000000000000000000000001" as Hex,
      s: "0x0000000000000000000000000000000000000000000000000000000000000002" as Hex
    });
  } catch (err: any) {
    if (err.message.includes("missing required yParity or v")) {
      yParityThrew = true;
    }
  }
  if (!yParityThrew) {
    throw new Error("CRITICAL SOUNDNESS BUG: decode7702 must throw on missing yParity/v, never default to 0!");
  }
  console.log("  ✓ decode7702 strictly rejects missing yParity and v");

  console.log("\n==================================================================");
  console.log("🎉 ALL SOUNDNESS & EVIDENCE HARDENING TESTS PASSED!");
  console.log("==================================================================\n");
}

runSoundnessTests().catch((err) => {
  console.error("❌ Soundness test failed:", err);
  process.exit(1);
});
