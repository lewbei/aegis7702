import {
  createPublicClient,
  createWalletClient,
  http,
  parseUnits,
  Hex,
  encodeFunctionData,
  Address
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";
import { spawn, ChildProcess } from "child_process";
import { MultiCapabilityAuditor, CapabilitySet } from "./capability/multiAuditor.js";
import { EIP7702Capability } from "./capability/types.js";
import { decode7702 } from "./capability/decode7702.js";
import { ERC20_ABI } from "./capability/abis.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ANVIL_PORT = 8556;
const RPC_URL = `http://127.0.0.1:${ANVIL_PORT}`;

const VICTIM_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const victimAccount = privateKeyToAccount(VICTIM_PRIVATE_KEY);
const victim = victimAccount.address;

const ATTACKER_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const attackerAccount = privateKeyToAccount(ATTACKER_PRIVATE_KEY);
const attacker = attackerAccount.address;

const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";

function loadArtifact(relativePath: string): { abi: any; bytecode: Hex } {
  const artifactPath = path.resolve(__dirname, "../../contracts/out", relativePath);
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`Artifact not found at ${artifactPath}. Did you run 'forge build'?`);
  }
  const raw = JSON.parse(fs.readFileSync(artifactPath, "utf-8"));
  return {
    abi: raw.abi,
    bytecode: (raw.bytecode?.object || raw.bytecode) as Hex
  };
}

async function bootAnvil(): Promise<ChildProcess> {
  const proc = spawn(ANVIL_BIN, ["--port", String(ANVIL_PORT), "--hardfork", "prague", "--silent"]);
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(RPC_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] })
      });
      if (res.ok) return proc;
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  proc.kill("SIGTERM");
  throw new Error(`Failed to boot Anvil on port ${ANVIL_PORT}`);
}

async function runMultiAuditorTests() {
  console.log("==================================================================");
  console.log("    AEGIS7702: MULTI-CAPABILITY AUDITOR & INCOMPLETE REJECTION   ");
  console.log("    (Testing UNMODELED Incomplete Defense & Priority Invariants) ");
  console.log("==================================================================\n");

  const anvilProc = await bootAnvil();

  try {
    const publicClient = createPublicClient({
      chain: foundry,
      transport: http(RPC_URL),
      pollingInterval: 25
    });

    const deployerWallet = createWalletClient({
      chain: foundry,
      transport: http(RPC_URL),
      account: victimAccount,
      pollingInterval: 25
    });

    // 1. Deploy MockUSDC
    const usdcArtifact = loadArtifact("MockUSDC.sol/MockUSDC.json");
    const usdcDeployTx = await deployerWallet.deployContract({
      abi: usdcArtifact.abi,
      bytecode: usdcArtifact.bytecode
    });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcDeployTx });
    const usdcAddress = usdcReceipt.contractAddress!;

    // 2. Deploy MaliciousDelegate (vulnerable modeled delegate)
    const malArtifact = loadArtifact("MaliciousDelegate.sol/MaliciousDelegate.json");
    const malDeployTx = await deployerWallet.deployContract({
      abi: malArtifact.abi,
      bytecode: malArtifact.bytecode
    });
    const malReceipt = await publicClient.waitForTransactionReceipt({ hash: malDeployTx });
    const vulnerableDelegate = malReceipt.contractAddress!;

    // 3. Deploy PluginOnlyDelegate (novel/unsupported delegate with no modeled selectors)
    const pluginArtifact = loadArtifact("PluginOnlyDelegate.sol/PluginOnlyDelegate.json");
    const pluginDeployTx = await deployerWallet.deployContract({
      abi: pluginArtifact.abi,
      bytecode: pluginArtifact.bytecode
    });
    const pluginReceipt = await publicClient.waitForTransactionReceipt({ hash: pluginDeployTx });
    const unmodeledDelegate = pluginReceipt.contractAddress!;

    // 4. Seed victim with USDC balance
    const mintTx = await deployerWallet.writeContract({
      address: usdcAddress,
      abi: usdcArtifact.abi,
      functionName: "mint",
      args: [victim, parseUnits("1000", 6)]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintTx });

    // Build capabilities:
    // A) Supported harmless capability (points to clean EOA 0x000...0001 with 0 code)
    const nonce0 = await publicClient.getTransactionCount({ address: victim });
    const harmlessAuth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: "0x0000000000000000000000000000000000000001",
      chainId: 31337,
      nonce: nonce0
    });
    const harmlessCap: EIP7702Capability = decode7702({
      owner: victim,
      chainId: harmlessAuth.chainId,
      address: harmlessAuth.address,
      nonce: harmlessAuth.nonce,
      yParity: harmlessAuth.yParity,
      r: harmlessAuth.r,
      s: harmlessAuth.s,
      targetToken: usdcAddress
    });

    // B) Unsupported capability (points to unmodeled delegate with no built-in sweep selectors)
    const unmodeledAuth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: unmodeledDelegate,
      chainId: 31337,
      nonce: nonce0
    });
    const unmodeledCap: EIP7702Capability = decode7702({
      owner: victim,
      chainId: unmodeledAuth.chainId,
      address: unmodeledDelegate,
      nonce: unmodeledAuth.nonce,
      yParity: unmodeledAuth.yParity,
      r: unmodeledAuth.r,
      s: unmodeledAuth.s,
      targetToken: usdcAddress
    });

    // C) Vulnerable capability (points to malicious sweep delegate)
    const vulnerableAuth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: vulnerableDelegate,
      chainId: 31337,
      nonce: nonce0
    });
    const vulnerableCap: EIP7702Capability = decode7702({
      owner: victim,
      chainId: vulnerableAuth.chainId,
      address: vulnerableDelegate,
      nonce: vulnerableAuth.nonce,
      yParity: vulnerableAuth.yParity,
      r: vulnerableAuth.r,
      s: vulnerableAuth.s,
      targetToken: usdcAddress
    });

    const auditor = new MultiCapabilityAuditor(publicClient, publicClient as any);

    // -------------------------------------------------------------------------
    // TEST 1: Harmless + Unsupported Capability Portfolio
    // MUST return PORTFOLIO_INCOMPLETE (strictly forbidden to return SECURE or PORTFOLIO_NO_MODELED_LOSS)
    // -------------------------------------------------------------------------
    console.log("[Test 1] Auditing portfolio: [harmlessCap, unmodeledCap]...");
    const portfolioIncomplete: CapabilitySet = [harmlessCap, unmodeledCap];
    const res1 = await auditor.audit(portfolioIncomplete, attacker);

    if (res1.status !== "PORTFOLIO_INCOMPLETE") {
      throw new Error(`CRITICAL INVARIANT VIOLATION: Expected status 'PORTFOLIO_INCOMPLETE', got '${(res1 as any).status}'!`);
    }
    if ((res1 as any).status === "SECURE") {
      throw new Error("FORBIDDEN: Status SECURE must never be emitted when an unmodeled capability is present!");
    }
    if (res1.unmodeledCapabilities.length !== 1) {
      throw new Error(`Expected 1 unmodeled capability, got ${res1.unmodeledCapabilities.length}`);
    }
    console.log("  ✓ Correctly rejected unmodeled capability as PORTFOLIO_INCOMPLETE (UNMODELED != SECURE)");
    console.log(`    Status: ${res1.status}`);
    console.log(`    Unmodeled capabilities: ${res1.unmodeledCapabilities.length}`);
    console.log(`    Message: "${res1.message}"`);

    // -------------------------------------------------------------------------
    // TEST 2: All-Harmless Modeled Portfolio
    // MUST return PORTFOLIO_NO_MODELED_LOSS
    // -------------------------------------------------------------------------
    console.log("\n[Test 2] Auditing portfolio: [harmlessCap]...");
    const portfolioHarmless: CapabilitySet = [harmlessCap];
    const res2 = await auditor.audit(portfolioHarmless, attacker);

    if (res2.status !== "PORTFOLIO_NO_MODELED_LOSS") {
      throw new Error(`Expected status 'PORTFOLIO_NO_MODELED_LOSS', got '${res2.status}'!`);
    }
    if ((res2 as any).status === "SECURE") {
      throw new Error("FORBIDDEN: 'SECURE' is forbidden; must use asymmetric PORTFOLIO_NO_MODELED_LOSS!");
    }
    console.log("  ✓ All-modeled non-loss portfolio certified as PORTFOLIO_NO_MODELED_LOSS");
    console.log(`    Status: ${res2.status}`);
    console.log(`    Message: "${res2.message}"`);

    // -------------------------------------------------------------------------
    // TEST 3: Harmless + Unsupported + Vulnerable Portfolio
    // Priority Invariant: FOUND_LOSS strictly dominates UNMODELED => FOUND_RESIDUAL_LOSS
    // -------------------------------------------------------------------------
    console.log("\n[Test 3] Auditing portfolio: [harmlessCap, unmodeledCap, vulnerableCap]...");
    const portfolioMixed: CapabilitySet = [harmlessCap, unmodeledCap, vulnerableCap];
    const res3 = await auditor.audit(portfolioMixed, attacker);

    if (res3.status !== "FOUND_RESIDUAL_LOSS") {
      throw new Error(`Expected status 'FOUND_RESIDUAL_LOSS' (loss dominates), got '${res3.status}'!`);
    }
    console.log("  ✓ Loss dominance invariant verified: FOUND_RESIDUAL_LOSS takes strict precedence");
    console.log(`    Status: ${res3.status}`);
    console.log(`    Violating capability: ${res3.violatingCapability.kind}`);
    console.log(`    Discovered loss: ${res3.counterexample.counterexample.loss.amount} tokens`);

    console.log("\n==================================================================");
    console.log("🎉 ALL MULTI-CAPABILITY AUDITOR INVARIANT TESTS PASSED 100%!");
    console.log("==================================================================\n");
  } finally {
    anvilProc.kill("SIGTERM");
  }
}

runMultiAuditorTests().catch((err) => {
  console.error("❌ Test failed:", err);
  process.exit(1);
});
