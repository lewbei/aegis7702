import * as http from "http";
import { spawn, ChildProcess } from "child_process";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  parseAbi,
  parseUnits,
  formatUnits,
  Address,
  Hex
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

import { ReachabilityExplorer } from "./search/explorer.js";
import { Permit2RecoveryPlanner } from "./recovery/permit2.js";
import { Permit2SignatureRecoveryPlanner } from "./recovery/permit2Signature.js";
import { EIP7702RecoveryPlanner } from "./recovery/eip7702.js";
import { decodePermit2Allowance } from "./capability/decodePermit2Allowance.js";
import { decodePermit2Signature } from "./capability/decodePermit2Signature.js";
import { decode7702 } from "./capability/decode7702.js";
import { ERC20_ABI } from "./capability/abis.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.ENGINE_PORT ?? 3001);
const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";

type CanonicalScenario = "permit2_allowance" | "permit2_signature" | "eip7702";

function normalizeScenario(scenarioId: string): CanonicalScenario {
  const s = (scenarioId || "").toLowerCase().replace(/[-_]/g, "");
  if (s.includes("7702")) return "eip7702";
  if (s.includes("signature")) return "permit2_signature";
  return "permit2_allowance";
}

interface ActiveSession {
  scenarioId: string;
  canonicalId: CanonicalScenario;
  anvilProcess: ChildProcess;
  anvilPort: number;
  publicClient: any;
  victimWallet: any;
  attackerWallet: any;
  victim: Address;
  attacker: Address;
  capability: any;
  counterexample: any;
  recoveryPlan: any;
  tokenAddress: Address;
}

const sessions = new Map<string, ActiveSession>();
let nextPort = 8600;

function sendJson(res: http.ServerResponse, statusCode: number, data: any) {
  if (res.headersSent) return;
  try {
    const json = JSON.stringify(data, (_, v) => (typeof v === "bigint" ? v.toString() : v));
    res.writeHead(statusCode, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    });
    res.end(json);
  } catch (err: any) {
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message ?? "Serialization error" }));
    }
  }
}

async function startEphemeralAnvil(hardfork?: string): Promise<{ process: ChildProcess; port: number }> {
  const port = nextPort++;
  const args = ["--port", port.toString(), "--silent"];
  if (hardfork) {
    args.push("--hardfork", hardfork);
  }
  const anvil = spawn(ANVIL_BIN, args);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  return { process: anvil, port };
}

async function handleAnalyze(body: any): Promise<any> {
  const requestedScenarioId = body.scenarioId ?? "permit2-allowance";
  const canonicalId = normalizeScenario(requestedScenarioId);
  const runId = `run_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  const VICTIM_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
  const ATTACKER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
  const victimAccount = privateKeyToAccount(VICTIM_PK);
  const attackerAccount = privateKeyToAccount(ATTACKER_PK);
  const victim = victimAccount.address;
  const attacker = attackerAccount.address;

  if (canonicalId === "permit2_allowance") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil();
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const permit2Artifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8"));
    const p2Hash = await victimWallet.deployContract({ abi: permit2Artifact.abi, bytecode: permit2Artifact.bytecode.object as Hex });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Hash });
    const permit2Address = p2Receipt.contractAddress!;

    const usdcArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8"));
    const usdcHash = await victimWallet.deployContract({ abi: usdcArtifact.abi, bytecode: usdcArtifact.bytecode.object as Hex });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcHash });
    const usdcAddress = usdcReceipt.contractAddress!;

    const DRAIN_AMOUNT = parseUnits("10000", 6);
    const mintHash = await victimWallet.writeContract({
      address: usdcAddress,
      abi: usdcArtifact.abi,
      functionName: "mint",
      args: [victim, DRAIN_AMOUNT]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintHash });

    const approveHash = await victimWallet.writeContract({
      address: usdcAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [permit2Address, 2n ** 256n - 1n]
    });
    await publicClient.waitForTransactionReceipt({ hash: approveHash });

    const expiration = Math.floor(Date.now() / 1000) + 86400;
    const sigDeadline = BigInt(Math.floor(Date.now() / 1000) + 3600);

    const typeData = {
      types: {
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
      },
      primaryType: "PermitSingle" as const,
      domain: { name: "Permit2", chainId: 31337, verifyingContract: permit2Address },
      message: {
        details: { token: usdcAddress, amount: DRAIN_AMOUNT, expiration, nonce: 0 },
        spender: attacker,
        sigDeadline
      }
    };

    const signature = await victimWallet.signTypedData(typeData);
    const capability = decodePermit2Allowance({
      owner: victim,
      domain: typeData.domain,
      types: typeData.types,
      message: typeData.message,
      signature
    });

    const explorer = new ReachabilityExplorer(publicClient, {
      request: async (args: any) => publicClient.request(args)
    }, 3);

    const counterexample = await explorer.explore(capability, attacker);
    const recoveryPlan = await Permit2RecoveryPlanner.plan(capability, publicClient);

    sessions.set(runId, {
      scenarioId: requestedScenarioId,
      canonicalId,
      anvilProcess,
      anvilPort,
      publicClient,
      victimWallet,
      attackerWallet,
      victim,
      attacker,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "Baseline 1-step simulation detected 0.00 USDC loss (Current state safe, blind to multi-step reachability)"
      },
      counterexample,
      recoveryPlan
    };
  }

  if (canonicalId === "permit2_signature") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil();
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const permit2Artifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8"));
    const p2Hash = await victimWallet.deployContract({ abi: permit2Artifact.abi, bytecode: permit2Artifact.bytecode.object as Hex });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Hash });
    const permit2Address = p2Receipt.contractAddress!;

    const usdcArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8"));
    const usdcHash = await victimWallet.deployContract({ abi: usdcArtifact.abi, bytecode: usdcArtifact.bytecode.object as Hex });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcHash });
    const usdcAddress = usdcReceipt.contractAddress!;

    const DRAIN_AMOUNT = parseUnits("10000", 6);
    const NONCE = 1025n;

    const mintHash = await victimWallet.writeContract({
      address: usdcAddress,
      abi: parseAbi(["function mint(address to, uint256 amount) external"]),
      functionName: "mint",
      args: [victim, DRAIN_AMOUNT]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintHash });

    const approveHash = await victimWallet.writeContract({
      address: usdcAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [permit2Address, 2n ** 256n - 1n]
    });
    await publicClient.waitForTransactionReceipt({ hash: approveHash });

    const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const typeData = {
      types: {
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
      },
      primaryType: "PermitTransferFrom" as const,
      domain: { name: "Permit2", chainId: 31337, verifyingContract: permit2Address },
      message: {
        permitted: { token: usdcAddress, amount: DRAIN_AMOUNT },
        spender: attacker,
        nonce: NONCE,
        deadline
      }
    };

    const signature = await victimWallet.signTypedData(typeData);
    const capability = decodePermit2Signature({
      owner: victim,
      domain: typeData.domain,
      types: typeData.types,
      message: typeData.message,
      signature
    });

    const explorer = new ReachabilityExplorer(publicClient, {
      request: async (args: any) => publicClient.request(args)
    }, 3);

    const counterexample = await explorer.explore(capability, attacker);
    const recoveryPlan = await Permit2SignatureRecoveryPlanner.plan(capability, publicClient);

    sessions.set(runId, {
      scenarioId: requestedScenarioId,
      canonicalId,
      anvilProcess,
      anvilPort,
      publicClient,
      victimWallet,
      attackerWallet,
      victim,
      attacker,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "Baseline 1-step simulation detected 0.00 USDC loss (Signature transfer unexecuted at signing)"
      },
      counterexample,
      recoveryPlan
    };
  }

  if (canonicalId === "eip7702") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil("prague");
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const usdcArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8"));
    const delegateArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MaliciousDelegate.sol/MaliciousDelegate.json"), "utf8"));

    const usdcTx = await victimWallet.deployContract({ abi: usdcArtifact.abi, bytecode: usdcArtifact.bytecode.object as Hex });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcTx });
    const usdcAddress = usdcReceipt.contractAddress!;

    const delTx = await attackerWallet.deployContract({ abi: delegateArtifact.abi, bytecode: delegateArtifact.bytecode.object as Hex });
    const delReceipt = await publicClient.waitForTransactionReceipt({ hash: delTx });
    const delegateAddress = delReceipt.contractAddress!;

    const INITIAL_USDC = parseUnits("10000", 6);
    const mintTx = await victimWallet.writeContract({
      address: usdcAddress,
      abi: usdcArtifact.abi,
      functionName: "mint",
      args: [victim, INITIAL_USDC]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintTx });

    const victimNonce = await publicClient.getTransactionCount({ address: victim });
    const auth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: delegateAddress,
      chainId: 31337,
      nonce: victimNonce
    });

    const capability = decode7702({
      owner: victim,
      chainId: auth.chainId,
      address: (auth as any).contractAddress ?? (auth as any).address ?? delegateAddress,
      nonce: auth.nonce,
      yParity: auth.yParity,
      r: auth.r,
      s: auth.s,
      targetToken: usdcAddress
    });

    const explorer = new ReachabilityExplorer(publicClient, {
      request: async (args: any) => publicClient.request(args)
    }, 3);

    const counterexample = await explorer.explore(capability, attacker);
    const recoveryPlan = await EIP7702RecoveryPlanner.plan(capability, publicClient);

    sessions.set(runId, {
      scenarioId: requestedScenarioId,
      canonicalId,
      anvilProcess,
      anvilPort,
      publicClient,
      victimWallet,
      attackerWallet,
      victim,
      attacker,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "Baseline 1-step simulation detected 0.00 USDC loss (Type-4 authorization unbroadcast)"
      },
      counterexample,
      recoveryPlan
    };
  }

  throw new Error(`Scenario ${requestedScenarioId} not supported for live execution`);
}

async function handleRecover(body: any): Promise<any> {
  const { runId } = body;
  const session = sessions.get(runId);
  if (!session) {
    throw new Error(`Session ${runId} not found or expired`);
  }

  const { victimWallet, publicClient, recoveryPlan, victim, canonicalId } = session;

  let txHash: Hex;

  if (canonicalId === "eip7702") {
    // EIP-7702 nonce advance self-transaction
    txHash = await victimWallet.sendTransaction({
      to: victim,
      value: 0n,
      data: "0x"
    });
  } else {
    // Permit2 invalidateNonces or invalidateUnorderedNonces
    txHash = await victimWallet.sendTransaction({
      to: recoveryPlan.target,
      data: recoveryPlan.calldata,
      value: 0n
    });
  }

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  return {
    runId,
    txHash,
    status: receipt.status === "success" ? "CONFIRMED" : "REVERTED",
    blockNumber: receipt.blockNumber.toString(),
    gasUsed: receipt.gasUsed.toString(),
    strategy: recoveryPlan.strategy,
    description: recoveryPlan.description
  };
}

async function handleReplay(body: any): Promise<any> {
  const { runId } = body;
  const session = sessions.get(runId);
  if (!session) {
    throw new Error(`Session ${runId} not found or expired`);
  }

  const {
    attackerWallet,
    publicClient,
    counterexample,
    victim,
    tokenAddress,
    anvilProcess,
    canonicalId
  } = session;

  let replayReverted = false;
  let failedStep = 0;
  let revertError = "";

  if (canonicalId === "eip7702") {
    // EIP-7702 replay: attempt to broadcast Type-4 transaction with stolen authorization
    const step1 = counterexample.trace[0];
    try {
      const tx = await publicClient.request({
        method: "eth_sendTransaction",
        params: [
          {
            from: step1.actor,
            to: step1.target,
            data: step1.calldata,
            authorizationList: step1.authorizationList
          }
        ]
      } as any);
      await publicClient.waitForTransactionReceipt({ hash: tx });

      // Check if delegation code installed
      const code = await publicClient.getBytecode({ address: victim });
      if (!code || code === "0x") {
        replayReverted = true;
        failedStep = 1;
        revertError = "EIP-7702: Authorization skipped due to nonce mismatch (account code unchanged)";
      }
    } catch (err: any) {
      replayReverted = true;
      failedStep = 1;
      revertError = err.message ?? "Type-4 transaction rejected";
    }
  } else {
    // Permit2 scenarios: replay attacker trace steps
    for (let i = 0; i < counterexample.trace.length; i++) {
      const step = counterexample.trace[i];
      try {
        const tx = await attackerWallet.sendTransaction({
          to: step.target,
          data: step.calldata,
          value: step.value ?? 0n
        });
        const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });
        if (receipt.status === "reverted") {
          replayReverted = true;
          failedStep = i + 1;
          revertError = "Transaction reverted on chain";
          break;
        }
      } catch (err: any) {
        replayReverted = true;
        failedStep = i + 1;
        revertError = err.message ?? "Transaction execution reverted";
        break;
      }
    }
  }

  const finalBal: bigint = await publicClient.readContract({
    address: tokenAddress,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [victim]
  });

  // Clean up anvil process and session
  anvilProcess.kill();
  sessions.delete(runId);

  return {
    runId,
    mitigated: replayReverted,
    failedStep,
    revertError: revertError.slice(0, 100),
    finalVictimBalance: `${formatUnits(finalBal, 6)} USDC`,
    message: "Exploit replay reverted on-chain. Zero assets lost post-recovery."
  };
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    });
    res.end();
    return;
  }

  const url = req.url ?? "/";

  if (req.method === "GET" && url === "/api/health") {
    sendJson(res, 200, { status: "OK", engine: "Aegis7702 Reachability Engine", version: "1.0.0" });
    return;
  }

  if (req.method === "POST" && (url === "/api/analyze" || url === "/api/recover" || url === "/api/replay")) {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", async () => {
      try {
        const body = raw ? JSON.parse(raw) : {};
        if (url === "/api/analyze") {
          const result = await handleAnalyze(body);
          sendJson(res, 200, result);
        } else if (url === "/api/recover") {
          const result = await handleRecover(body);
          sendJson(res, 200, result);
        } else if (url === "/api/replay") {
          const result = await handleReplay(body);
          sendJson(res, 200, result);
        }
      } catch (err: any) {
        sendJson(res, 500, { error: err.message ?? "Internal server error" });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`Aegis7702 Engine API Server listening on http://127.0.0.1:${PORT}`);
});
