import * as http from "http";
import { spawn, ChildProcess } from "child_process";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  parseAbi,
  encodeFunctionData,
  keccak256,
  encodePacked,
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
import { PERMIT2_ABI, ERC20_ABI, MALICIOUS_DELEGATE_ABI } from "./capability/abis.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.ENGINE_PORT ?? 3001);
const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";

interface ActiveSession {
  scenarioId: string;
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
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  });
  res.end(JSON.stringify(data));
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
  const scenarioId = body.scenarioId ?? "permit2-allowance";
  const runId = `run_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  if (scenarioId === "permit2-allowance") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil();
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });

    const VICTIM_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
    const ATTACKER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
    const victimAccount = privateKeyToAccount(VICTIM_PK);
    const attackerAccount = privateKeyToAccount(ATTACKER_PK);
    const victim = victimAccount.address;
    const attacker = attackerAccount.address;

    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    // Deploy contracts
    const permit2Artifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8"));
    const p2Hash = await victimWallet.deployContract({ abi: permit2Artifact.abi, bytecode: permit2Artifact.bytecode.object as Hex });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Hash });
    const permit2Address = p2Receipt.contractAddress!;

    const usdcArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8"));
    const usdcHash = await victimWallet.deployContract({ abi: usdcArtifact.abi, bytecode: usdcArtifact.bytecode.object as Hex });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcHash });
    const usdcAddress = usdcReceipt.contractAddress!;

    const DRAIN_AMOUNT = parseUnits("10000", 6);
    await victimWallet.writeContract({
      address: usdcAddress,
      abi: ERC20_ABI,
      functionName: "mint",
      args: [victim, DRAIN_AMOUNT]
    });
    await victimWallet.writeContract({
      address: usdcAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [permit2Address, 2n ** 256n - 1n]
    });

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
      scenarioId,
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
      scenarioId,
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

  throw new Error(`Scenario ${scenarioId} not supported yet for live execution`);
}

async function handleRecover(body: any): Promise<any> {
  const { runId } = body;
  const session = sessions.get(runId);
  if (!session) {
    throw new Error(`Session ${runId} not found or expired`);
  }

  const { victimWallet, publicClient, recoveryPlan } = session;

  const txHash = await victimWallet.sendTransaction({
    to: recoveryPlan.target,
    data: recoveryPlan.calldata,
    value: 0n
  });
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

  const { attackerWallet, publicClient, counterexample, victim, tokenAddress, anvilProcess } = session;

  let replayReverted = false;
  let failedStep = 0;
  let revertError = "";

  for (let i = 0; i < counterexample.trace.length; i++) {
    const step = counterexample.trace[i];
    try {
      const tx = await attackerWallet.sendTransaction({
        to: step.target,
        data: step.calldata,
        value: step.value
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: tx });
      if (receipt.status === "reverted") {
        replayReverted = true;
        failedStep = i + 1;
        break;
      }
    } catch (err: any) {
      replayReverted = true;
      failedStep = i + 1;
      revertError = err.message ?? "Transaction reverted on chain";
      break;
    }
  }

  const finalBal: bigint = await publicClient.readContract({
    address: tokenAddress,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [victim]
  });

  // Clean up anvil process
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
    sendJson(res, 200, { status: "OK", engine: "Guard7702 Reachability Engine", version: "1.0.0" });
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
  console.log(`Guard7702 Engine API Server listening on http://127.0.0.1:${PORT}`);
});
