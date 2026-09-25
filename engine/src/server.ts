import http from "http";
import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as dns from "dns";
import { fileURLToPath } from "url";
import {
  createPublicClient,
  createWalletClient,
  http as viemHttp,
  parseUnits,
  formatUnits,
  encodeFunctionData,
  parseAbi,
  Hex,
  Address,
  getAddress
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";
import { ReachabilityExplorer } from "./search/explorer.js";
import { Permit2RecoveryPlanner } from "./recovery/permit2.js";
import { Permit2SignatureRecoveryPlanner } from "./recovery/permit2Signature.js";
import { EIP7702RecoveryPlanner } from "./recovery/eip7702.js";
import { decodePermit2Allowance } from "./capability/decodePermit2Allowance.js";
import { decodePermit2Signature } from "./capability/decodePermit2Signature.js";
import { decode7702 } from "./capability/decode7702.js";
import { ERC20_ABI, PERMIT2_ABI } from "./capability/abis.js";
import { CapabilityValidator } from "./capability/validator.js";
import {
  Capability,
  Permit2AllowanceCapability,
  Permit2SignatureCapability,
  VerificationOutcome,
  ProspectiveRisk
} from "./capability/types.js";
import { MultiCapabilityAuditor, CapabilitySet } from "./capability/multiAuditor.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.ENGINE_PORT ?? 3001);
const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";

export type CanonicalScenario =
  | "permit2_allowance"
  | "permit2_future_delta_65535"
  | "permit2_future_delta_65536"
  | "permit2_signature"
  | "eip7702"
  | "eip7702_future_nonce"
  | "eip7702_active_delegation"
  | "portfolio_residual_risk";

export function normalizeScenario(scenarioId: string): CanonicalScenario {
  if (typeof scenarioId !== "string" || !scenarioId.trim()) {
    throw new Error("Invalid scenario ID: must be a non-empty string");
  }
  const s = scenarioId.toLowerCase().replace(/[-_]/g, "");
  switch (s) {
    case "permit2allowance":
    case "permit2allowancetransfer":
      return "permit2_allowance";
    case "permit2futuredelta65535":
      return "permit2_future_delta_65535";
    case "permit2futuredelta65536":
      return "permit2_future_delta_65536";
    case "permit2signature":
    case "permit2signaturetransfer":
      return "permit2_signature";
    case "eip7702":
    case "eip7702prague":
      return "eip7702";
    case "eip7702futurenonce":
      return "eip7702_future_nonce";
    case "eip7702activedelegation":
      return "eip7702_active_delegation";
    case "portfolioresidualrisk":
    case "portfolioresidual":
      return "portfolio_residual_risk";
    default:
      throw new Error(`Unsupported scenario: ${scenarioId}`);
  }
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
  victimAccount: any;
  capability: any;
  capabilityPortfolio?: CapabilitySet;
  status: VerificationOutcome;
  counterexample: any;
  prospectiveRisk: ProspectiveRisk | null;
  recoveryPlan: any;
  tokenAddress: Address;
  delegateAddress?: Address;
  initialBalance: bigint;
  createdAt: number;
}

const sessions = new Map<string, ActiveSession>();
let nextPort = 8600;

let activeWorkers = 0;
const MAX_CONCURRENT_WORKERS = 4;
const WORKER_TIMEOUT_MS = Number(process.env.WORKER_TIMEOUT_MS ?? 30000);
const SESSION_TTL_MS = 10 * 60 * 1000; // 10 minutes

// Periodic session sweeper
setInterval(() => {
  const now = Date.now();
  for (const [id, sess] of sessions.entries()) {
    if (sess.createdAt && now - sess.createdAt > SESSION_TTL_MS) {
      try {
        sess.anvilProcess.kill();
      } catch {}
      sessions.delete(id);
    }
  }
}, 30000).unref();

export function isPrivateIp(ip: string): boolean {
  const ipv4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [_, o1, o2, o3, o4] = ipv4.map(Number);
    if (o1 === 0 || o1 === 10 || o1 === 127 || (o1 === 169 && o2 === 254) || (o1 === 172 && o2 >= 16 && o2 <= 31) || (o1 === 192 && o2 === 168) || o1 >= 224) {
      return true;
    }
    return false;
  }
  const norm = ip.toLowerCase();
  if (
    norm === "::1" ||
    norm === "::" ||
    norm.startsWith("fe80:") ||
    norm.startsWith("fc") ||
    norm.startsWith("fd") ||
    norm.includes("127.0.0.1")
  ) {
    return true;
  }
  return false;
}

export async function validateForkUrl(urlStr: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new Error(`Invalid forkUrl format: ${urlStr}`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Invalid forkUrl protocol '${parsed.protocol}'. Only http/https are allowed.`);
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block localhost / loopback / cloud metadata endpoints immediately
  if (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "0.0.0.0" ||
    hostname === "::1" ||
    hostname === "metadata.google.internal" ||
    hostname === "169.254.169.254"
  ) {
    throw new Error(`SSRF rejected: forkUrl targeting loopback/metadata endpoint (${hostname}) is forbidden`);
  }

  if (isPrivateIp(hostname)) {
    throw new Error(`SSRF rejected: forkUrl targeting private/internal IP (${hostname}) is forbidden`);
  }

  // Resolve DNS A and AAAA records to prevent DNS rebinding / internal resolution bypass
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true });
    for (const record of addresses) {
      if (isPrivateIp(record.address)) {
        throw new Error(
          `SSRF rejected: hostname '${hostname}' resolves to forbidden internal IP (${record.address})`
        );
      }
    }
  } catch (err: any) {
    if (err.message && err.message.startsWith("SSRF rejected")) {
      throw err;
    }
    throw new Error(`SSRF rejected: cannot resolve forkUrl hostname '${hostname}': ${err.code ?? err.message}`);
  }
}

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

async function startEphemeralAnvil(hardfork?: string, forkUrl?: string): Promise<{ process: ChildProcess; port: number }> {
  if (forkUrl) {
    await validateForkUrl(forkUrl);
  }

  if (activeWorkers >= MAX_CONCURRENT_WORKERS) {
    throw new Error(
      `Worker pool saturated: maximum concurrent analysis limit (${MAX_CONCURRENT_WORKERS}) reached. Please retry.`
    );
  }

  activeWorkers++;
  const port = nextPort++;
  const args = ["--port", port.toString(), "--silent"];
  if (hardfork) {
    args.push("--hardfork", hardfork);
  }
  if (forkUrl) {
    args.push("--fork-url", forkUrl);
  }
  const anvil = spawn(ANVIL_BIN, args);

  let decremented = false;
  const decrement = () => {
    if (!decremented) {
      decremented = true;
      activeWorkers = Math.max(0, activeWorkers - 1);
    }
  };
  anvil.once("exit", decrement);
  anvil.once("close", decrement);
  anvil.once("error", decrement);

  await new Promise((resolve) => setTimeout(resolve, 1500));
  return { process: anvil, port };
}

async function handleAnalyze(body: any): Promise<any> {
  const requestedScenarioId = body.scenarioId ?? "permit2_allowance";
  const canonicalId = normalizeScenario(requestedScenarioId);
  const runId = `run_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  const VICTIM_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
  const ATTACKER_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
  const victimAccount = privateKeyToAccount(VICTIM_PK);
  const attackerAccount = privateKeyToAccount(ATTACKER_PK);
  const victim = victimAccount.address;
  const attacker = attackerAccount.address;

  if (
    canonicalId === "permit2_allowance" ||
    canonicalId === "permit2_future_delta_65535" ||
    canonicalId === "permit2_future_delta_65536"
  ) {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil();
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const permit2Artifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8")
    );
    const p2Hash = await victimWallet.deployContract({
      abi: permit2Artifact.abi,
      bytecode: permit2Artifact.bytecode.object as Hex
    });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Hash });
    const permit2Address = p2Receipt.contractAddress!;

    const usdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const usdcHash = await victimWallet.deployContract({
      abi: usdcArtifact.abi,
      bytecode: usdcArtifact.bytecode.object as Hex
    });
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

    let signedNonce = 0;
    if (canonicalId === "permit2_future_delta_65535") {
      signedNonce = 65534; // target will be 65535, delta = 65535 (single chunk limit)
    } else if (canonicalId === "permit2_future_delta_65536") {
      signedNonce = 65535; // target will be 65536, delta = 65536 (requires multi-chunk: 65535 + 1)
    }

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
        details: { token: usdcAddress, amount: DRAIN_AMOUNT, expiration, nonce: signedNonce },
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

    const explorer = new ReachabilityExplorer(
      publicClient,
      { request: async (args: any) => publicClient.request(args) },
      3
    );

    const exploreRes = await explorer.explore(capability, attacker);
    let status: VerificationOutcome = exploreRes.status;
    const counterexample: any = exploreRes.status === "FOUND_LOSS" ? exploreRes.counterexample : null;
    let prospectiveRisk: ProspectiveRisk | null = null;

    if (exploreRes.status !== "FOUND_LOSS") {
      if (canonicalId === "permit2_future_delta_65535" || canonicalId === "permit2_future_delta_65536") {
        status = "CONDITIONAL_RISK";
        const permitCalldata = encodeFunctionData({
          abi: PERMIT2_ABI,
          functionName: "permit",
          args: [
            victim,
            {
              details: {
                token: capability.details.token,
                amount: capability.details.amount,
                expiration: capability.details.expiration,
                nonce: capability.details.nonce
              },
              spender: capability.spender,
              sigDeadline: capability.sigDeadline
            },
            capability.signature
          ]
        });

        const transferCalldata = encodeFunctionData({
          abi: PERMIT2_ABI,
          functionName: "transferFrom",
          args: [victim, attacker, capability.details.amount, capability.details.token]
        });

        prospectiveRisk = {
          condition: `Permit2 allowance signed with future nonce ${capability.details.nonce} (current on-chain nonce: 0). Activates when on-chain nonce reaches ${capability.details.nonce}.`,
          candidateTrace: [
            {
              id: "Permit2.permit",
              description: `Attacker submits signed PermitSingle for nonce ${capability.details.nonce}`,
              target: permit2Address,
              calldata: permitCalldata,
              value: 0n,
              actor: attacker
            },
            {
              id: "Permit2.transferFrom",
              description: `Attacker drains ${formatUnits(capability.details.amount, 6)} USDC via transferFrom`,
              target: permit2Address,
              calldata: transferCalldata,
              value: 0n,
              actor: attacker
            }
          ],
          projectedLoss: {
            token: usdcAddress,
            symbol: "USDC",
            amount: capability.details.amount.toString(),
            formatted: formatUnits(capability.details.amount, 6)
          }
        };
      }
    }

    const recoveryPlan = await Permit2RecoveryPlanner.plan(capability, publicClient);

    const [allowedAmount, , permitNonce] = await publicClient.readContract({
      address: permit2Address,
      abi: PERMIT2_ABI,
      functionName: "allowance",
      args: [victim, capability.details.token, capability.spender]
    });

    const authoritativePreconditions = {
      accountAddress: victim,
      permit2Address,
      token: capability.details.token,
      spender: capability.spender,
      expectedPermitNonce: Number(permitNonce),
      expectedAllowedAmount: allowedAmount.toString(),
      chainId: Number(capability.chainId)
    };

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
      victimAccount,
      capability,
      capabilityPortfolio: [capability],
      status,
      counterexample,
      prospectiveRisk,
      recoveryPlan,
      tokenAddress: usdcAddress,
      initialBalance: DRAIN_AMOUNT,
      authoritativePreconditions,
      createdAt: Date.now()
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      status,
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "B₀ verdict SAFE under immediate-delta criterion only (0.00 USDC loss at Step 0; detached capability unconsumed at signing)"
      },
      counterexample,
      prospectiveRisk,
      recoveryPlan
    };
  }

  if (canonicalId === "permit2_signature") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil();
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const permit2Artifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8")
    );
    const p2Hash = await victimWallet.deployContract({
      abi: permit2Artifact.abi,
      bytecode: permit2Artifact.bytecode.object as Hex
    });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Hash });
    const permit2Address = p2Receipt.contractAddress!;

    const usdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const usdcHash = await victimWallet.deployContract({
      abi: usdcArtifact.abi,
      bytecode: usdcArtifact.bytecode.object as Hex
    });
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

    const explorer = new ReachabilityExplorer(
      publicClient,
      { request: async (args: any) => publicClient.request(args) },
      3
    );

    const exploreRes = await explorer.explore(capability, attacker);
    const status: VerificationOutcome = exploreRes.status;
    const counterexample = exploreRes.status === "FOUND_LOSS" ? exploreRes.counterexample : null;
    const prospectiveRisk: ProspectiveRisk | null = null;
    const recoveryPlan = await Permit2SignatureRecoveryPlanner.plan(capability, publicClient);

    const wordPos = capability.nonce >> 8n;
    const currentWord: bigint = await publicClient.readContract({
      address: permit2Address,
      abi: PERMIT2_ABI,
      functionName: "nonceBitmap",
      args: [victim, wordPos]
    });

    const authoritativePreconditions = {
      accountAddress: victim,
      permit2Address,
      wordPos: wordPos.toString(),
      expectedNonceBitmapWord: currentWord.toString(),
      chainId: Number(capability.chainId)
    };

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
      victimAccount,
      capability,
      capabilityPortfolio: [capability],
      status,
      counterexample,
      prospectiveRisk,
      recoveryPlan,
      tokenAddress: usdcAddress,
      initialBalance: DRAIN_AMOUNT,
      authoritativePreconditions,
      createdAt: Date.now()
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      status,
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "B₀ verdict SAFE under immediate-delta criterion only (0.00 USDC loss at Step 0; signature transfer unexecuted at signing)"
      },
      counterexample,
      prospectiveRisk,
      recoveryPlan
    };
  }

  if (
    canonicalId === "eip7702" ||
    canonicalId === "eip7702_future_nonce" ||
    canonicalId === "eip7702_active_delegation"
  ) {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil("prague");
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const usdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const delegateArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MaliciousDelegate.sol/MaliciousDelegate.json"), "utf8")
    );

    const usdcTx = await victimWallet.deployContract({
      abi: usdcArtifact.abi,
      bytecode: usdcArtifact.bytecode.object as Hex
    });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcTx });
    const usdcAddress = usdcReceipt.contractAddress!;

    const delTx = await attackerWallet.deployContract({
      abi: delegateArtifact.abi,
      bytecode: delegateArtifact.bytecode.object as Hex
    });
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

    let signedNonce: number;

    if (canonicalId === "eip7702_future_nonce") {
      // Advance victim nonce to 5 via dummy self-transactions
      let currNonce = await publicClient.getTransactionCount({ address: victim });
      while (currNonce < 5) {
        const dummyTx = await victimWallet.sendTransaction({
          to: victim,
          value: 0n,
          data: "0x"
        });
        await publicClient.waitForTransactionReceipt({ hash: dummyTx });
        currNonce = await publicClient.getTransactionCount({ address: victim });
      }
      signedNonce = 8;
    } else {
      signedNonce = await publicClient.getTransactionCount({ address: victim });
    }

    const auth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: delegateAddress,
      chainId: 31337,
      nonce: signedNonce
    });

    if (canonicalId === "eip7702_active_delegation") {
      // Attacker pre-installs active delegation on victim EOA
      const installTx = await publicClient.request({
        method: "eth_sendTransaction",
        params: [
          {
            from: attacker,
            to: victim,
            data: "0x",
            authorizationList: [auth]
          }
        ]
      } as any);
      await publicClient.waitForTransactionReceipt({ hash: installTx });
    }

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

    const explorer = new ReachabilityExplorer(
      publicClient,
      { request: async (args: any) => publicClient.request(args) },
      3
    );

    const exploreRes = await explorer.explore(capability, attacker);
    let status: VerificationOutcome = exploreRes.status;
    const counterexample: any = exploreRes.status === "FOUND_LOSS" ? exploreRes.counterexample : null;
    let prospectiveRisk: ProspectiveRisk | null = null;

    if (exploreRes.status !== "FOUND_LOSS") {
      if (canonicalId === "eip7702_future_nonce") {
        status = "CONDITIONAL_RISK";
        const sweepCalldata = encodeFunctionData({
          abi: delegateArtifact.abi,
          functionName: "sweep",
          args: [usdcAddress, attacker]
        });
        prospectiveRisk = {
          condition: `EIP-7702 authorization signed for future account nonce ${auth.nonce} (current on-chain nonce: ${signedNonce === 8 ? 5 : 0}). Activates when victim account nonce reaches ${auth.nonce} without revocation.`,
          candidateTrace: [
            {
              id: "EIP7702.Type4Relay",
              description: `Attacker broadcasts Type-4 transaction with authorization tuple once victim account nonce reaches ${auth.nonce}`,
              target: victim,
              calldata: "0x",
              value: 0n,
              actor: attacker,
              authorizationList: [auth]
            },
            {
              id: "MaliciousDelegate.sweep",
              description: `Attacker calls sweep() to drain ${formatUnits(INITIAL_USDC, 6)} USDC`,
              target: victim,
              calldata: sweepCalldata,
              value: 0n,
              actor: attacker
            }
          ],
          projectedLoss: {
            token: usdcAddress,
            symbol: "USDC",
            amount: INITIAL_USDC.toString(),
            formatted: formatUnits(INITIAL_USDC, 6)
          }
        };
      }
    }

    const recoveryPlan = await EIP7702RecoveryPlanner.plan(capability, publicClient);

    const actualAccountNonce = await publicClient.getTransactionCount({ address: victim });
    const actualBytecode = (await publicClient.getBytecode({ address: victim })) ?? "0x";
    const actualActiveDelegation = Boolean(
      actualBytecode.length >= 48 && actualBytecode.toLowerCase().startsWith("0xef0100")
    );

    const authoritativePreconditions = {
      accountAddress: victim,
      expectedAccountNonce: actualAccountNonce,
      expectedBytecode: actualBytecode,
      expectedActiveDelegation: actualActiveDelegation,
      chainId: Number(capability.chainId)
    };

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
      victimAccount,
      capability,
      capabilityPortfolio: [capability],
      status,
      counterexample,
      prospectiveRisk,
      recoveryPlan,
      tokenAddress: usdcAddress,
      delegateAddress,
      initialBalance: INITIAL_USDC,
      authoritativePreconditions,
      createdAt: Date.now()
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      status,
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "B₀ verdict SAFE under immediate-delta criterion only (0.00 USDC loss at Step 0; detached capability unconsumed at signing)"
      },
      counterexample,
      prospectiveRisk,
      recoveryPlan
    };
  }

  if (canonicalId === "portfolio_residual_risk") {
    const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil("prague");
    const rpcUrl = `http://127.0.0.1:${anvilPort}`;
    const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: viemHttp(rpcUrl) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: viemHttp(rpcUrl) });

    const usdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const delegateArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MaliciousDelegate.sol/MaliciousDelegate.json"), "utf8")
    );
    const permit2Artifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8")
    );

    const usdcTx = await victimWallet.deployContract({
      abi: usdcArtifact.abi,
      bytecode: usdcArtifact.bytecode.object as Hex
    });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcTx });
    const usdcAddress = usdcReceipt.contractAddress!;

    const delTx = await attackerWallet.deployContract({
      abi: delegateArtifact.abi,
      bytecode: delegateArtifact.bytecode.object as Hex
    });
    const delReceipt = await publicClient.waitForTransactionReceipt({ hash: delTx });
    const delegateAddress = delReceipt.contractAddress!;

    const p2Tx = await victimWallet.deployContract({
      abi: permit2Artifact.abi,
      bytecode: permit2Artifact.bytecode.object as Hex
    });
    const p2Receipt = await publicClient.waitForTransactionReceipt({ hash: p2Tx });
    const permit2Address = p2Receipt.contractAddress!;

    const INITIAL_USDC = parseUnits("10000", 6);
    const mintTx = await victimWallet.writeContract({
      address: usdcAddress,
      abi: usdcArtifact.abi,
      functionName: "mint",
      args: [victim, INITIAL_USDC]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintTx });

    // Setup Permit2 approval & signed allowance
    const approveTx = await victimWallet.writeContract({
      address: usdcAddress,
      abi: ERC20_ABI,
      functionName: "approve",
      args: [permit2Address, 2n ** 256n - 1n]
    });
    await publicClient.waitForTransactionReceipt({ hash: approveTx });

    const expiration = Math.floor(Date.now() / 1000) + 86400;
    const sigDeadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const p2TypeData = {
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
        details: { token: usdcAddress, amount: parseUnits("5000", 6), expiration, nonce: 0 },
        spender: attacker,
        sigDeadline
      }
    };
    const p2Sig = await victimWallet.signTypedData(p2TypeData);
    const permit2Cap = decodePermit2Allowance({
      owner: victim,
      domain: p2TypeData.domain,
      types: p2TypeData.types,
      message: p2TypeData.message,
      signature: p2Sig
    });

    // Setup EIP-7702 active delegation
    const signedNonce = await publicClient.getTransactionCount({ address: victim });
    const auth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: delegateAddress,
      chainId: 31337,
      nonce: signedNonce
    });

    const installTx = await publicClient.request({
      method: "eth_sendTransaction",
      params: [
        {
          from: attacker,
          to: victim,
          data: "0x",
          authorizationList: [auth]
        }
      ]
    } as any);
    await publicClient.waitForTransactionReceipt({ hash: installTx });

    const eip7702Cap = decode7702({
      owner: victim,
      chainId: auth.chainId,
      address: delegateAddress,
      nonce: auth.nonce,
      yParity: auth.yParity,
      r: auth.r,
      s: auth.s,
      targetToken: usdcAddress
    });

    const capabilityPortfolio: CapabilitySet = [eip7702Cap, permit2Cap];

    const explorer = new ReachabilityExplorer(
      publicClient,
      { request: async (args: any) => publicClient.request(args) },
      3
    );
    const exploreRes = await explorer.explore(eip7702Cap, attacker);
    const status: VerificationOutcome = exploreRes.status;
    const counterexample: any = exploreRes.status === "FOUND_LOSS" ? exploreRes.counterexample : null;

    const recoveryPlan = await EIP7702RecoveryPlanner.plan(eip7702Cap, publicClient);

    const actualAccountNonce = await publicClient.getTransactionCount({ address: victim });
    const actualBytecode = (await publicClient.getBytecode({ address: victim })) ?? "0x";
    const actualActiveDelegation = Boolean(
      actualBytecode.length >= 48 && actualBytecode.toLowerCase().startsWith("0xef0100")
    );

    const authoritativePreconditions: any = {
      expectedAccountNonce: actualAccountNonce,
      expectedBytecode: actualBytecode,
      expectedActiveDelegation: actualActiveDelegation
    };

    if (permit2Address && usdcAddress && attacker) {
      try {
        const [actualAllowedAmount, , actualPermitNonce] = await publicClient.readContract({
          address: permit2Address,
          abi: PERMIT2_ABI,
          functionName: "allowance",
          args: [victim, usdcAddress, attacker]
        });
        authoritativePreconditions.expectedPermitNonce = actualPermitNonce;
        authoritativePreconditions.expectedAllowedAmount = actualAllowedAmount;
        authoritativePreconditions.token = usdcAddress;
        authoritativePreconditions.spender = attacker;
        authoritativePreconditions.permit2Address = permit2Address;
      } catch {
        // Permit2 not deployed in scenario
      }
    }

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
      victimAccount,
      capability: eip7702Cap,
      capabilityPortfolio,
      status,
      counterexample,
      prospectiveRisk: null,
      recoveryPlan,
      tokenAddress: usdcAddress,
      delegateAddress,
      initialBalance: INITIAL_USDC,
      authoritativePreconditions,
      createdAt: Date.now()
    });

    return {
      runId,
      scenarioId: requestedScenarioId,
      canonicalId,
      port: anvilPort,
      engineStatus: "LIVE_ANVIL",
      status,
      baseline: {
        lossAmount: "0.00",
        lossSymbol: "USDC",
        verdict: "SAFE",
        message: "B₀ verdict SAFE under immediate-delta criterion only"
      },
      counterexample,
      prospectiveRisk: null,
      recoveryPlan,
      portfolioCount: capabilityPortfolio.length
    };
  }

  throw new Error(`Scenario ${requestedScenarioId} not supported for live execution`);
}

async function handleRecover(body: any): Promise<any> {
  const {
    runId,
    expectedAccountNonce,
    expectedActiveDelegation,
    expectedBytecode,
    expectedPermitNonce,
    expectedAllowedAmount,
    expectedNonceBitmapWord,
    token,
    spender,
    wordPos
  } = body;
  const session = sessions.get(runId);
  if (!session) {
    throw new Error(`Session ${runId} not found or expired`);
  }

  const { victimWallet, publicClient, recoveryPlan, victim, canonicalId, victimAccount } = session;

  const authPreconditions = session.authoritativePreconditions ?? {};
  // Authoritative trust boundary: Stored session preconditions MUST take precedence
  // over untrusted client parameters to prevent client-controlled race suppression.
  const effectiveAccountNonce = authPreconditions.expectedAccountNonce !== undefined ? authPreconditions.expectedAccountNonce : expectedAccountNonce;
  const effectiveActiveDelegation = authPreconditions.expectedActiveDelegation !== undefined ? authPreconditions.expectedActiveDelegation : expectedActiveDelegation;
  const effectiveBytecode = authPreconditions.expectedBytecode !== undefined ? authPreconditions.expectedBytecode : expectedBytecode;
  const effectivePermitNonce = authPreconditions.expectedPermitNonce !== undefined ? authPreconditions.expectedPermitNonce : expectedPermitNonce;
  const effectiveAllowedAmount = authPreconditions.expectedAllowedAmount !== undefined ? authPreconditions.expectedAllowedAmount : expectedAllowedAmount;
  const effectiveNonceBitmapWord = authPreconditions.expectedNonceBitmapWord !== undefined ? authPreconditions.expectedNonceBitmapWord : expectedNonceBitmapWord;
  const effectiveToken =
    token ??
    authPreconditions.token ??
    (session.capability as any)?.details?.token ??
    (session.capability as any)?.tokenAddress ??
    (session.capability as any)?.permitted?.token ??
    session.tokenAddress;
  const effectiveSpender =
    spender ??
    authPreconditions.spender ??
    (session.capability as any)?.spender ??
    session.attacker;
  const effectiveWordPos =
    wordPos ??
    authPreconditions.wordPos ??
    ((session.capability as any)?.nonce !== undefined ? (session.capability as any).nonce >> 8n : undefined);
  const effectivePermit2 =
    body.permit2Address ??
    (session.capability as any)?.permit2Address ??
    authPreconditions.permit2Address ??
    session.permit2Address;

  // Precondition Defense against State-Race Regressions & Client Overrides
  if (
    expectedAccountNonce !== undefined &&
    authPreconditions.expectedAccountNonce !== undefined &&
    BigInt(expectedAccountNonce) !== BigInt(authPreconditions.expectedAccountNonce)
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected account nonce (${expectedAccountNonce}) contradicts authoritative session precondition (${authPreconditions.expectedAccountNonce}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (
    expectedActiveDelegation !== undefined &&
    authPreconditions.expectedActiveDelegation !== undefined &&
    Boolean(expectedActiveDelegation) !== Boolean(authPreconditions.expectedActiveDelegation)
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected active delegation (${expectedActiveDelegation}) contradicts authoritative session precondition (${authPreconditions.expectedActiveDelegation}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (
    expectedBytecode !== undefined &&
    authPreconditions.expectedBytecode !== undefined &&
    String(expectedBytecode).toLowerCase() !== String(authPreconditions.expectedBytecode).toLowerCase()
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected bytecode (${expectedBytecode}) contradicts authoritative session precondition (${authPreconditions.expectedBytecode}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (
    expectedPermitNonce !== undefined &&
    authPreconditions.expectedPermitNonce !== undefined &&
    BigInt(expectedPermitNonce) !== BigInt(authPreconditions.expectedPermitNonce)
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected Permit2 nonce (${expectedPermitNonce}) contradicts authoritative session precondition (${authPreconditions.expectedPermitNonce}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (
    expectedAllowedAmount !== undefined &&
    authPreconditions.expectedAllowedAmount !== undefined &&
    BigInt(expectedAllowedAmount) !== BigInt(authPreconditions.expectedAllowedAmount)
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected Permit2 allowed amount (${expectedAllowedAmount}) contradicts authoritative session precondition (${authPreconditions.expectedAllowedAmount}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (
    expectedNonceBitmapWord !== undefined &&
    authPreconditions.expectedNonceBitmapWord !== undefined &&
    BigInt(expectedNonceBitmapWord) !== BigInt(authPreconditions.expectedNonceBitmapWord)
  ) {
    return {
      runId,
      status: "STATE_PRECONDITION_FAILED",
      reason: `Client expected Permit2 nonce bitmap word (${expectedNonceBitmapWord}) contradicts authoritative session precondition (${authPreconditions.expectedNonceBitmapWord}). Recovery aborted.`,
      totalTxsExecuted: 0
    };
  }

  if (effectiveAccountNonce !== undefined) {
    const actualNonce = await publicClient.getTransactionCount({ address: victim });
    if (BigInt(actualNonce) !== BigInt(effectiveAccountNonce)) {
      return {
        runId,
        status: "STATE_PRECONDITION_FAILED",
        reason: `State race detected: on-chain account nonce changed from ${effectiveAccountNonce} to ${actualNonce}. Recovery aborted to prevent state regression.`,
        totalTxsExecuted: 0
      };
    }
  }

  if (effectiveActiveDelegation !== undefined) {
    const actualCode = (await publicClient.getBytecode({ address: victim })) ?? "0x";
    const currentlyDelegated = Boolean(
      actualCode.length >= 48 && actualCode.toLowerCase().startsWith("0xef0100")
    );
    if (currentlyDelegated !== Boolean(effectiveActiveDelegation)) {
      return {
        runId,
        status: "STATE_PRECONDITION_FAILED",
        reason: `State race detected: on-chain delegation state changed (expected active: ${effectiveActiveDelegation}, actual: ${currentlyDelegated}). Recovery aborted to prevent state regression.`,
        totalTxsExecuted: 0
      };
    }
  }

  if (effectiveBytecode !== undefined) {
    const actualCode = (await publicClient.getBytecode({ address: victim })) ?? "0x";
    if (actualCode.toLowerCase() !== String(effectiveBytecode).toLowerCase()) {
      return {
        runId,
        status: "STATE_PRECONDITION_FAILED",
        reason: `State race detected: on-chain account bytecode changed (expected: ${effectiveBytecode}, actual: ${actualCode}). Recovery aborted to prevent state regression.`,
        totalTxsExecuted: 0
      };
    }
  }

  if (effectivePermitNonce !== undefined || effectiveAllowedAmount !== undefined) {
    if (effectivePermit2 && effectiveToken && effectiveSpender) {
      const [actualAllowedAmount, , actualPermitNonce] = await publicClient.readContract({
        address: effectivePermit2,
        abi: PERMIT2_ABI,
        functionName: "allowance",
        args: [victim, effectiveToken, effectiveSpender]
      });

      if (effectivePermitNonce !== undefined && BigInt(actualPermitNonce) !== BigInt(effectivePermitNonce)) {
        return {
          runId,
          status: "STATE_PRECONDITION_FAILED",
          reason: `State race detected: Permit2 allowance nonce changed from ${effectivePermitNonce} to ${actualPermitNonce}. Recovery aborted to prevent state regression.`,
          totalTxsExecuted: 0
        };
      }

      if (effectiveAllowedAmount !== undefined && BigInt(actualAllowedAmount) !== BigInt(effectiveAllowedAmount)) {
        return {
          runId,
          status: "STATE_PRECONDITION_FAILED",
          reason: `State race detected: Permit2 allowed amount changed from ${effectiveAllowedAmount} to ${actualAllowedAmount}. Recovery aborted to prevent state regression.`,
          totalTxsExecuted: 0
        };
      }
    }
  }

  if (effectiveNonceBitmapWord !== undefined) {
    const calcWordPos =
      effectiveWordPos !== undefined
        ? BigInt(effectiveWordPos)
        : (session.capability as any)?.nonce !== undefined
        ? (session.capability as any).nonce >> 8n
        : undefined;

    if (effectivePermit2 && calcWordPos !== undefined) {
      const actualWord: bigint = await publicClient.readContract({
        address: effectivePermit2,
        abi: PERMIT2_ABI,
        functionName: "nonceBitmap",
        args: [victim, calcWordPos]
      });

      if (BigInt(actualWord) !== BigInt(effectiveNonceBitmapWord)) {
        return {
          runId,
          status: "STATE_PRECONDITION_FAILED",
          reason: `State race detected: Permit2 signature nonce bitmap word changed (expected: ${effectiveNonceBitmapWord}, actual: ${actualWord}). Recovery aborted to prevent state regression.`,
          totalTxsExecuted: 0
        };
      }
    }
  }

  let txHash: Hex = "0x";
  let totalTxsExecuted = 0;

  if (
    canonicalId === "eip7702" ||
    canonicalId === "eip7702_future_nonce" ||
    canonicalId === "eip7702_active_delegation" ||
    canonicalId === "portfolio_residual_risk"
  ) {
    switch (recoveryPlan.strategy) {
      case "ADVANCE_NONCE":
      case "FUTURE_NONCE_MULTI_ADVANCE": {
        const txs = recoveryPlan.transactions ?? [{ to: victim, value: 0n, data: "0x" }];
        totalTxsExecuted = txs.length;
        for (let i = 0; i < txs.length; i++) {
          const tx = txs[i];
          txHash = await victimWallet.sendTransaction({
            to: tx.to ?? victim,
            value: tx.value ?? 0n,
            data: tx.data ?? "0x"
          });
          const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
          if (receipt.status !== "success") {
            return {
              runId,
              status: "RECOVERY_PARTIAL_FAILURE",
              message: `Recovery transaction ${i + 1}/${txs.length} reverted on-chain (txHash: ${txHash})`,
              failedTxIndex: i,
              totalTxsExecuted: i + 1,
              txHash,
              postRecoveryVerified: false
            };
          }
        }
        break;
      }
      case "CLEAR_DELEGATION": {
        const currentVictimNonce = await publicClient.getTransactionCount({ address: victim });
        const chainId = recoveryPlan.recoveryDelegation?.chainId ?? (await publicClient.getChainId());
        const recoveryAuth = await signAuthorization(publicClient, {
          account: victimAccount,
          contractAddress: "0x0000000000000000000000000000000000000000",
          chainId,
          nonce: currentVictimNonce + 1
        });
        txHash = await victimWallet.sendTransaction({
          to: victim,
          authorizationList: [recoveryAuth]
        });
        const clearReceipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
        if (clearReceipt.status !== "success") {
          return {
            runId,
            status: "RECOVERY_PARTIAL_FAILURE",
            message: `Clear delegation transaction reverted on-chain (txHash: ${txHash})`,
            failedTxIndex: 0,
            totalTxsExecuted: 1,
            txHash,
            postRecoveryVerified: false
          };
        }
        totalTxsExecuted = 1;
        break;
      }
      case "RECOVERY_INFEASIBLE": {
        return {
          runId,
          status: "RECOVERY_INFEASIBLE",
          message: recoveryPlan.description,
          totalTxsExecuted: 0
        };
      }
      case "NOOP":
      default: {
        txHash = "0x";
        totalTxsExecuted = 0;
        break;
      }
    }
  } else {
    // Permit2: allowance (single or multi-chunk delta) or signature bitmap
    const txs = recoveryPlan.transactions ?? [
      { to: recoveryPlan.target, data: recoveryPlan.calldata, value: 0n }
    ];
    totalTxsExecuted = txs.length;
    for (let i = 0; i < txs.length; i++) {
      const tx = txs[i];
      txHash = await victimWallet.sendTransaction({
        to: tx.to ?? recoveryPlan.target,
        data: tx.data ?? recoveryPlan.calldata,
        value: tx.value ?? 0n
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
      if (receipt.status !== "success") {
        return {
          runId,
          status: "RECOVERY_PARTIAL_FAILURE",
          message: `Permit2 recovery transaction ${i + 1}/${txs.length} reverted on-chain (txHash: ${txHash})`,
          failedTxIndex: i,
          totalTxsExecuted: i + 1,
          txHash,
          postRecoveryVerified: false
        };
      }
    }
  }

  let status = "CONFIRMED";
  let blockNumber = "0";
  let gasUsed = "0";

  if (txHash !== "0x") {
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    status = receipt.status === "success" ? "CONFIRMED" : "REVERTED";
    blockNumber = receipt.blockNumber.toString();
    gasUsed = receipt.gasUsed.toString();
  }

  // POST-RECOVERY FULL BOUNDED RE-SEARCH USING MULTI-CAPABILITY AUDITOR:
  // Evaluates the account's complete capability portfolio (CapabilitySet) on state s_R
  const auditor = new MultiCapabilityAuditor(
    publicClient,
    { request: async (args: any) => publicClient.request(args) }
  );
  // Authoritative trust boundary: Server recovery verification MUST evaluate
  // the trusted session portfolio and MUST NOT allow untrusted HTTP body overrides.
  const portfolioToAudit: CapabilitySet =
    session.capabilityPortfolio ?? [session.capability];
  const auditResult = await auditor.audit(portfolioToAudit, session.attacker);
  const postRecoveryVerified = auditResult.status === "PORTFOLIO_NO_MODELED_LOSS";

  return {
    runId,
    txHash,
    status,
    blockNumber,
    gasUsed,
    strategy: recoveryPlan.strategy,
    description: recoveryPlan.description,
    totalTxsExecuted,
    postRecoveryExplore: {
      status: auditResult.status,
      verified: postRecoveryVerified,
      evaluatedCount: auditResult.evaluatedCount,
      metrics: auditResult.metrics,
      violatingCapability:
        auditResult.status === "FOUND_RESIDUAL_LOSS" ? auditResult.violatingCapability.kind : undefined,
      residualLoss:
        auditResult.status === "FOUND_RESIDUAL_LOSS"
          ? auditResult.counterexample.loss
          : undefined,
      unmodeledCount:
        auditResult.status === "PORTFOLIO_INCOMPLETE"
          ? auditResult.unmodeledCapabilities.length
          : undefined,
      message: auditResult.message
    }
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
    prospectiveRisk,
    victim,
    tokenAddress,
    anvilProcess,
    canonicalId,
    recoveryPlan,
    initialBalance
  } = session;

  let replayReverted = false;
  let failedStep = 0;
  let revertError = "";

  const candidateTrace = counterexample?.trace ?? prospectiveRisk?.candidateTrace;

  if (!candidateTrace || candidateTrace.length === 0) {
    anvilProcess.kill();
    sessions.delete(runId);
    return {
      runId,
      mitigated: null,
      failedStep: 0,
      revertError: "",
      finalVictimBalance: `${formatUnits(initialBalance, 6)} USDC`,
      message: "No modeled loss path found within bound; no exploit trace to replay against state s_R."
    };
  }

  if (
    canonicalId === "eip7702" ||
    canonicalId === "eip7702_future_nonce" ||
    canonicalId === "eip7702_active_delegation" ||
    canonicalId === "portfolio_residual_risk"
  ) {
    if (recoveryPlan.strategy === "CLEAR_DELEGATION") {
      const delegateArtifact = JSON.parse(
        fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MaliciousDelegate.sol/MaliciousDelegate.json"), "utf8")
      );
      const sweepData = encodeFunctionData({
        abi: delegateArtifact.abi,
        functionName: "sweep",
        args: [tokenAddress, session.attacker]
      });
      try {
        const tx = await attackerWallet.sendTransaction({
          to: victim,
          data: sweepData
        });
        await publicClient.waitForTransactionReceipt({ hash: tx });
      } catch (err: any) {
        // Sweep call may revert or no-op on cleared EOA
      }

      const balAfter: bigint = await publicClient.readContract({
        address: tokenAddress,
        abi: ERC20_ABI,
        functionName: "balanceOf",
        args: [victim]
      });

      if (balAfter === initialBalance) {
        replayReverted = true;
        failedStep = 1;
        revertError = "EIP-7702: Active delegation cleared to address(0); sweep logic never executed";
      }
    } else {
      const step1 = candidateTrace[0];
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
    }
  } else {
    // Permit2 scenarios (allowance, signature, chunked nonces)
    for (let i = 0; i < candidateTrace.length; i++) {
      const step = candidateTrace[i];
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

  const assetsLost = session.initialBalance && session.initialBalance > finalBal ? session.initialBalance - finalBal : 0n;
  const mitigated = assetsLost <= 0n;

  // Clean up anvil process and session
  anvilProcess.kill();
  sessions.delete(runId);

  return {
    runId,
    mitigated,
    reverted: replayReverted,
    failedStep,
    revertError: revertError ? revertError.slice(0, 100) : null,
    finalVictimBalance: `${formatUnits(finalBal, 6)} USDC`,
    assetsLost: assetsLost.toString(),
    message: mitigated
      ? (replayReverted ? "Exploit replay reverted on-chain. Zero assets lost post-recovery." : "Zero assets lost post-recovery.")
      : `Replay exploit succeeded in draining funds (${formatUnits(assetsLost, 6)} USDC lost). Recovery was ineffective.`
  };
}

async function ensureContractsEtchedIfLocal(
  publicClient: PublicClient,
  capability: Capability,
  forkUrl?: string
) {
  if (forkUrl) return;
  const targetContract: Address | null =
    capability.kind === "EIP7702"
      ? capability.delegateAddress
      : (capability as any).permit2Address ?? null;

  if (targetContract && targetContract !== "0x0000000000000000000000000000000000000000") {
    const code = await publicClient.getBytecode({ address: targetContract });
    if (!code || code === "0x") {
      if (capability.kind === "PERMIT2_ALLOWANCE" || capability.kind === "PERMIT2_SIGNATURE") {
        try {
          const permit2Artifact = JSON.parse(
            fs.readFileSync(path.resolve(__dirname, "../../contracts/out/Permit2.sol/Permit2.json"), "utf8")
          );
          const deployedBytecode = permit2Artifact.deployedBytecode?.object ?? permit2Artifact.bytecode?.object;
          if (deployedBytecode) {
            await publicClient.request({
              method: "anvil_setCode" as any,
              params: [targetContract, deployedBytecode.startsWith("0x") ? deployedBytecode : `0x${deployedBytecode}`]
            });
          }
        } catch {}
      }
    }
  }

  const tokenContract: Address | null =
    capability.kind === "PERMIT2_ALLOWANCE"
      ? capability.details.token
      : capability.kind === "PERMIT2_SIGNATURE"
      ? capability.permitted.token
      : capability.kind === "EIP7702"
      ? capability.targetToken ?? null
      : null;

  if (tokenContract && tokenContract !== "0x0000000000000000000000000000000000000000") {
    const tokenCode = await publicClient.getBytecode({ address: tokenContract });
    if (!tokenCode || tokenCode === "0x") {
      try {
        const usdcArtifact = JSON.parse(
          fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
        );
        const deployedBytecode = usdcArtifact.deployedBytecode?.object ?? usdcArtifact.bytecode?.object;
        if (deployedBytecode) {
          await publicClient.request({
            method: "anvil_setCode" as any,
            params: [tokenContract, deployedBytecode.startsWith("0x") ? deployedBytecode : `0x${deployedBytecode}`]
          });
        }
      } catch {}
    }
  }
}

async function executeAnalyzeCapability(body: any, ctx?: { anvilProcess?: ChildProcess }): Promise<any> {
  const { type, payload, attackerAddress, forkUrl: rawForkUrl, rpcUrl } = body;
  const forkUrl = rawForkUrl || rpcUrl;
  if (forkUrl) {
    await validateForkUrl(forkUrl);
  }
  if (!type || !payload) {
    throw new Error("Missing required fields: 'type' and 'payload' must be provided");
  }

  let capability: Capability;
  const normType = String(type).toUpperCase().replace(/[-_]/g, "");
  if (normType === "EIP7702") {
    capability = decode7702(payload);
    if (body.tokenAddress || payload.targetToken) {
      capability.targetToken = getAddress(body.tokenAddress || payload.targetToken);
    }
  } else if (normType === "PERMIT2ALLOWANCE") {
    capability = decodePermit2Allowance(payload);
  } else if (normType === "PERMIT2SIGNATURE") {
    capability = decodePermit2Signature(payload);
  } else {
    throw new Error(`Unsupported capability type: ${type}`);
  }

  // 1. Spawn ephemeral Anvil instance for dynamic reachability analysis
  const is7702 = capability.kind === "EIP7702";
  const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil(is7702 ? "prague" : undefined, forkUrl);
  if (ctx) ctx.anvilProcess = anvilProcess;
  const anvilRpcUrl = `http://127.0.0.1:${anvilPort}`;
  const publicClient = createPublicClient({ transport: viemHttp(anvilRpcUrl) });

  // 2. Cryptographic Signature & Authority Validation (supports EIP-1271 contract wallets via publicClient)
  const validation = await CapabilityValidator.validate(capability, publicClient);
  if (!validation.valid) {
    anvilProcess.kill();
    return {
      status: "INVALID_CAPABILITY",
      valid: false,
      reason: validation.reason,
      counterexample: null,
      prospectiveRisk: null
    };
  }

  const attacker = attackerAddress
    ? getAddress(attackerAddress)
    : (capability.kind === "PERMIT2_ALLOWANCE" || capability.kind === "PERMIT2_SIGNATURE")
    ? getAddress(capability.spender)
    : "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

  try {
    // 3. State-Source Validation: Verify state chainId matches capability chainId (accepting chainId 0 for chain-agnostic EIP-7702)
    const stateChainId = await publicClient.getChainId();
    if (capability.chainId !== 0n && BigInt(stateChainId) !== capability.chainId) {
      throw new Error(
        `State chainId mismatch: reconstructed EVM state has chainId ${stateChainId} but capability is signed for chainId ${capability.chainId}. Provide corresponding forkUrl.`
      );
    }

    await ensureContractsEtchedIfLocal(publicClient, capability, forkUrl);

    // 4. Validate target contract availability on reconstructed state
    const targetContract: Address | null =
      capability.kind === "EIP7702"
        ? capability.delegateAddress
        : (capability as any).permit2Address ?? null;

    if (targetContract && targetContract !== "0x0000000000000000000000000000000000000000") {
      const targetCode = await publicClient.getBytecode({ address: targetContract });
      if (!targetCode || targetCode === "0x") {
        throw new Error(
          `Target contract at ${targetContract} is not deployed on reconstructed EVM state (chainId ${stateChainId}). Provide forkUrl parameter to reconstruct on-chain storage/bytecode.`
        );
      }
    }

    // Ensure targetToken is provided for EIP-7702 reachability exploration
    if (capability.kind === "EIP7702" && !capability.targetToken) {
      return {
        status: "UNMODELED",
        valid: true,
        signer: validation.signer,
        reason: "Missing target token: EIP-7702 reachability analysis requires an explicit tokenAddress to observe asset invariants",
        counterexample: null,
        prospectiveRisk: null
      };
    }

    const explorer = new ReachabilityExplorer(
      publicClient,
      { request: async (args: any) => publicClient.request(args) },
      3
    );

    const exploreRes = await explorer.explore(capability, attacker);

    if (exploreRes.status === "FOUND_LOSS") {
      return {
        status: "FOUND_LOSS",
        valid: true,
        signer: validation.signer,
        counterexample: exploreRes.counterexample,
        prospectiveRisk: null
      };
    }

    if (exploreRes.status === "UNMODELED") {
      return {
        status: "UNMODELED",
        valid: true,
        signer: validation.signer,
        reason: exploreRes.reason,
        counterexample: null,
        prospectiveRisk: null
      };
    }

    // Check for conditional risk (e.g. future nonce)
    let prospectiveRisk: ProspectiveRisk | null = null;
    let status: VerificationOutcome = "NO_MODELED_LOSS";

    if (capability.kind === "EIP7702") {
      const currNonce = await publicClient.getTransactionCount({ address: capability.owner });
      if (BigInt(currNonce) < capability.nonce) {
        status = "CONDITIONAL_RISK";
        prospectiveRisk = {
          condition: `EIP-7702 authorization signed for future account nonce ${capability.nonce} (current on-chain: ${currNonce})`,
          candidateTrace: [],
          projectedLoss: {
            token: capability.targetToken ?? "0x0000000000000000000000000000000000000000",
            symbol: "TOKEN",
            amount: "0",
            formatted: "0.00"
          }
        };
      }
    } else if (capability.kind === "PERMIT2_ALLOWANCE") {
      try {
        const [, , currentNonce] = await publicClient.readContract({
          address: capability.permit2Address,
          abi: PERMIT2_ABI,
          functionName: "allowance",
          args: [capability.owner, capability.details.token, capability.spender]
        });
        if (BigInt(currentNonce) < BigInt(capability.details.nonce)) {
          status = "CONDITIONAL_RISK";
          prospectiveRisk = {
            condition: `Permit2 allowance signed for future nonce ${capability.details.nonce} (current on-chain: ${currentNonce})`,
            candidateTrace: [],
            projectedLoss: {
              token: capability.details.token,
              symbol: "TOKEN",
              amount: capability.details.amount.toString(),
              formatted: `${capability.details.amount}`
            }
          };
        }
      } catch (err: any) {
        return {
          status: "UNMODELED",
          valid: true,
          signer: validation.signer,
          reason: `Failed to inspect on-chain Permit2 allowance state: ${err.message || err}`,
          counterexample: null,
          prospectiveRisk: null
        };
      }
    }

    return {
      status,
      valid: true,
      signer: validation.signer,
      counterexample: null,
      prospectiveRisk
    };
  } finally {
    anvilProcess.kill();
  }
}

async function handleAnalyzeCapability(body: any): Promise<any> {
  const ctx: { anvilProcess?: ChildProcess } = {};
  let timer: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      executeAnalyzeCapability(body, ctx),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          if (ctx.anvilProcess) {
            try {
              ctx.anvilProcess.kill("SIGKILL");
            } catch {}
          }
          reject(new Error(`Analysis timed out after ${WORKER_TIMEOUT_MS / 1000}s`));
        }, WORKER_TIMEOUT_MS);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function handleRecoveryPlan(body: any): Promise<any> {
  const { runId, type, payload, forkUrl } = body;
  if (forkUrl) {
    await validateForkUrl(forkUrl);
  }

  // Case 1: Existing session referenced by runId
  if (runId) {
    const session = sessions.get(runId);
    if (!session) {
      throw new Error(`Session ${runId} not found or expired`);
    }

    const { publicClient, victim, capability, recoveryPlan, canonicalId } = session;
    const currentNonce = await publicClient.getTransactionCount({ address: victim });
    const currentBytecode = (await publicClient.getBytecode({ address: victim })) ?? "0x";
    const hasDelegation =
      currentBytecode.length >= 48 && currentBytecode.toLowerCase().startsWith("0xef0100");

    // Format unsigned wallet transactions for window.ethereum.request
    const walletTransactions: any[] = [];

    if (
      canonicalId === "eip7702" ||
      canonicalId === "eip7702_future_nonce" ||
      canonicalId === "eip7702_active_delegation" ||
      canonicalId === "portfolio_residual_risk"
    ) {
      if (recoveryPlan.strategy === "CLEAR_DELEGATION") {
        walletTransactions.push({
          from: victim,
          to: victim,
          value: "0x0",
          data: "0x",
          authorizationList: [
            {
              contractAddress: "0x0000000000000000000000000000000000000000",
              chainId: Number(capability.chainId),
              nonce: currentNonce + 1
            }
          ]
        });
      } else if (
        recoveryPlan.strategy === "ADVANCE_NONCE" ||
        recoveryPlan.strategy === "FUTURE_NONCE_MULTI_ADVANCE"
      ) {
        const txs = recoveryPlan.transactions ?? [{ to: victim, value: 0n, data: "0x" }];
        for (const tx of txs) {
          walletTransactions.push({
            from: victim,
            to: tx.to ?? victim,
            value: `0x${(tx.value ?? 0n).toString(16)}`,
            data: tx.data ?? "0x"
          });
        }
      }
    } else {
      // Permit2
      const txs = recoveryPlan.transactions ?? [
        { to: recoveryPlan.target, data: recoveryPlan.calldata, value: 0n }
      ];
      for (const tx of txs) {
        walletTransactions.push({
          from: victim,
          to: tx.to ?? recoveryPlan.target,
          value: `0x${(tx.value ?? 0n).toString(16)}`,
          data: tx.data ?? recoveryPlan.calldata
        });
      }
    }

    let preconditions: any;
    if (
      canonicalId === "eip7702" ||
      canonicalId === "eip7702_future_nonce" ||
      canonicalId === "eip7702_active_delegation" ||
      canonicalId === "portfolio_residual_risk"
    ) {
      preconditions = {
        accountAddress: victim,
        expectedAccountNonce: currentNonce,
        expectedBytecode: currentBytecode,
        expectedActiveDelegation: hasDelegation,
        chainId: Number(capability.chainId)
      };
    } else if (
      canonicalId === "permit2_allowance" ||
      canonicalId === "permit2_future_delta_65535" ||
      canonicalId === "permit2_future_delta_65536"
    ) {
      const p2Cap = capability as Permit2AllowanceCapability;
      const [allowedAmount, , permitNonce] = await publicClient.readContract({
        address: p2Cap.permit2Address,
        abi: PERMIT2_ABI,
        functionName: "allowance",
        args: [victim, p2Cap.details.token, p2Cap.spender]
      });
      preconditions = {
        accountAddress: victim,
        permit2Address: p2Cap.permit2Address,
        token: p2Cap.details.token,
        spender: p2Cap.spender,
        expectedPermitNonce: Number(permitNonce),
        expectedAllowedAmount: allowedAmount.toString(),
        chainId: Number(capability.chainId)
      };
    } else if (canonicalId === "permit2_signature") {
      const p2SigCap = capability as Permit2SignatureCapability;
      const wordPos = p2SigCap.nonce >> 8n;
      const currentWord: bigint = await publicClient.readContract({
        address: p2SigCap.permit2Address,
        abi: PERMIT2_ABI,
        functionName: "nonceBitmap",
        args: [victim, wordPos]
      });
      preconditions = {
        accountAddress: victim,
        permit2Address: p2SigCap.permit2Address,
        wordPos: wordPos.toString(),
        expectedNonceBitmapWord: currentWord.toString(),
        chainId: Number(capability.chainId)
      };
    }

    return {
      runId,
      strategy: recoveryPlan.strategy,
      description: recoveryPlan.description,
      preconditions,
      walletTransactions
    };
  }

  // Case 2: Arbitrary capability provided
  if (!type || !payload) {
    throw new Error("Missing required parameters: provide either 'runId' or 'type' and 'payload'");
  }

  let capability: Capability;
  const normType = String(type).toUpperCase().replace(/[-_]/g, "");
  if (normType === "EIP7702") {
    capability = decode7702(payload);
  } else if (normType === "PERMIT2ALLOWANCE") {
    capability = decodePermit2Allowance(payload);
  } else if (normType === "PERMIT2SIGNATURE") {
    capability = decodePermit2Signature(payload);
  } else {
    throw new Error(`Unsupported capability type: ${type}`);
  }

  const validation = await CapabilityValidator.validate(capability);
  if (!validation.valid) {
    return {
      status: "INVALID_CAPABILITY",
      strategy: "NOOP",
      description: `Capability validation failed: ${validation.reason}`,
      preconditions: null,
      walletTransactions: []
    };
  }

  const is7702 = capability.kind === "EIP7702";
  const { process: anvilProcess, port: anvilPort } = await startEphemeralAnvil(
    is7702 ? "prague" : undefined,
    forkUrl
  );
  const rpcUrl = `http://127.0.0.1:${anvilPort}`;
  const publicClient = createPublicClient({ transport: viemHttp(rpcUrl) });

  try {
    const stateChainId = await publicClient.getChainId();
    if (capability.chainId !== 0n && BigInt(stateChainId) !== capability.chainId) {
      throw new Error(
        `State chainId mismatch: reconstructed EVM state has chainId ${stateChainId} but capability is signed for chainId ${capability.chainId}. Provide corresponding forkUrl.`
      );
    }

    const owner = capability.owner;
    const currentNonce = await publicClient.getTransactionCount({ address: owner });
    const currentBytecode = (await publicClient.getBytecode({ address: owner })) ?? "0x";
    const hasDelegation =
      currentBytecode.length >= 48 && currentBytecode.toLowerCase().startsWith("0xef0100");

    await ensureContractsEtchedIfLocal(publicClient, capability, forkUrl);

    let recoveryPlan: any;
    if (capability.kind === "EIP7702") {
      recoveryPlan = await EIP7702RecoveryPlanner.plan(capability, publicClient);
    } else if (capability.kind === "PERMIT2_ALLOWANCE") {
      recoveryPlan = await Permit2RecoveryPlanner.plan(capability, publicClient);
    } else {
      recoveryPlan = await Permit2SignatureRecoveryPlanner.plan(capability, publicClient);
    }

    const walletTransactions: any[] = [];
    if (capability.kind === "EIP7702") {
      if (recoveryPlan.strategy === "CLEAR_DELEGATION") {
        walletTransactions.push({
          from: owner,
          to: owner,
          value: "0x0",
          data: "0x",
          authorizationList: [
            {
              contractAddress: "0x0000000000000000000000000000000000000000",
              chainId: capability.chainId === 0n ? Number(stateChainId) : Number(capability.chainId),
              nonce: currentNonce + 1
            }
          ]
        });
      } else if (
        recoveryPlan.strategy === "ADVANCE_NONCE" ||
        recoveryPlan.strategy === "FUTURE_NONCE_MULTI_ADVANCE"
      ) {
        const txs = recoveryPlan.transactions ?? [{ to: owner, value: 0n, data: "0x" }];
        for (const tx of txs) {
          walletTransactions.push({
            from: owner,
            to: tx.to ?? owner,
            value: `0x${(tx.value ?? 0n).toString(16)}`,
            data: tx.data ?? "0x"
          });
        }
      }
    } else {
      const txs = recoveryPlan.transactions ?? [
        { to: recoveryPlan.target, data: recoveryPlan.calldata, value: 0n }
      ];
      for (const tx of txs) {
        walletTransactions.push({
          from: owner,
          to: tx.to ?? recoveryPlan.target,
          value: `0x${(tx.value ?? 0n).toString(16)}`,
          data: tx.data ?? recoveryPlan.calldata
        });
      }
    }

    let preconditions: any;
    if (capability.kind === "EIP7702") {
      preconditions = {
        accountAddress: owner,
        expectedAccountNonce: currentNonce,
        expectedBytecode: currentBytecode,
        expectedActiveDelegation: hasDelegation,
        chainId: Number(capability.chainId)
      };
    } else if (capability.kind === "PERMIT2_ALLOWANCE") {
      const p2Cap = capability as Permit2AllowanceCapability;
      const [allowedAmount, , permitNonce] = await publicClient.readContract({
        address: p2Cap.permit2Address,
        abi: PERMIT2_ABI,
        functionName: "allowance",
        args: [owner, p2Cap.details.token, p2Cap.spender]
      });
      preconditions = {
        accountAddress: owner,
        permit2Address: p2Cap.permit2Address,
        token: p2Cap.details.token,
        spender: p2Cap.spender,
        expectedPermitNonce: Number(permitNonce),
        expectedAllowedAmount: allowedAmount.toString(),
        chainId: Number(capability.chainId)
      };
    } else {
      const p2SigCap = capability as Permit2SignatureCapability;
      const wordPos = p2SigCap.nonce >> 8n;
      const currentWord: bigint = await publicClient.readContract({
        address: p2SigCap.permit2Address,
        abi: PERMIT2_ABI,
        functionName: "nonceBitmap",
        args: [owner, wordPos]
      });
      preconditions = {
        accountAddress: owner,
        permit2Address: p2SigCap.permit2Address,
        wordPos: wordPos.toString(),
        expectedNonceBitmapWord: currentWord.toString(),
        chainId: Number(capability.chainId)
      };
    }

    return {
      strategy: recoveryPlan.strategy,
      description: recoveryPlan.description,
      preconditions,
      walletTransactions
    };
  } finally {
    anvilProcess.kill();
  }
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

  if (
    req.method === "POST" &&
    (url === "/api/analyze" ||
      url === "/api/recover" ||
      url === "/api/recovery-plan" ||
      url === "/api/replay" ||
      url === "/api/analyze-capability")
  ) {
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
          const statusCode = result.status === "STATE_PRECONDITION_FAILED" ? 409 : 200;
          sendJson(res, statusCode, result);
        } else if (url === "/api/recovery-plan") {
          const result = await handleRecoveryPlan(body);
          sendJson(res, 200, result);
        } else if (url === "/api/replay") {
          const result = await handleReplay(body);
          sendJson(res, 200, result);
        } else if (url === "/api/analyze-capability") {
          const result = await handleAnalyzeCapability(body);
          sendJson(res, 200, result);
        }
      } catch (err: any) {
        const isClientErr =
          err.message &&
          (err.message.startsWith("Unsupported scenario") ||
            err.message.startsWith("Invalid scenario") ||
            err.message.startsWith("Missing required") ||
            err.message.startsWith("Unsupported capability") ||
            err.message.startsWith("SSRF rejected") ||
            err.message.startsWith("State chainId mismatch") ||
            err.message.startsWith("Target contract at") ||
            err.message.includes("Unexpected token"));
        const isRateLimit = err.message && err.message.startsWith("Worker pool saturated");
        const status = isRateLimit ? 429 : isClientErr ? 400 : 500;
        sendJson(res, status, { error: err.message ?? "Internal server error" });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`Aegis7702 Engine API Server listening on http://127.0.0.1:${PORT}`);
});
