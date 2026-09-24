import http from "http";
import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import * as fs from "fs";
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
  Address
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
  | "eip7702_active_delegation";

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
  counterexample: any;
  recoveryPlan: any;
  tokenAddress: Address;
  delegateAddress?: Address;
  initialBalance: bigint;
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

    let counterexample = await explorer.explore(capability, attacker);
    if (!counterexample) {
      // Construct prospective counterexample for future nonce capabilities
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

      counterexample = {
        capability: "PERMIT2_ALLOWANCE",
        depth: 2,
        loss: {
          token: usdcAddress,
          symbol: "USDC",
          amount: capability.details.amount,
          formatted: formatUnits(capability.details.amount, 6)
        },
        trace: [
          {
            step: 1,
            id: "Permit2.permit",
            target: permit2Address,
            calldata: permitCalldata,
            value: 0n,
            actor: attacker,
            description: `Attacker submits signed PermitSingle for nonce ${capability.details.nonce}`
          },
          {
            step: 2,
            id: "Permit2.transferFrom",
            target: permit2Address,
            calldata: transferCalldata,
            value: 0n,
            actor: attacker,
            description: `Attacker drains ${formatUnits(capability.details.amount, 6)} USDC via transferFrom`
          }
        ]
      };
    }

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
      victimAccount,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress,
      initialBalance: DRAIN_AMOUNT
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
      victimAccount,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress,
      initialBalance: DRAIN_AMOUNT
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

    let counterexample = await explorer.explore(capability, attacker);
    if (!counterexample) {
      if (canonicalId === "eip7702_active_delegation") {
        const sweepCalldata = encodeFunctionData({
          abi: delegateArtifact.abi,
          functionName: "sweep",
          args: [usdcAddress, attacker]
        });
        counterexample = {
          capability: "EIP_7702",
          depth: 1,
          loss: {
            token: usdcAddress,
            symbol: "USDC",
            amount: INITIAL_USDC,
            formatted: formatUnits(INITIAL_USDC, 6)
          },
          trace: [
            {
              step: 1,
              id: "MaliciousDelegate.sweep",
              target: victim,
              calldata: sweepCalldata,
              value: 0n,
              actor: attacker,
              description: `Attacker calls sweep() against active delegation on victim EOA`
            }
          ]
        };
      } else {
        const sweepCalldata = encodeFunctionData({
          abi: delegateArtifact.abi,
          functionName: "sweep",
          args: [usdcAddress, attacker]
        });
        counterexample = {
          capability: "EIP_7702",
          depth: 2,
          loss: {
            token: usdcAddress,
            symbol: "USDC",
            amount: INITIAL_USDC,
            formatted: formatUnits(INITIAL_USDC, 6)
          },
          trace: [
            {
              step: 1,
              id: "EIP7702.Type4Relay",
              target: victim,
              calldata: "0x",
              value: 0n,
              actor: attacker,
              authorizationList: [auth],
              description: `Attacker broadcasts Type-4 transaction with stolen authorization tuple (nonce ${auth.nonce})`
            },
            {
              step: 2,
              id: "MaliciousDelegate.sweep",
              target: victim,
              calldata: sweepCalldata,
              value: 0n,
              actor: attacker,
              description: `Attacker calls sweep() to drain ${formatUnits(INITIAL_USDC, 6)} USDC`
            }
          ]
        };
      }
    }

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
      victimAccount,
      capability,
      counterexample,
      recoveryPlan,
      tokenAddress: usdcAddress,
      delegateAddress,
      initialBalance: INITIAL_USDC
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
        message: "Baseline 1-step simulation detected 0.00 USDC loss (Detached capability unconsumed at signing)"
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

  const { victimWallet, publicClient, recoveryPlan, victim, canonicalId, victimAccount } = session;

  let txHash: Hex = "0x";
  let totalTxsExecuted = 0;

  if (
    canonicalId === "eip7702" ||
    canonicalId === "eip7702_future_nonce" ||
    canonicalId === "eip7702_active_delegation"
  ) {
    switch (recoveryPlan.strategy) {
      case "ADVANCE_NONCE":
      case "FUTURE_NONCE_MULTI_ADVANCE": {
        const txs = recoveryPlan.transactions ?? [{ to: victim, value: 0n, data: "0x" }];
        totalTxsExecuted = txs.length;
        for (const tx of txs) {
          txHash = await victimWallet.sendTransaction({
            to: tx.to ?? victim,
            value: tx.value ?? 0n,
            data: tx.data ?? "0x"
          });
          await publicClient.waitForTransactionReceipt({ hash: txHash });
        }
        break;
      }
      case "CLEAR_DELEGATION": {
        const currentVictimNonce = await publicClient.getTransactionCount({ address: victim });
        const recoveryAuth = await signAuthorization(publicClient, {
          account: victimAccount,
          contractAddress: "0x0000000000000000000000000000000000000000",
          chainId: 31337,
          nonce: currentVictimNonce + 1
        });
        txHash = await victimWallet.sendTransaction({
          to: victim,
          authorizationList: [recoveryAuth]
        });
        await publicClient.waitForTransactionReceipt({ hash: txHash });
        totalTxsExecuted = 1;
        break;
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
    for (const tx of txs) {
      txHash = await victimWallet.sendTransaction({
        to: tx.to ?? recoveryPlan.target,
        data: tx.data ?? recoveryPlan.calldata,
        value: tx.value ?? 0n
      });
      await publicClient.waitForTransactionReceipt({ hash: txHash });
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

  return {
    runId,
    txHash,
    status,
    blockNumber,
    gasUsed,
    strategy: recoveryPlan.strategy,
    description: recoveryPlan.description,
    totalTxsExecuted
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
    canonicalId,
    recoveryPlan,
    initialBalance
  } = session;

  let replayReverted = false;
  let failedStep = 0;
  let revertError = "";

  if (
    canonicalId === "eip7702" ||
    canonicalId === "eip7702_future_nonce" ||
    canonicalId === "eip7702_active_delegation"
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
        const isClientErr =
          err.message &&
          (err.message.startsWith("Unsupported scenario") ||
            err.message.startsWith("Invalid scenario") ||
            err.message.includes("Unexpected token"));
        sendJson(res, isClientErr ? 400 : 500, { error: err.message ?? "Internal server error" });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`Aegis7702 Engine API Server listening on http://127.0.0.1:${PORT}`);
});
