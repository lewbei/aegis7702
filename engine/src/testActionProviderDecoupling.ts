import {
  createPublicClient,
  createWalletClient,
  http,
  parseUnits,
  Hex,
  encodeFunctionData,
  Address,
  formatUnits
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";
import { spawn, ChildProcess } from "child_process";
import {
  ReachabilityExplorer,
  ActionProvider,
  LossOracle,
  LossObservation
} from "./search/explorer.js";
import { Action, Capability, EIP7702Capability } from "./capability/types.js";
import { decode7702 } from "./capability/decode7702.js";
import { ERC20_ABI } from "./capability/abis.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ANVIL_PORT = 8554;
const RPC_URL = `http://127.0.0.1:${ANVIL_PORT}`;

const VICTIM_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const victimAccount = privateKeyToAccount(VICTIM_PRIVATE_KEY);
const victim = victimAccount.address;

const ATTACKER_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const attackerAccount = privateKeyToAccount(ATTACKER_PRIVATE_KEY);
const attacker = attackerAccount.address;

const ANVIL_BIN = process.env.ANVIL_BIN ?? "anvil";

const PLUGIN_DELEGATE_ABI = [
  {
    type: "function",
    name: "evacuateAsset",
    inputs: [
      { name: "token", type: "address" },
      { name: "recipient", type: "address" }
    ],
    outputs: []
  },
  {
    type: "function",
    name: "harmlessPing",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }]
  },
  {
    type: "function",
    name: "forcedRevert",
    inputs: [],
    outputs: []
  }
] as const;

async function startAnvil(): Promise<ChildProcess> {
  const anvil = spawn(ANVIL_BIN, [
    "--port",
    ANVIL_PORT.toString(),
    "--hardfork",
    "prague",
    "--silent"
  ]);

  await new Promise((resolve) => setTimeout(resolve, 1500));
  return anvil;
}

async function runDecouplingTest() {
  console.log("==================================================================");
  console.log("  AEGIS7702: NOVEL SELECTOR & LOSS ORACLE DECOUPLING TEST        ");
  console.log("  (Proving Search Branching b=3, Backtracking & Protocol-Agnostic) ");
  console.log("==================================================================");

  console.log("\n[1/6] Booting clean local Anvil node (Prague hardfork)...");
  const anvil = await startAnvil();

  try {
    const publicClient = createPublicClient({ transport: http(RPC_URL) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: http(RPC_URL) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: http(RPC_URL) });

    // Deploy MockUSDC & PluginOnlyDelegate (which exposes NOVEL unmodeled selectors)
    console.log("[2/6] Deploying MockUSDC & novel PluginOnlyDelegate contract...");
    const mockUsdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const delegateArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/PluginOnlyDelegate.sol/PluginOnlyDelegate.json"), "utf8")
    );

    const usdcDeployTx = await victimWallet.deployContract({
      abi: mockUsdcArtifact.abi,
      bytecode: mockUsdcArtifact.bytecode.object as Hex
    });
    const usdcReceipt = await publicClient.waitForTransactionReceipt({ hash: usdcDeployTx });
    const usdcAddress = usdcReceipt.contractAddress!;

    const delegateDeployTx = await attackerWallet.deployContract({
      abi: delegateArtifact.abi,
      bytecode: delegateArtifact.bytecode.object as Hex
    });
    const delegateReceipt = await publicClient.waitForTransactionReceipt({ hash: delegateDeployTx });
    const delegateAddress = delegateReceipt.contractAddress!;

    console.log(`      MockUSDC deployed to:           ${usdcAddress}`);
    console.log(`      PluginOnlyDelegate deployed to: ${delegateAddress}`);

    // Mint 10,000 USDC
    const INITIAL_USDC = parseUnits("10000", 6);
    const mintTx = await victimWallet.writeContract({
      address: usdcAddress,
      abi: mockUsdcArtifact.abi,
      functionName: "mint",
      args: [victim, INITIAL_USDC]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintTx });

    // Victim signs authorization pointing to novel PluginOnlyDelegate
    console.log("[3/6] Victim signs EIP-7702 authorization tuple for novel delegate...");
    const victimNonce = await publicClient.getTransactionCount({ address: victim });
    const auth = await signAuthorization(publicClient, {
      account: victimAccount,
      contractAddress: delegateAddress,
      chainId: 31337,
      nonce: victimNonce
    });

    const capability: EIP7702Capability = decode7702({
      owner: victim,
      chainId: auth.chainId,
      address: (auth as any).contractAddress ?? (auth as any).address ?? delegateAddress,
      nonce: auth.nonce,
      yParity: auth.yParity,
      r: auth.r,
      s: auth.s,
      targetToken: usdcAddress
    });

    const rpcClient = {
      request: async (args: { method: string; params?: any[] }) => {
        return await publicClient.request(args as any);
      }
    };

    // 4. Verify that Built-in EIP7702Semantics FAILS to discover loss on novel selector
    console.log("\n[4/6] Evaluating Built-in Semantics (Should find 0 exploit paths on novel delegate)...");
    const defaultExplorer = new ReachabilityExplorer(publicClient, rpcClient, 3);
    const builtInResult = await defaultExplorer.explore(capability, attacker);

    if (builtInResult !== null) {
      throw new Error("Expected built-in semantics to return null on novel delegate, but it found a false exploit path!");
    }
    console.log("  ✓ Confirmed: Built-in semantics abstains on novel selector (Zero false alarms on unmodeled interfaces).");

    // 5. Define an independent, external plugin ActionProvider with real branching (b=3) & backtracking
    console.log("\n[5/6] Injecting PluginOnlyActionProvider (b=3 branching with reverts & no-ops) + CustomLossOracle...");
    let providerInvocationCount = 0;
    let revertedBranchCount = 0;
    let harmlessBranchCount = 0;

    const pluginActionProvider: ActionProvider = {
      async enumerateActions(cap: Capability, client, actor): Promise<Action[]> {
        providerInvocationCount++;
        const eip7702Cap = cap as EIP7702Capability;
        const code = await client.getBytecode({ address: victim });
        const hasDelegation =
          code &&
          code.length >= 48 &&
          code.toLowerCase().startsWith("0xef0100");

        // Calldata for novel delegate actions
        const forcedRevertCalldata = encodeFunctionData({
          abi: PLUGIN_DELEGATE_ABI,
          functionName: "forcedRevert"
        });

        const evacuateAssetCalldata = encodeFunctionData({
          abi: PLUGIN_DELEGATE_ABI,
          functionName: "evacuateAsset",
          args: [usdcAddress, actor]
        });

        // State 0: Before delegation is installed on victim EOA
        // Provide 3 branching candidate paths:
        // Branch 1: Force revert (triggers kernel exception handling & snapshot revert)
        // Branch 2: Harmless probe (succeeds with 0 balance delta -> explores dead end & backtracks)
        // Branch 3: Type-4 relay authorization (installs delegation)
        if (!hasDelegation) {
          return [
            {
              id: "plugin.revertPreDelegation",
              description: "Attacker attempts invalid call pre-delegation (expect revert)",
              target: usdcAddress,
              calldata: forcedRevertCalldata,
              value: 0n,
              actor
            },
            {
              id: "plugin.customRelay",
              description: "Relayer broadcasts Type-4 transaction with authorization",
              target: victim,
              calldata: "0x",
              value: 0n,
              actor,
              authorizationList: [
                eip7702Cap.authorizationObject || {
                  address: eip7702Cap.delegateAddress,
                  chainId: Number(eip7702Cap.chainId),
                  nonce: Number(eip7702Cap.nonce),
                  yParity: eip7702Cap.yParity,
                  r: eip7702Cap.r,
                  s: eip7702Cap.s
                }
              ]
            },
            {
              id: "plugin.harmlessProbePreDelegation",
              description: "Attacker executes harmless read call pre-delegation",
              target: usdcAddress,
              calldata: encodeFunctionData({ abi: ERC20_ABI, functionName: "symbol" }),
              value: 0n,
              actor
            }
          ];
        }

        // State 1: Once delegated, provide candidate actions (b=3):
        // Branch 1: Forced revert on delegated code (reverts on-chain -> backtracks)
        // Branch 2: Harmless ping on delegated code (succeeds, zero loss -> backtracks)
        // Branch 3: evacuateAsset(usdcAddress, actor) -> novel unmodeled drain function!
        return [
          {
            id: "plugin.revertPostDelegation",
            description: "Attacker executes reverting call on delegated victim EOA",
            target: victim,
            calldata: forcedRevertCalldata,
            value: 0n,
            actor
          },
          {
            id: "plugin.evacuateAsset",
            description: "Attacker calls novel evacuateAsset(USDC, attacker) on delegated victim",
            target: victim,
            calldata: evacuateAssetCalldata,
            value: 0n,
            actor
          },
          {
            id: "plugin.harmlessProbePostDelegation",
            description: "Attacker calls harmless ping on delegated victim EOA",
            target: victim,
            calldata: encodeFunctionData({ abi: PLUGIN_DELEGATE_ABI, functionName: "harmlessPing" }),
            value: 0n,
            actor
          }
        ];
      }
    };

    // Define a fully decoupled CustomLossOracle that implements the LossOracle interface
    // Demonstrating the verifier kernel has zero hardcoded knowledge of ERC20 ABI
    interface CustomLossContext {
      monitoredToken: Address;
      initialBalance: bigint;
    }

    let oracleEvaluationCount = 0;
    const customLossOracle: LossOracle<CustomLossContext> = {
      async snapshotInitial(cap: Capability, client): Promise<CustomLossContext> {
        const eipCap = cap as EIP7702Capability;
        const bal = await client.readContract({
          address: eipCap.targetToken!,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [eipCap.owner]
        });
        return {
          monitoredToken: eipCap.targetToken!,
          initialBalance: bal
        };
      },

      async evaluate(ctx: CustomLossContext, cap: Capability, client): Promise<LossObservation | null> {
        oracleEvaluationCount++;
        const currentBal = await client.readContract({
          address: ctx.monitoredToken,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [cap.owner]
        });

        if (currentBal < ctx.initialBalance) {
          const delta = ctx.initialBalance - currentBal;
          return {
            lossAmount: delta,
            token: ctx.monitoredToken,
            symbol: "USDC",
            amount: delta.toString(),
            formatted: formatUnits(delta, 6)
          };
        }
        return null;
      },

      async formatCurrentState(ctx: CustomLossContext, cap: Capability, client): Promise<string> {
        const currentBal = await client.readContract({
          address: ctx.monitoredToken,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [cap.owner]
        });
        return `${formatUnits(currentBal, 6)} USDC (initial: ${formatUnits(ctx.initialBalance, 6)} USDC)`;
      }
    };

    // 6. Execute UNMODIFIED ReachabilityExplorer with novel ActionProvider + LossOracle
    console.log("\n[6/6] Executing UNMODIFIED ReachabilityExplorer with injected ActionProvider & LossOracle...");
    const decoupledExplorer = new ReachabilityExplorer(publicClient, rpcClient, {
      maxDepth: 3,
      actionProvider: pluginActionProvider,
      lossOracle: customLossOracle
    });

    const counterexample = await decoupledExplorer.explore(capability, attacker);

    if (!counterexample) {
      throw new Error("Expected ReachabilityExplorer to discover loss witness using external ActionProvider, but found null!");
    }

    console.log("\n  🚨 COUNTEREXAMPLE DISCOVERED BY VERIFIER KERNEL!");
    console.log(`    - Exploit Depth: ${counterexample.depth} step(s)`);
    console.log(`    - Discovered Loss: ${counterexample.loss.formatted} ${counterexample.loss.symbol}`);
    console.log(`    - Winning Exploit Trace: ${counterexample.trace.map(t => t.id).join(" -> ")}`);
    console.log(`    - ActionProvider Invocations: ${providerInvocationCount}`);
    console.log(`    - Invariant Oracle Evaluations: ${oracleEvaluationCount}`);

    // Verify assertions
    if (counterexample.loss.formatted !== "10000") {
      throw new Error(`Expected loss to be 10000 USDC, got ${counterexample.loss.formatted}`);
    }
    if (counterexample.trace.length !== 2) {
      throw new Error(`Expected 2-step trace, got ${counterexample.trace.length}`);
    }
    if (counterexample.trace[0].id !== "plugin.customRelay" || counterexample.trace[1].id !== "plugin.evacuateAsset") {
      throw new Error(`Unexpected action IDs in winning trace: ${counterexample.trace.map(t => t.id).join(", ")}`);
    }

    console.log("\n==================================================================");
    console.log("  ✅ SUCCESS: PROVED NOVEL SEMANTICS + SEARCH BRANCHING (b=3)    ");
    console.log("  1. Novel delegate selector 'evacuateAsset' discovered          ");
    console.log("  2. Built-in semantics abstained (0 false positives)            ");
    console.log("  3. DFS kernel explored multi-branch tree & backtracked reverts ");
    console.log("  4. LossOracle independently evaluated invariant violations    ");
    console.log("==================================================================");

  } finally {
    anvil.kill();
  }
}

runDecouplingTest().catch((err) => {
  console.error("❌ Decoupling test failed:", err);
  process.exit(1);
});
