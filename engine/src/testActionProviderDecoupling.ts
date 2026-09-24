import {
  createPublicClient,
  createWalletClient,
  http,
  parseUnits,
  Hex,
  encodeFunctionData
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";
import { spawn, ChildProcess } from "child_process";
import { ReachabilityExplorer, ActionProvider } from "./search/explorer.js";
import { Action, Capability, EIP7702Capability } from "./capability/types.js";
import { MALICIOUS_DELEGATE_ABI } from "./capability/abis.js";
import { decode7702 } from "./capability/decode7702.js";
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
  console.log("  AEGIS7702: ACTION PROVIDER / VERIFIER KERNEL DECOUPLING TEST   ");
  console.log("==================================================================");

  console.log("\n[1/5] Booting clean local Anvil node (Prague hardfork)...");
  const anvil = await startAnvil();

  try {
    const publicClient = createPublicClient({ transport: http(RPC_URL) });
    const victimWallet = createWalletClient({ account: victimAccount, transport: http(RPC_URL) });
    const attackerWallet = createWalletClient({ account: attackerAccount, transport: http(RPC_URL) });

    // Deploy MockUSDC & MaliciousDelegate
    console.log("[2/5] Deploying contracts and setting up victim balance...");
    const mockUsdcArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MockUSDC.sol/MockUSDC.json"), "utf8")
    );
    const delegateArtifact = JSON.parse(
      fs.readFileSync(path.resolve(__dirname, "../../contracts/out/MaliciousDelegate.sol/MaliciousDelegate.json"), "utf8")
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

    // Mint 10,000 USDC
    const INITIAL_USDC = parseUnits("10000", 6);
    const mintTx = await victimWallet.writeContract({
      address: usdcAddress,
      abi: mockUsdcArtifact.abi,
      functionName: "mint",
      args: [victim, INITIAL_USDC]
    });
    await publicClient.waitForTransactionReceipt({ hash: mintTx });

    // Victim signs authorization
    console.log("[3/5] Victim signs EIP-7702 authorization tuple...");
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

    // 4. Define an independent, external plugin action provider (ActionSource B)
    console.log("[4/5] Defining decoupled external ActionProvider (ActionSource B)...");
    let providerInvocationCount = 0;
    const pluginActionProvider: ActionProvider = {
      async enumerateActions(cap: Capability, client, actor): Promise<Action[]> {
        providerInvocationCount++;
        const eip7702Cap = cap as EIP7702Capability;
        const code = await client.getBytecode({ address: victim });
        const hasDelegation =
          code &&
          code.length >= 48 &&
          code.toLowerCase().startsWith("0xef0100");

        // If victim does not have delegate code yet, synthesize relay action
        if (!hasDelegation) {
          return [
            {
              id: "plugin.customRelay",
              description: "Custom plugin synthesized Type-4 authorization relay",
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
            }
          ];
        }

        // Once delegated, synthesize custom drain action
        const drainCalldata = encodeFunctionData({
          abi: MALICIOUS_DELEGATE_ABI,
          functionName: "sweep",
          args: [usdcAddress, actor]
        });

        return [
          {
            id: "plugin.customDrain",
            description: "Custom plugin synthesized sweep invocation",
            target: victim,
            calldata: drainCalldata,
            value: 0n,
            actor
          }
        ];
      }
    };

    // 5. Run the UNCHANGED ReachabilityExplorer using the decoupled ActionProvider
    console.log("[5/5] Executing UNCHANGED ReachabilityExplorer with Plugin ActionProvider...");
    const explorer = new ReachabilityExplorer(
      publicClient,
      {
        request: async (args: { method: string; params?: any[] }) => {
          return await publicClient.request(args as any);
        }
      },
      3,
      pluginActionProvider
    );
    const counterexample = await explorer.explore(capability, attacker);

    if (!counterexample) {
      throw new Error("Expected ReachabilityExplorer to discover loss witness using external ActionProvider, but found null!");
    }

    console.log("\n  ✓ Counterexample successfully discovered by un-modified verifier kernel!");
    console.log(`    - Exploit Depth: ${counterexample.depth} step(s)`);
    console.log(`    - Discovered Loss: ${counterexample.loss.formatted} ${counterexample.loss.symbol}`);
    console.log(`    - Discovered Trace: ${counterexample.trace.map(t => t.id).join(" -> ")}`);
    console.log(`    - ActionProvider Invocations: ${providerInvocationCount}`);

    if (counterexample.loss.formatted !== "10000") {
      throw new Error(`Expected loss to be 10000 USDC, got ${counterexample.loss.formatted}`);
    }
    if (counterexample.trace[0].id !== "plugin.customRelay" || counterexample.trace[1].id !== "plugin.customDrain") {
      throw new Error(`Unexpected action IDs in trace: ${counterexample.trace.map(t => t.id).join(", ")}`);
    }

    console.log("\n==================================================================");
    console.log("  ✅ SUCCESS: PROVED semantic generation ⟂ verification kernel   ");
    console.log("==================================================================");

  } finally {
    anvil.kill();
  }
}

runDecouplingTest().catch((err) => {
  console.error("❌ Decoupling test failed:", err);
  process.exit(1);
});
