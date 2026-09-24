import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TEST_PORT = 3099;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runIntegrationTests() {
  console.log("================================================================================");
  console.log("🚀 STARTING AEGIS7702 LIVE ENGINE HTTP API SMOKE & INTEGRATION TEST");
  console.log("================================================================================");

  // 1. Spawn server on TEST_PORT
  const serverProcess = spawn("npx", ["tsx", path.resolve(__dirname, "server.ts")], {
    env: { ...process.env, ENGINE_PORT: TEST_PORT.toString() },
    stdio: "inherit"
  });

  // Give server time to bind
  await sleep(2500);

  try {
    // 2. Healthcheck
    console.log(`\n[1/4] Checking GET ${BASE_URL}/api/health...`);
    const healthRes = await fetch(`${BASE_URL}/api/health`);
    if (!healthRes.ok) {
      throw new Error(`Health check failed with status ${healthRes.status}`);
    }
    const healthData = await healthRes.json();
    console.log("  ✓ Healthcheck OK:", healthData);

    const testScenarios = [
      { id: "permit2_allowance", name: "Permit2 AllowanceTransfer" },
      { id: "permit2_signature", name: "Permit2 SignatureTransfer" },
      { id: "eip7702_prague", name: "EIP-7702 Prague Type-4" }
    ];

    for (let idx = 0; idx < testScenarios.length; idx++) {
      const sc = testScenarios[idx];
      console.log(`\n[${idx + 2}/4] Testing Live Pipeline for: ${sc.name} (${sc.id})`);

      // A. /api/analyze
      console.log(`  -> Sending POST /api/analyze for scenario: ${sc.id}...`);
      const analyzeRes = await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: sc.id })
      });

      if (!analyzeRes.ok) {
        const err = await analyzeRes.text();
        throw new Error(`Analyze failed: ${err}`);
      }

      const analyzeData = await analyzeRes.json();
      console.log(`  ✓ Analyze Complete: runId=${analyzeData.runId}`);
      console.log(`  ✓ Reachability Result: Depth=${analyzeData.counterexample.depth}, Loss=${analyzeData.counterexample.loss.formatted} ${analyzeData.counterexample.loss.symbol}`);
      console.log(`  ✓ Planned Recovery Strategy: ${analyzeData.recoveryPlan.strategy}`);

      // B. /api/recover
      console.log(`  -> Sending POST /api/recover for runId: ${analyzeData.runId}...`);
      const recoverRes = await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: analyzeData.runId })
      });

      if (!recoverRes.ok) {
        const err = await recoverRes.text();
        throw new Error(`Recover failed: ${err}`);
      }

      const recoverData = await recoverRes.json();
      console.log(`  ✓ Recovery Transaction Confirmed: txHash=${recoverData.txHash}, gasUsed=${recoverData.gasUsed}`);

      // C. /api/replay
      console.log(`  -> Sending POST /api/replay to verify mitigation against live Anvil fork...`);
      const replayRes = await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: analyzeData.runId })
      });

      if (!replayRes.ok) {
        const err = await replayRes.text();
        throw new Error(`Replay failed: ${err}`);
      }

      const replayData = await replayRes.json();
      console.log(`  ✓ Attacker Exploit Replay Result: mitigated=${replayData.mitigated}`);
      console.log(`  ✓ Final Victim Balance Preserved: ${replayData.finalVictimBalance}`);

      if (!replayData.mitigated) {
        throw new Error(`Mitigation failed for scenario ${sc.id}`);
      }
    }

    console.log("\n================================================================================");
    console.log("🎉 ALL 3 LIVE ENGINE API SCENARIOS 100% TESTED & VERIFIED ON-CHAIN");
    console.log("================================================================================\n");
  } finally {
    serverProcess.kill("SIGTERM");
  }
}

runIntegrationTests().catch((err) => {
  console.error("❌ Integration test failed:", err);
  process.exit(1);
});
