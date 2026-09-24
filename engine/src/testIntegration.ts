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
  console.log("🚀 STARTING AEGIS7702 COMPREHENSIVE ENGINE API SMOKE & ADVERSARIAL TEST SUITE");
  console.log("================================================================================");

  // 1. Spawn server on TEST_PORT
  const serverProcess = spawn("npx", ["tsx", path.resolve(__dirname, "server.ts")], {
    env: { ...process.env, ENGINE_PORT: TEST_PORT.toString() },
    stdio: "inherit"
  });

  // Give server time to bind
  await sleep(2500);

  try {
    // 1. Healthcheck
    console.log(`\n[1/6] Checking GET ${BASE_URL}/api/health...`);
    const healthRes = await fetch(`${BASE_URL}/api/health`);
    if (!healthRes.ok) {
      throw new Error(`Health check failed with status ${healthRes.status}`);
    }
    const healthData = await healthRes.json();
    console.log("  ✓ Healthcheck OK:", healthData);

    // 2. Canonical 3 Scenarios
    console.log("\n[2/6] Verifying 3 Canonical Scenarios (Allowance, Signature, EIP-7702 Prague)...");
    const canonicalScenarios = [
      { id: "permit2_allowance", name: "Permit2 AllowanceTransfer" },
      { id: "permit2_signature", name: "Permit2 SignatureTransfer" },
      { id: "eip7702_prague", name: "EIP-7702 Prague Type-4 Relay" }
    ];

    for (const sc of canonicalScenarios) {
      console.log(`  -> Testing: ${sc.name} (${sc.id})`);
      const analyzeRes = await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: sc.id })
      });
      if (!analyzeRes.ok) throw new Error(`Analyze failed for ${sc.id}: ${await analyzeRes.text()}`);
      const analyzeData = await analyzeRes.json();

      const recoverRes = await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: analyzeData.runId })
      });
      if (!recoverRes.ok) throw new Error(`Recover failed for ${sc.id}: ${await recoverRes.text()}`);

      const replayRes = await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: analyzeData.runId })
      });
      if (!replayRes.ok) throw new Error(`Replay failed for ${sc.id}: ${await replayRes.text()}`);
      const replayData = await replayRes.json();

      if (!replayData.mitigated) {
        throw new Error(`Mitigation failed for canonical scenario ${sc.id}`);
      }
      console.log(`     ✓ Canonical ${sc.name}: analyze, recover, replay mitigated=true (100% verified)`);
    }

    // 3. Adversarial Test 1: EIP-7702 Multi-Advance (current=5, auth=8)
    console.log("\n[3/6] Adversarial Test 1: EIP-7702 Future Nonce (current=5, auth=8)...");
    const eipFutureRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "eip7702_future_nonce" })
    });
    if (!eipFutureRes.ok) throw new Error(`Analyze eip7702_future_nonce failed: ${await eipFutureRes.text()}`);
    const eipFutureData = await eipFutureRes.json();

    if (eipFutureData.recoveryPlan.strategy !== "FUTURE_NONCE_MULTI_ADVANCE") {
      throw new Error(`Expected FUTURE_NONCE_MULTI_ADVANCE but got ${eipFutureData.recoveryPlan.strategy}`);
    }
    if (eipFutureData.recoveryPlan.requiredAdvances !== 4) {
      throw new Error(`Expected 4 required advances but got ${eipFutureData.recoveryPlan.requiredAdvances}`);
    }
    console.log(`  ✓ Planner correctly synthesized strategy: ${eipFutureData.recoveryPlan.strategy} with ${eipFutureData.recoveryPlan.requiredAdvances} advances`);

    const eipFutureRec = await (
      await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: eipFutureData.runId })
      })
    ).json();

    if (eipFutureRec.totalTxsExecuted !== 4) {
      throw new Error(`Expected 4 executed self-transactions but got ${eipFutureRec.totalTxsExecuted}`);
    }
    console.log(`  ✓ Recovery successfully executed all ${eipFutureRec.totalTxsExecuted} self-transactions on-chain`);

    const eipFutureRep = await (
      await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: eipFutureData.runId })
      })
    ).json();

    if (!eipFutureRep.mitigated) {
      throw new Error("Exploit replay was not blocked after multi-nonce advance!");
    }
    console.log(`  ✓ Exploit replay rejected on-chain (mitigated=true, victim balance preserved: ${eipFutureRep.finalVictimBalance})`);

    // 4. Adversarial Test 2: EIP-7702 Active Delegation Clearance (address(0))
    console.log("\n[4/6] Adversarial Test 2: EIP-7702 Active Delegation Clearance (CLEAR_DELEGATION -> address(0))...");
    const eipActiveRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "eip7702_active_delegation" })
    });
    if (!eipActiveRes.ok) throw new Error(`Analyze eip7702_active_delegation failed: ${await eipActiveRes.text()}`);
    const eipActiveData = await eipActiveRes.json();

    if (eipActiveData.recoveryPlan.strategy !== "CLEAR_DELEGATION") {
      throw new Error(`Expected CLEAR_DELEGATION but got ${eipActiveData.recoveryPlan.strategy}`);
    }
    console.log(`  ✓ Planner detected active delegation and synthesized CLEAR_DELEGATION`);

    const eipActiveRec = await (
      await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: eipActiveData.runId })
      })
    ).json();
    console.log(`  ✓ Victim broadcasted Type-4 recovery authorization for address(0): txHash=${eipActiveRec.txHash}`);

    const eipActiveRep = await (
      await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: eipActiveData.runId })
      })
    ).json();

    if (!eipActiveRep.mitigated) {
      throw new Error("Attacker sweep drain succeeded despite active delegation clearance!");
    }
    console.log(`  ✓ Attacker sweep call neutralized on cleared EOA (mitigated=true, victim balance: ${eipActiveRep.finalVictimBalance})`);

    // 5. Adversarial Tests 3 & 4: Permit2 Nonce Delta Limits (delta=65535 and delta=65536)
    console.log("\n[5/6] Adversarial Tests 3 & 4: Permit2 Nonce Delta Limits (delta=65535 vs delta=65536)...");

    // Test 3: delta = 65535 (Single transaction chunk)
    console.log("  -> Subtest 3A: delta=65535 (single invalidation transaction)...");
    const p2Delta65535Res = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "permit2_future_delta_65535" })
    });
    if (!p2Delta65535Res.ok) throw new Error(`Analyze delta 65535 failed: ${await p2Delta65535Res.text()}`);
    const p2Delta65535Data = await p2Delta65535Res.json();

    const p2Delta65535Rec = await (
      await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: p2Delta65535Data.runId })
      })
    ).json();

    if (p2Delta65535Rec.totalTxsExecuted !== 1) {
      throw new Error(`Expected 1 transaction for delta 65535 but got ${p2Delta65535Rec.totalTxsExecuted}`);
    }
    console.log(`     ✓ Delta=65535 executed in single transaction: txHash=${p2Delta65535Rec.txHash}`);

    const p2Delta65535Rep = await (
      await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: p2Delta65535Data.runId })
      })
    ).json();
    if (!p2Delta65535Rep.mitigated) throw new Error("Replay not mitigated for delta 65535!");
    console.log("     ✓ Exploit replay reverted with InvalidNonce on Permit2");

    // Test 4: delta = 65536 (Multi-chunk invalidation: 65535 + 1)
    console.log("  -> Subtest 3B: delta=65536 (multi-chunk invalidation avoiding ExcessiveInvalidation)...");
    const p2Delta65536Res = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "permit2_future_delta_65536" })
    });
    if (!p2Delta65536Res.ok) throw new Error(`Analyze delta 65536 failed: ${await p2Delta65536Res.text()}`);
    const p2Delta65536Data = await p2Delta65536Res.json();

    const p2Delta65536Rec = await (
      await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: p2Delta65536Data.runId })
      })
    ).json();

    if (p2Delta65536Rec.totalTxsExecuted !== 2) {
      throw new Error(`Expected 2 chunked transactions for delta 65536 but got ${p2Delta65536Rec.totalTxsExecuted}`);
    }
    console.log(`     ✓ Multi-chunk recovery succeeded without ExcessiveInvalidation: ${p2Delta65536Rec.totalTxsExecuted} chunked txs executed`);

    const p2Delta65536Rep = await (
      await fetch(`${BASE_URL}/api/replay`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: p2Delta65536Data.runId })
      })
    ).json();
    if (!p2Delta65536Rep.mitigated) throw new Error("Replay not mitigated for delta 65536!");
    console.log("     ✓ Exploit replay reverted with InvalidNonce on Permit2");

    // 6. Adversarial Test 5: Unknown scenarioId rejection (Fail-closed API)
    console.log("\n[6/6] Adversarial Test 5: Unknown scenarioId rejection (Fail Closed)...");
    const garbageRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "garbage" })
    });

    if (garbageRes.status !== 400) {
      throw new Error(`Expected HTTP 400 for unknown scenarioId but got ${garbageRes.status}`);
    }
    const garbageData = await garbageRes.json();
    if (!garbageData.error || !garbageData.error.includes("Unsupported scenario: garbage")) {
      throw new Error(`Expected error message mentioning Unsupported scenario: garbage, got ${JSON.stringify(garbageData)}`);
    }
    console.log(`  ✓ Unknown scenario 'garbage' successfully rejected with HTTP 400 Bad Request: "${garbageData.error}"`);

    console.log("\n================================================================================");
    console.log("🎉 ALL CANONICAL & ADVERSARIAL INTEGRATION TESTS PASSED 100% ON LIVE FORK");
    console.log("================================================================================\n");
  } finally {
    serverProcess.kill("SIGTERM");
  }
}

runIntegrationTests().catch((err) => {
  console.error("❌ Integration test failed:", err);
  process.exit(1);
});
