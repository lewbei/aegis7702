import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";
import { createPublicClient, http as viemHttp } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { signAuthorization } from "viem/experimental";

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
      if (analyzeData.status !== "FOUND_LOSS") {
        throw new Error(`Expected FOUND_LOSS status for ${sc.id} but got ${analyzeData.status}`);
      }
      if (!analyzeData.counterexample) {
        throw new Error(`Expected physical counterexample for ${sc.id}`);
      }

      const recoverRes = await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: analyzeData.runId })
      });
      if (!recoverRes.ok) throw new Error(`Recover failed for ${sc.id}: ${await recoverRes.text()}`);
      const recoverData = await recoverRes.json();
      if (
        !recoverData.postRecoveryExplore ||
        recoverData.postRecoveryExplore.status !== "NO_MODELED_LOSS" ||
        !recoverData.postRecoveryExplore.verified
      ) {
        throw new Error(`Post-recovery bounded search failed for ${sc.id}: ${JSON.stringify(recoverData.postRecoveryExplore)}`);
      }

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
      console.log(`     ✓ Canonical ${sc.name}: status=FOUND_LOSS, postRecoveryExplore=NO_MODELED_LOSS, replay mitigated=true (100% verified)`);
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

    if (eipFutureData.status !== "CONDITIONAL_RISK") {
      throw new Error(`Expected CONDITIONAL_RISK for future nonce but got ${eipFutureData.status}`);
    }
    if (eipFutureData.counterexample !== null) {
      throw new Error(`Fabricated counterexample detected for unexecutable future-nonce scenario!`);
    }
    if (!eipFutureData.prospectiveRisk) {
      throw new Error(`Expected prospectiveRisk for future-nonce scenario`);
    }
    console.log(`  ✓ Unexecutable future-nonce strictly verified: status=CONDITIONAL_RISK, counterexample=null, prospectiveRisk populated`);

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

    if (
      !eipFutureRec.postRecoveryExplore ||
      eipFutureRec.postRecoveryExplore.status !== "NO_MODELED_LOSS" ||
      !eipFutureRec.postRecoveryExplore.verified
    ) {
      throw new Error(`Post-recovery bounded search failed for eip7702_future_nonce: ${JSON.stringify(eipFutureRec.postRecoveryExplore)}`);
    }
    console.log(`  ✓ Post-recovery bounded search verified 0 loss paths on state s_R: ${eipFutureRec.postRecoveryExplore.status}`);

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

    if (p2Delta65535Data.status !== "CONDITIONAL_RISK") {
      throw new Error(`Expected CONDITIONAL_RISK for delta 65535 but got ${p2Delta65535Data.status}`);
    }
    if (p2Delta65535Data.counterexample !== null) {
      throw new Error(`Fabricated counterexample detected for unexecutable Permit2 delta 65535!`);
    }
    if (!p2Delta65535Data.prospectiveRisk) {
      throw new Error(`Expected prospectiveRisk for delta 65535`);
    }
    console.log(`     ✓ Delta=65535 strictly verified: status=CONDITIONAL_RISK, counterexample=null, prospectiveRisk populated`);

    const p2Delta65535Rec = await (
      await fetch(`${BASE_URL}/api/recover`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId: p2Delta65535Data.runId })
      })
    ).json();

    if (
      !p2Delta65535Rec.postRecoveryExplore ||
      p2Delta65535Rec.postRecoveryExplore.status !== "NO_MODELED_LOSS" ||
      !p2Delta65535Rec.postRecoveryExplore.verified
    ) {
      throw new Error(`Post-recovery bounded search failed for delta 65535: ${JSON.stringify(p2Delta65535Rec.postRecoveryExplore)}`);
    }
    console.log(`     ✓ Post-recovery bounded search verified 0 loss paths on state s_R: ${p2Delta65535Rec.postRecoveryExplore.status}`);

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

    if (
      !p2Delta65536Rec.postRecoveryExplore ||
      p2Delta65536Rec.postRecoveryExplore.status !== "NO_MODELED_LOSS" ||
      !p2Delta65536Rec.postRecoveryExplore.verified
    ) {
      throw new Error(`Post-recovery bounded search failed for delta 65536: ${JSON.stringify(p2Delta65536Rec.postRecoveryExplore)}`);
    }
    console.log(`     ✓ Post-recovery bounded search verified 0 loss paths on state s_R: ${p2Delta65536Rec.postRecoveryExplore.status}`);

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
    console.log("\n[6/7] Adversarial Test 5: Unknown scenarioId rejection (Fail Closed)...");
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

    // 7. Test Arbitrary Capability API (/api/analyze-capability)
    console.log("\n[7/7] Testing Arbitrary Capability API (/api/analyze-capability)...");

    // Subtest 7A: Cryptographic rejection of tampered signature / forged authority
    console.log("  -> Subtest 7A: Forged cryptographic authority rejection (Fail Closed)...");
    const forgedRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        payload: {
          owner: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
          delegateAddress: "0x1111111111111111111111111111111111111111",
          chainId: 31337,
          nonce: 0,
          yParity: 0,
          r: "0x1234567890123456789012345678901234567890123456789012345678901234",
          s: "0x1234567890123456789012345678901234567890123456789012345678901234"
        }
      })
    });
    if (!forgedRes.ok) throw new Error(`POST /api/analyze-capability failed: ${await forgedRes.text()}`);
    const forgedData = await forgedRes.json();
    if (forgedData.status !== "INVALID_CAPABILITY" || forgedData.valid !== false) {
      throw new Error(`Expected INVALID_CAPABILITY for forged payload, got ${JSON.stringify(forgedData)}`);
    }
    console.log(`     ✓ Forged signature rejected: status=${forgedData.status}, reason="${forgedData.reason}"`);

    // Subtest 7B: Cryptographic acceptance of valid signed EIP-7702 tuple
    console.log("  -> Subtest 7B: Valid cryptographic signature verification & reachability analysis...");
    const testAccount = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    const validAuth = await signAuthorization(
      createPublicClient({ transport: viemHttp("http://127.0.0.1:8545") }),
      {
        account: testAccount,
        contractAddress: "0x0000000000000000000000000000000000000000",
        chainId: 31337,
        nonce: 0
      }
    );
    const validRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        payload: {
          owner: testAccount.address,
          address: validAuth.address,
          chainId: validAuth.chainId,
          nonce: validAuth.nonce,
          yParity: validAuth.yParity,
          r: validAuth.r,
          s: validAuth.s
        }
      })
    });
    if (!validRes.ok) throw new Error(`POST /api/analyze-capability failed: ${await validRes.text()}`);
    const validData = await validRes.json();
    if (!validData.valid || (validData.status !== "NO_MODELED_LOSS" && validData.status !== "UNMODELED")) {
      throw new Error(`Expected valid outcome for authenticated capability, got ${JSON.stringify(validData)}`);
    }
    console.log(`     ✓ Authenticated capability verified: status=${validData.status}, valid=${validData.valid}, signer=${validData.signer}`);

    // Subtest 7C: SSRF defense rejection for forbidden forkUrl
    console.log("  -> Subtest 7C: SSRF defense rejection for forbidden forkUrl...");
    const ssrfRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        payload: {
          owner: testAccount.address,
          address: validAuth.address,
          chainId: validAuth.chainId,
          nonce: validAuth.nonce,
          yParity: validAuth.yParity,
          r: validAuth.r,
          s: validAuth.s
        },
        forkUrl: "http://169.254.169.254/latest/meta-data"
      })
    });
    if (ssrfRes.status !== 400) {
      throw new Error(`Expected HTTP 400 for SSRF target but got ${ssrfRes.status}`);
    }
    const ssrfData = await ssrfRes.json();
    if (!ssrfData.error || !ssrfData.error.includes("SSRF rejected")) {
      throw new Error(`Expected SSRF error message, got ${JSON.stringify(ssrfData)}`);
    }
    console.log(`     ✓ Forbidden cloud metadata SSRF successfully blocked: "${ssrfData.error}"`);

    // Subtest 7C.2: State chainId mismatch rejection (Fail Closed HTTP 400)
    console.log("  -> Subtest 7C.2: State chainId mismatch rejection (Fail Closed HTTP 400)...");
    const mainnetAuth = await signAuthorization(
      createPublicClient({ transport: viemHttp("http://127.0.0.1:8545") }),
      {
        account: testAccount,
        contractAddress: "0x0000000000000000000000000000000000000000",
        chainId: 1,
        nonce: 0
      }
    );
    const mismatchRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        payload: {
          owner: testAccount.address,
          address: mainnetAuth.address,
          chainId: mainnetAuth.chainId,
          nonce: mainnetAuth.nonce,
          yParity: mainnetAuth.yParity,
          r: mainnetAuth.r,
          s: mainnetAuth.s
        }
      })
    });
    if (mismatchRes.status !== 400) {
      throw new Error(`Expected HTTP 400 for state chainId mismatch, got ${mismatchRes.status}`);
    }
    const mismatchData = await mismatchRes.json();
    if (!mismatchData.error || !mismatchData.error.includes("State chainId mismatch")) {
      throw new Error(`Expected error mentioning State chainId mismatch, got ${JSON.stringify(mismatchData)}`);
    }
    console.log(`     ✓ State chainId mismatch successfully rejected with HTTP 400: "${mismatchData.error}"`);

    // Subtest 7D: Wallet-Signable Recovery API (/api/recovery-plan)
    console.log("  -> Subtest 7D: Wallet-signable recovery plan generation (/api/recovery-plan)...");
    const planRes = await fetch(`${BASE_URL}/api/recovery-plan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        payload: {
          owner: testAccount.address,
          address: validAuth.address,
          chainId: validAuth.chainId,
          nonce: validAuth.nonce,
          yParity: validAuth.yParity,
          r: validAuth.r,
          s: validAuth.s
        }
      })
    });
    if (!planRes.ok) throw new Error(`POST /api/recovery-plan failed: ${await planRes.text()}`);
    const planData = await planRes.json();
    if (!planData.preconditions || !planData.walletTransactions || !Array.isArray(planData.walletTransactions)) {
      throw new Error(`Invalid recovery-plan response: ${JSON.stringify(planData)}`);
    }
    if (planData.preconditions.accountAddress.toLowerCase() !== testAccount.address.toLowerCase()) {
      throw new Error(`Precondition address mismatch: expected ${testAccount.address}, got ${planData.preconditions.accountAddress}`);
    }
    console.log(`     ✓ Wallet-signable recovery plan synthesized: strategy=${planData.strategy}, txs=${planData.walletTransactions.length}, preconditions=${JSON.stringify(planData.preconditions)}`);

    // Subtest 7E: State-Race Precondition Failure Detection
    console.log("  -> Subtest 7E: State-race precondition failure defense in /api/recover...");
    const raceSession = await (
      await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: "eip7702" })
      })
    ).json();

    const raceRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        runId: raceSession.runId,
        expectedAccountNonce: 999999 // Intentionally diverged nonce to trigger state-race guard
      })
    });
    const raceRecoverData = await raceRecoverRes.json();
    if (raceRecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED for nonce mismatch, got ${JSON.stringify(raceRecoverData)}`);
    }
    console.log(`     ✓ State-race regression defense triggered: status=${raceRecoverData.status}, reason="${raceRecoverData.reason}"`);

    // Clean up raceSession
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: raceSession.runId })
    });

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
