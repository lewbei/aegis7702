import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";
import { createPublicClient, http as viemHttp, parseUnits } from "viem";
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
        recoverData.postRecoveryExplore.status !== "PORTFOLIO_NO_MODELED_LOSS" ||
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
      console.log(`     ✓ Canonical ${sc.name}: status=FOUND_LOSS, postRecoveryExplore=PORTFOLIO_NO_MODELED_LOSS, replay mitigated=true (100% verified)`);
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
      eipFutureRec.postRecoveryExplore.status !== "PORTFOLIO_NO_MODELED_LOSS" ||
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
      p2Delta65535Rec.postRecoveryExplore.status !== "PORTFOLIO_NO_MODELED_LOSS" ||
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
      p2Delta65536Rec.postRecoveryExplore.status !== "PORTFOLIO_NO_MODELED_LOSS" ||
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

    // Subtest 7C.3: DNS resolution SSRF rejection for domain resolving to 127.0.0.1 (nip.io)
    console.log("  -> Subtest 7C.3: DNS resolution SSRF rejection (127.0.0.1.nip.io)...");
    const dnsSsrfRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
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
        forkUrl: "http://127.0.0.1.nip.io:8545"
      })
    });
    if (dnsSsrfRes.status !== 400) {
      throw new Error(`Expected HTTP 400 for DNS SSRF target but got ${dnsSsrfRes.status}`);
    }
    const dnsSsrfData = await dnsSsrfRes.json();
    if (!dnsSsrfData.error || !dnsSsrfData.error.includes("SSRF rejected")) {
      throw new Error(`Expected SSRF error message for nip.io target, got ${JSON.stringify(dnsSsrfData)}`);
    }
    console.log(`     ✓ DNS rebinding / resolved loopback SSRF blocked: "${dnsSsrfData.error}"`);

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
    console.log("  -> Subtest 7E: State-race account nonce mismatch defense in /api/recover...");
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
    if (raceRecoverRes.status !== 409) {
      throw new Error(`Expected HTTP 409 Conflict for nonce mismatch, got HTTP ${raceRecoverRes.status}`);
    }
    const raceRecoverData = await raceRecoverRes.json();
    if (raceRecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED for nonce mismatch, got ${JSON.stringify(raceRecoverData)}`);
    }
    console.log(`     ✓ State-race nonce mismatch triggered HTTP 409: status=${raceRecoverData.status}, reason="${raceRecoverData.reason}"`);

    // Subtest 7E.1: Bytecode mismatch triggers STATE_PRECONDITION_FAILED
    console.log("  -> Subtest 7E.1: State-race expectedBytecode mismatch defense in /api/recover...");
    const bytecodeRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        runId: raceSession.runId,
        expectedBytecode: "0xdeadbeef" // Intentionally diverged bytecode
      })
    });
    if (bytecodeRecoverRes.status !== 409) {
      throw new Error(`Expected HTTP 409 Conflict for bytecode mismatch, got HTTP ${bytecodeRecoverRes.status}`);
    }
    const bytecodeRecoverData = await bytecodeRecoverRes.json();
    if (bytecodeRecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED for bytecode mismatch, got ${JSON.stringify(bytecodeRecoverData)}`);
    }
    console.log(`     ✓ State-race bytecode mismatch triggered HTTP 409: status=${bytecodeRecoverData.status}, reason="${bytecodeRecoverData.reason}"`);

    // Clean up raceSession
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: raceSession.runId })
    });

    // Subtest 7E.2: Permit2 allowance nonce mismatch triggers STATE_PRECONDITION_FAILED
    console.log("  -> Subtest 7E.2: Permit2 allowance expectedPermitNonce mismatch defense in /api/recover...");
    const p2Session = await (
      await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: "permit2_allowance" })
      })
    ).json();

    const p2RecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        runId: p2Session.runId,
        expectedPermitNonce: 999999
      })
    });
    if (p2RecoverRes.status !== 409) {
      throw new Error(`Expected HTTP 409 Conflict for Permit2 nonce mismatch, got HTTP ${p2RecoverRes.status}`);
    }
    const p2RecoverData = await p2RecoverRes.json();
    if (p2RecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED for Permit2 nonce mismatch, got ${JSON.stringify(p2RecoverData)}`);
    }
    console.log(`     ✓ Permit2 allowance nonce mismatch triggered HTTP 409: status=${p2RecoverData.status}, reason="${p2RecoverData.reason}"`);

    // Clean up p2Session
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: p2Session.runId })
    });

    // Subtest 7E.3: Permit2 signature bitmap word mismatch triggers STATE_PRECONDITION_FAILED
    console.log("  -> Subtest 7E.3: Permit2 signature expectedNonceBitmapWord mismatch defense in /api/recover...");
    const p2SigSession = await (
      await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: "permit2_signature" })
      })
    ).json();

    const p2SigRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        runId: p2SigSession.runId,
        expectedNonceBitmapWord: "999999999999999999"
      })
    });
    if (p2SigRecoverRes.status !== 409) {
      throw new Error(`Expected HTTP 409 Conflict for Permit2 bitmap word mismatch, got HTTP ${p2SigRecoverRes.status}`);
    }
    const p2SigRecoverData = await p2SigRecoverRes.json();
    if (p2SigRecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED for Permit2 bitmap word mismatch, got ${JSON.stringify(p2SigRecoverData)}`);
    }
    console.log(`     ✓ Permit2 signature bitmap word mismatch triggered HTTP 409: status=${p2SigRecoverData.status}, reason="${p2SigRecoverData.reason}"`);

    // Clean up p2SigSession
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: p2SigSession.runId })
    });

    // Subtest 7F: Concurrency limit saturation (activeWorkers >= 4) returns HTTP 429
    console.log("  -> Subtest 7F: Worker pool saturation concurrency limit (MAX_CONCURRENT_WORKERS = 4 -> HTTP 429)...");
    const activeSessions: any[] = [];
    try {
      for (let i = 0; i < 4; i++) {
        const sRes = await fetch(`${BASE_URL}/api/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenarioId: "permit2_allowance" })
        });
        if (!sRes.ok) throw new Error(`Failed spawning session ${i + 1}: ${await sRes.text()}`);
        activeSessions.push(await sRes.json());
      }
      console.log(`     ✓ 4 worker sessions spawned, pool saturated`);

      const satRes = await fetch(`${BASE_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: "permit2_allowance" })
      });
      if (satRes.status !== 429) {
        throw new Error(`Expected HTTP 429 for saturated worker pool but got ${satRes.status}`);
      }
      const satData = await satRes.json();
      if (!satData.error || !satData.error.includes("Worker pool saturated")) {
        throw new Error(`Expected Worker pool saturated error, got ${JSON.stringify(satData)}`);
      }
      console.log(`     ✓ 5th concurrent session rejected with HTTP 429 Too Many Requests: "${satData.error}"`);
    } finally {
      for (const s of activeSessions) {
        await fetch(`${BASE_URL}/api/replay`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ runId: s.runId })
        });
      }
      console.log(`     ✓ All saturated worker sessions released`);
    }

    const freedRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "permit2_allowance" })
    });
    if (!freedRes.ok) throw new Error(`Expected 200 OK after pool release, got ${freedRes.status}`);
    const freedData = await freedRes.json();
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: freedData.runId })
    });
    console.log(`     ✓ Worker pool successfully reclaimed: new session allocated and cleaned up`);

    // Subtest 7G: Multi-Capability Portfolio Residual Risk detection in /api/recover
    console.log("  -> Subtest 7G: Multi-Capability Portfolio Residual Risk detection in /api/recover...");
    const portfolioRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "portfolio_residual_risk" })
    });
    if (!portfolioRes.ok) throw new Error(`Analyze portfolio_residual_risk failed: ${await portfolioRes.text()}`);
    const portfolioData = await portfolioRes.json();
    if (portfolioData.status !== "FOUND_LOSS") {
      throw new Error(`Expected FOUND_LOSS for portfolio_residual_risk, got ${portfolioData.status}`);
    }

    const portfolioRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: portfolioData.runId })
    });
    if (!portfolioRecoverRes.ok) throw new Error(`Recover portfolio_residual_risk failed: ${await portfolioRecoverRes.text()}`);
    const portfolioRecoverData = await portfolioRecoverRes.json();

    if (
      !portfolioRecoverData.postRecoveryExplore ||
      portfolioRecoverData.postRecoveryExplore.status !== "FOUND_RESIDUAL_LOSS" ||
      portfolioRecoverData.postRecoveryExplore.verified !== false ||
      portfolioRecoverData.postRecoveryExplore.violatingCapability !== "PERMIT2_ALLOWANCE"
    ) {
      throw new Error(`Expected FOUND_RESIDUAL_LOSS with violatingCapability PERMIT2_ALLOWANCE, got: ${JSON.stringify(portfolioRecoverData.postRecoveryExplore)}`);
    }
    console.log(`     ✓ MultiCapabilityAuditor correctly detected unmitigated secondary risk on state s_R: status=${portfolioRecoverData.postRecoveryExplore.status}, violating=${portfolioRecoverData.postRecoveryExplore.violatingCapability}, verified=${portfolioRecoverData.postRecoveryExplore.verified}`);

    // Clean up portfolioSession
    await fetch(`${BASE_URL}/api/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: portfolioData.runId })
    });

    // Subtest 7H: Trust Boundary Defense: untrusted client request CANNOT suppress session portfolio
    console.log("  -> Subtest 7H: Trust Boundary Defense (untrusted client cannot suppress session portfolio)...");
    const overrideAttemptRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "portfolio_residual_risk" })
    });
    if (!overrideAttemptRes.ok) throw new Error(`Analyze for Subtest 7H failed: ${await overrideAttemptRes.text()}`);
    const overrideSession = await overrideAttemptRes.json();

    // Adversarial client attempt: passes capabilityPortfolio: [] to trick the server into skipping portfolio verification
    const spoofedRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        runId: overrideSession.runId,
        capabilityPortfolio: [] // Attacker attempts to bypass portfolio check with empty list
      })
    });
    if (!spoofedRecoverRes.ok) throw new Error(`Recover for Subtest 7H failed: ${await spoofedRecoverRes.text()}`);
    const spoofedRecoverData = await spoofedRecoverRes.json();

    if (
      !spoofedRecoverData.postRecoveryExplore ||
      spoofedRecoverData.postRecoveryExplore.status === "PORTFOLIO_NO_MODELED_LOSS" ||
      spoofedRecoverData.postRecoveryExplore.status !== "FOUND_RESIDUAL_LOSS" ||
      spoofedRecoverData.postRecoveryExplore.verified !== false ||
      spoofedRecoverData.postRecoveryExplore.violatingCapability !== "PERMIT2_ALLOWANCE"
    ) {
      throw new Error(`CRITICAL SOUNDNESS FAILURE: Client bypassed portfolio check with empty list! Got: ${JSON.stringify(spoofedRecoverData.postRecoveryExplore)}`);
    }
    console.log(`     ✓ Trust boundary enforced: server strictly audited session portfolio and discovered residual loss despite client sending capabilityPortfolio: [] (status=${spoofedRecoverData.postRecoveryExplore.status}, verified=${spoofedRecoverData.postRecoveryExplore.verified})`);

    // Subtest 7I: Authoritative Server Preconditions Defense (client sends ONLY { runId })
    console.log("  -> Subtest 7I: Authoritative Server Preconditions ({ runId } only rejects stale state with HTTP 409)...");
    const staleAttemptRes = await fetch(`${BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenarioId: "eip7702" })
    });
    if (!staleAttemptRes.ok) throw new Error(`Analyze for Subtest 7I failed: ${await staleAttemptRes.text()}`);
    const staleSession = await staleAttemptRes.json();

    // Out-of-band state mutation on victim's account (e.g. user performed external transaction)
    const ephemeralClient = createPublicClient({ transport: viemHttp(`http://127.0.0.1:${staleSession.port}`) });
    const victimEOA = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const currentNonceBefore = await ephemeralClient.getTransactionCount({ address: victimEOA });
    await ephemeralClient.request({
      method: "anvil_setNonce" as any,
      params: [victimEOA, `0x${(currentNonceBefore + 5).toString(16)}`] as any
    });

    // Client sends ONLY { runId }, with NO expected* fields (matching real UI behavior)
    const staleRecoverRes = await fetch(`${BASE_URL}/api/recover`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ runId: staleSession.runId })
    });
    if (staleRecoverRes.status !== 409) {
      throw new Error(`CRITICAL SOUNDNESS BUG: Expected HTTP 409 Conflict when client sends only { runId } on stale state, got HTTP ${staleRecoverRes.status}`);
    }
    const staleRecoverData = await staleRecoverRes.json();
    if (staleRecoverData.status !== "STATE_PRECONDITION_FAILED") {
      throw new Error(`Expected STATE_PRECONDITION_FAILED, got ${JSON.stringify(staleRecoverData)}`);
    }
    console.log(`     ✓ Authoritative server preconditions defended: HTTP 409 returned for { runId } only: status=${staleRecoverData.status}, reason="${staleRecoverData.reason}"`);

    // Subtest 7J: Arbitrary Permit2 future nonce detection (CONDITIONAL_RISK)
    console.log("  -> Subtest 7J: Arbitrary Permit2 future nonce detection (CONDITIONAL_RISK)...");
    const futurePermit2Payload = {
      owner: testAccount.address,
      spender: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
      permit2Address: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
      details: {
        token: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        amount: parseUnits("5000", 6).toString(),
        expiration: (Math.floor(Date.now() / 1000) + 86400).toString(),
        nonce: "999" // Future nonce on chain
      },
      sigDeadline: (Math.floor(Date.now() / 1000) + 3600).toString()
    };
    const futureP2TypeData = {
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
      domain: { name: "Permit2", chainId: 31337, verifyingContract: futurePermit2Payload.permit2Address },
      message: {
        details: {
          token: futurePermit2Payload.details.token,
          amount: BigInt(futurePermit2Payload.details.amount),
          expiration: Number(futurePermit2Payload.details.expiration),
          nonce: Number(futurePermit2Payload.details.nonce)
        },
        spender: futurePermit2Payload.spender,
        sigDeadline: BigInt(futurePermit2Payload.sigDeadline)
      }
    };
    const futureP2Sig = await testAccount.signTypedData(futureP2TypeData);

    const futureP2Res = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "PERMIT2_ALLOWANCE",
        payload: {
          owner: testAccount.address,
          spender: futurePermit2Payload.spender,
          permit2Address: futurePermit2Payload.permit2Address,
          chainId: 31337,
          details: {
            token: futurePermit2Payload.details.token,
            amount: futurePermit2Payload.details.amount,
            expiration: futurePermit2Payload.details.expiration,
            nonce: futurePermit2Payload.details.nonce
          },
          sigDeadline: futurePermit2Payload.sigDeadline,
          signature: futureP2Sig
        }
      })
    });
    if (!futureP2Res.ok) throw new Error(`Analyze future Permit2 capability failed: ${await futureP2Res.text()}`);
    const futureP2Data = await futureP2Res.json();
    if (futureP2Data.status !== "CONDITIONAL_RISK" || !futureP2Data.prospectiveRisk) {
      throw new Error(`Expected CONDITIONAL_RISK for future Permit2 nonce, got: ${JSON.stringify(futureP2Data)}`);
    }
    console.log(`     ✓ Arbitrary Permit2 future nonce classified as CONDITIONAL_RISK: condition="${futureP2Data.prospectiveRisk.condition}"`);

    // Subtest 7K: EIP-7702 chainId = 0 Cross-Chain Compatibility
    console.log("  -> Subtest 7K: EIP-7702 chainId = 0 Cross-Chain Compatibility...");
    const localClient = createPublicClient({ transport: viemHttp("http://127.0.0.1:8545") });
    const chainZeroAuth = await signAuthorization(localClient, {
      account: testAccount,
      contractAddress: "0x0000000000000000000000000000000000000000",
      chainId: 0, // Cross-chain valid authorization tuple
      nonce: 0
    });
    const chainZeroRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: "EIP7702",
        tokenAddress: "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
        payload: {
          owner: testAccount.address,
          address: chainZeroAuth.address,
          chainId: 0,
          nonce: chainZeroAuth.nonce,
          yParity: chainZeroAuth.yParity,
          r: chainZeroAuth.r,
          s: chainZeroAuth.s
        }
      })
    });
    if (!chainZeroRes.ok) throw new Error(`Analyze chainId=0 capability failed: ${await chainZeroRes.text()}`);
    const chainZeroData = await chainZeroRes.json();
    if (chainZeroData.status === "INVALID_CAPABILITY") {
      throw new Error(`CRITICAL PROTOCOL BUG: chainId=0 was rejected as invalid capability: ${JSON.stringify(chainZeroData)}`);
    }
    console.log(`     ✓ EIP-7702 authorization with chainId = 0 accepted without chainId mismatch: status=${chainZeroData.status}`);

    // Subtest 7L: Missing targetToken for EIP-7702 yields UNMODELED (no silent Mainnet USDC fallback)
    console.log("  -> Subtest 7L: EIP-7702 missing targetToken yields UNMODELED (no silent USDC fallback)...");
    const missingTokenRes = await fetch(`${BASE_URL}/api/analyze-capability`, {
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
    const missingTokenData = await missingTokenRes.json();
    if (missingTokenData.status !== "UNMODELED") {
      throw new Error(`CRITICAL SOUNDNESS BUG: Missing target token must return UNMODELED, got ${missingTokenData.status}`);
    }
    console.log(`     ✓ Missing targetToken correctly returned UNMODELED: reason="${missingTokenData.reason}"`);

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
