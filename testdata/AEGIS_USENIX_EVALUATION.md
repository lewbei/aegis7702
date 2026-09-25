# Benchmark A: Real-World Empirical Evaluation on 58 USENIX Delegates

**Reference Corpus:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.

## Inclusion Methodology & Protocol
- **Dataset Source:** Official artifact from USENIX Security '26 containing 793 EOA detection records (718 unique contract addresses) across 7 production blockchains.
- **Inclusion Criterion:** $C = \text{EOA final detections} \cap \text{sensitive-function detections}$, yielding **58 chain-address cases (53 unique delegate addresses, 47 unique runtime bytecodes)** across 6 production chains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon).
- **Execution Pipeline:** Real bytecode deployed via `anvil_setCode` into ephemeral local Anvil Prague EVM state snapshots, evaluated under identical starting state $s_0$:
  - **Baseline B₁ (`StateAwareGreedyRunner`):** State-aware greedy forward execution with full capability semantics (EIP-7702 Type-4 relay) but linear execution (0 EVM snapshots, no backtracking).
  - **Aegis CRV (`ReachabilityExplorer`):** Bounded reachability tree search ($k \le 3$) with state snapshot rollback and branch backtracking (`evm_snapshot` / `evm_revert`).
  - **Clean-State Witness Replay:** Discovered counterexample witnesses are replayed on fresh state snapshots to verify concrete loss.
  - **Post-Recovery Verification:** Automated synthesis of EIP-7702 recovery transactions, replaying historical traces against state $s_R$.

---

## Detailed Comparative Execution Matrix (Full 58 Cases + 4 Negatives)

| Benchmark ID | Chain | Delegate Address | Function Archetype | B₁ Status | Aegis CRV Status | B₁ Calls | Aegis Calls | Aegis Snaps | B₁ Time | Aegis Time | Delta | Replay Valid | Recovery Blocked |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `USENIX-FULL-001` | `optimism` | `0x2f1211e3...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 94ms | 96ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-002` | `optimism` | `0xbe7ae1e5...` | `sweepTokens(address,uint` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 73ms | 82ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-003` | `optimism` | `0xf443cf13...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 73ms | 87ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-004` | `optimism` | `0x7f7f0dcb...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 87ms | 83ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-005` | `optimism` | `0x7b6ae45c...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 79ms | 89ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-006` | `optimism` | `0x0c1a9297...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 4064ms | 90ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-007` | `optimism` | `0x128f99fc...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 4065ms | 83ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-008` | `optimism` | `0x2d274da3...` | `sweepTokens(address)` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 67ms | 82ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-009` | `optimism` | `0x280c17a6...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 68ms | 80ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-010` | `optimism` | `0xeacc7e98...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 64ms | 84ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-011` | `optimism` | `0x54827357...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 58ms | 79ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-012` | `arbitrum` | `0x93c1bfc9...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 63ms | 75ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-013` | `arbitrum` | `0xbbc9e641...` | `sweep(address[]) / sweep` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 61ms | 79ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-014` | `arbitrum` | `0xa95fe020...` | `sweepTokens(address)` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 4062ms | 71ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-015` | `arbitrum` | `0x48d17cfd...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 86ms | 87ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-016` | `polygon` | `0x93c1bfc9...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 57ms | 75ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-017` | `bnb` | `0x29ada5cb...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 70ms | 83ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-018` | `bnb` | `0xddb2dbde...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 4061ms | 74ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-019` | `bnb` | `0x45cf19a8...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 57ms | 77ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-020` | `bnb` | `0x03d3a033...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 57ms | 87ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-021` | `bnb` | `0x677237ec...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 53ms | 74ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-022` | `bnb` | `0xef7b31f4...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 63ms | 4072ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-023` | `bnb` | `0x14d73d97...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 61ms | 79ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-024` | `bnb` | `0x4351d1be...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 63ms | 78ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-025` | `bnb` | `0xef99fc5b...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 59ms | 75ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-026` | `bnb` | `0xdc534312...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 56ms | 76ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-027` | `bnb` | `0xd53f5c32...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 59ms | 72ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-028` | `bnb` | `0x4c3cbefc...` | `sweepTokens(address)` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 57ms | 93ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-029` | `base` | `0xecdc0b36...` | `sweepETH() / sweepTokens` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 61ms | 81ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-030` | `base` | `0xfc1e0178...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 72ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-031` | `base` | `0x3495fed2...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 4058ms | 77ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-032` | `base` | `0xd1d4b213...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 58ms | 4081ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-033` | `base` | `0xcc7c302c...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 78ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-034` | `base` | `0x52064cea...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 80ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-035` | `base` | `0xfc4a4381...` | `sweepETH() / sweepTokens` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 64ms | 82ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-036` | `base` | `0x214070b6...` | `sweep(address[]) / sweep` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 73ms | 98ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-037` | `base` | `0x09551d2a...` | `sweepERC20(address)` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 66ms | 85ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-038` | `base` | `0x93c1bfc9...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 67ms | 81ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-039` | `base` | `0x628ff693...` | `sweepToken(address)` | `UNMODELED` | **`UNMODELED`** | 0 | 0 | 0 | 20ms | 17ms | `MATCH` | - | - |
| `USENIX-FULL-040` | `base` | `0xae9d88d9...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 68ms | 94ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-041` | `base` | `0x49c1d860...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 71ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-042` | `ethereum` | `0x544bb1d8...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 75ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-043` | `ethereum` | `0x2ae985de...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 54ms | 71ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-044` | `ethereum` | `0xf5fb3834...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 60ms | 72ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-045` | `ethereum` | `0xecdbddd1...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 56ms | 78ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-046` | `ethereum` | `0x47daf8e2...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 55ms | 71ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-047` | `ethereum` | `0x7fbeb059...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 57ms | 74ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-048` | `ethereum` | `0x7f7f0dcb...` | `sweepERC20(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 63ms | 4071ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-049` | `ethereum` | `0xc39d0c26...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 66ms | 84ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-050` | `ethereum` | `0x8c16769d...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 60ms | 73ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-051` | `ethereum` | `0x93c1bfc9...` | `sweepTokens(address)` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 59ms | 78ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-052` | `ethereum` | `0x3d560dad...` | `sweepERC20(address)` | `REVERT_ERROR` | **`NO_MODELED_LOSS`** | 2 | 2 | 2 | 58ms | 72ms | `DIVERGE (REVERT_ERROR vs NO_MODELED_LOSS)` | - | - |
| `USENIX-FULL-053` | `ethereum` | `0xf5258ab8...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 58ms | 4071ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-054` | `ethereum` | `0x89318ee0...` | `sweep(address[]) / sweep` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 58ms | 64ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-055` | `ethereum` | `0xef7b31f4...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 61ms | 71ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-056` | `ethereum` | `0xb7893c1f...` | `drainToken(address,uint2` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 4052ms | 82ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-057` | `ethereum` | `0x912ac7a8...` | `sweep(address[]) / sweep` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 72ms | 74ms | `MATCH` | ✅ YES | ✅ YES |
| `USENIX-FULL-058` | `ethereum` | `0x2a755758...` | `sweep(address[])` | `FOUND_LOSS` | **`FOUND_LOSS`** | 2 | 2 | 2 | 56ms | 76ms | `MATCH` | ✅ YES | ✅ YES |
| `CTRL-NEG-001` | `ethereum` | `0x00000000...` | `BENIGN_GUARD_REVERTS` | `NO_MODELED_LOSS` | **`NO_MODELED_LOSS`** | 1 | 1 | 1 | 47ms | 52ms | `MATCH` | - | - |
| `CTRL-NEG-002` | `ethereum` | `0x00000000...` | `CLEAN_EOA_NO_DELEGATION` | `NO_MODELED_LOSS` | **`NO_MODELED_LOSS`** | 1 | 1 | 1 | 52ms | 42ms | `MATCH` | - | - |
| `CTRL-NEG-003` | `ethereum` | `0x2f1211e3...` | `EXPIRED_NONCE_MISMATCH` | `NO_MODELED_LOSS` | **`NO_MODELED_LOSS`** | 0 | 0 | 0 | 19ms | 16ms | `MATCH` | - | - |
| `CTRL-NEG-004` | `ethereum` | `0x48d17cfd...` | `ZERO_VICTIM_BALANCE` | `NO_MODELED_LOSS` | **`NO_MODELED_LOSS`** | 1 | 1 | 1 | 47ms | 56ms | `MATCH` | - | - |

---

## Quantitative Evaluation Summary

### 1. Detection Status Breakdown (58 Real USENIX Cases)

| Metric | Baseline B₁ (Greedy Forward) | Aegis CRV (Tree Search) | Delta / Meaning |
|---|---|---|---|
| **Exploit Detected (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | **51 / 58 (87.9%)** | Identical 51/51 exploit discovery on all vulnerable delegates |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **0 / 58 (0.0%)** | **6 / 58 (10.3%)** | Aegis rolls back reverting calls to certify no modeled loss |
| **Unmodeled Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | **1 / 58 (1.7%)** | Identical abstention on non-modeled selector |
| **Execution Halted on Revert (`REVERT_ERROR`)** | **6 / 58 (10.3%)** | **0 / 58 (0.0%)** | Linear B₁ halts on revert; Aegis recovers via snapshot rollback |
| **Overall Agreement Rate** | **52 / 58 (89.7%)** | **52 / 58 (89.7%)** | Perfect agreement on all 51 vulnerable cases & 1 unmodeled case |

### 2. Resource & Overhead Comparison

| Overhead Metric | Baseline B₁ (All 58) | Aegis CRV (All 58) | Baseline B₁ (51 FOUND_LOSS) | Aegis CRV (51 FOUND_LOSS) |
|---|---|---|---|---|
| **EVM Calls (Mean)** | **1.97** | **1.97** | **2.00** | **2.00** |
| **EVM Calls (Median)** | **2** | **2** | **2** | **2** |
| **EVM Snapshots (Mean)** | **0.00** | **1.97** | **0.00** | **2.00** |
| **EVM Snapshots (Median)** | **0** | **2** | **0** | **2** |
| **Runtime ms (Mean)** | **476.7ms** | **353.7ms** | **455.8ms** | **392.4ms** |
| **Runtime ms (Median)** | **63ms** | **79ms** | **63ms** | **79ms** |

### 3. Verification & Governance Metrics
- **Clean-State Witness Replay Success:** 51 / 51 (100% concrete reproducibility on fresh EVM snapshot).
- **Post-Recovery Exploit Neutralization:** 51 / 51 (100% neutralized via Type-4 recovery transactions).
- **Controlled Negative Controls:** 4 / 4 negative controls produced zero loss witnesses under both B₁ and Aegis CRV.

---

## Empirical Boundary & Key Scientific Findings

### Finding 1: Monotonic Linear Topologies in Real-World Exploits
On the 58 real-world USENIX Security 2026 cases:
1. **Identical Exploit Detection (51/51 FOUND_LOSS):** On all 51 vulnerable cases, Baseline B₁ and Aegis CRV achieve **100% identical detection**.
   Empirical inspection of the USENIX artifact contracts explains why: **100% of the executable malicious delegates in the USENIX corpus exhibit monotonic single-path exploit topologies** (a single `sweep(address, address)` or direct asset evacuation routine). There are zero branching decoys or state-dependent branch guards.
   In this linear regime:
   - B₁ is optimal in resource consumption: **0 EVM snapshots** and lower median latency (63ms vs 79ms).
   - Tree search with EVM snapshots introduces snapshot overhead without yielding additional detection on this specific historical dataset.
2. **Revert Resilience on Non-Vulnerable Contracts (6 cases):** On the 6 non-vulnerable cases where contract calls revert due to unsatisfied preconditions, B₁ halts with `REVERT_ERROR` because it lacks state rollback. Aegis CRV catches the revert, restores state, and certifies `NO_MODELED_LOSS`.
3. **Transparent Abstention (1 case):** On `0x628ff693...` (`sweepToken(address)`), both systems cleanly abstain with `UNMODELED`.

### Finding 2: Where Tree Search is Structurally Required (Benchmark B)
To establish the exact boundary where tree search provides structural capability beyond greedy linear execution, we refer to the adversarial capability benchmarks in `evalBaselineComparison.ts` (Benchmark B):
1. **Adversarial Branching Decoys (Fixture 3):** When an attacker contract introduces candidate branches that revert before the true exploit (e.g. `decoyRevert -> decoyPing -> evacuateAsset`), B₁ halts on the first reverting candidate (`REVERT_ERROR`), failing to discover the vulnerability. Aegis CRV uses EVM snapshots and depth-first backtracking to explore past reverting decoys and locate the asset drain.
2. **Post-Recovery Safety Certification (Fixture 4):** Single-trace replay proves only that historical trace $\pi$ is blocked (`TRACE_BLOCKED`), making no claim about overall account safety. Aegis CRV re-searches known candidate capabilities from state $s_R$ to uncover residual multi-capability exposure (e.g., an unrevoked Permit2 allowance).
