# Aegis7702: Immutable Submission Evidence & Audit Package

**Hackathon:** 3rd-Web-Hack Hackathon (TechZap Club, Sept 2026)  
**Project Name:** Aegis7702  
**Tagline:** Catches zero-delta deferred drains in EIP-7702 & Permit2 signatures. Aegis7702 verifies multi-step capability reachability on EVM forks and synthesizes verified on-fork recovery.  
**Repository:** [https://github.com/lewbei/aegis7702](https://github.com/lewbei/aegis7702)  
**Release Tag:** [`hackathon-final-v1.0.3`](https://github.com/lewbei/aegis7702/releases/tag/hackathon-final-v1.0.3)  
**Latest Verified Release CI Run:** [GitHub Actions Run #36086398781](https://github.com/lewbei/aegis7702/actions/runs/36086398781) (4/4 jobs green)  
**Reference Benchmark CI Run:** [GitHub Actions Run #36086398781](https://github.com/lewbei/aegis7702/actions/runs/36086398781)  

---

## 1. Verified CI Execution Package

The complete verification pipeline was executed end-to-end on GitHub Actions CI across all four dedicated jobs:

| CI Job Name | Status | Duration | Scope |
|---|:---:|:---:|---|
| **Foundry Solidity Tests** | ✅ `success` | 27s | 14/14 security tests passing across 4 suites |
| **TypeScript Reachability Engine Kill Tests** | ✅ `success` | 6m 29s | Typecheck + 3 kill tests + 5 adversarial recovery scenarios |
| **React Frontend Build** | ✅ `success` | 15s | Clean Vite 8 + React 19 production build (`0` errors) |
| **USENIX 58-Case Executable Benchmark** | ✅ `success` | 29m 40s | Full Prague-EVM execution across all 58 artifact bytecodes |

---

## 2. Benchmark A: Real-World Empirical Evaluation on 58 USENIX Delegates ($B_1$ vs. Aegis CRV)

- **Reference Corpus:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.
- **Inclusion Criterion ($C$):** $C = \text{EOA final detections} \cap \text{sensitive-function detections}$, yielding **58 chain-address cases (53 unique delegate addresses, 47 unique runtime bytecodes)** across 6 production blockchains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon).
- **Execution Methodology:** Original runtime bytecodes extracted directly from the USENIX artifact, deployed via `anvil_setCode` into standardized Prague-EVM snapshots. Both Baseline $B_1$ (`StateAwareGreedyRunner`) and Aegis CRV (`ReachabilityExplorer` with $k \le 3$) evaluated on the exact same state $s_0$.

### Quantitative Results Matrix

| Metric | Baseline B₁ (Greedy Forward) | Aegis CRV (Tree Search) | Empirical Meaning |
|---|:---:|:---:|---|
| **Evaluated Real Artifact Contracts** | **58 (53 addresses, 47 bytecodes)** | **58 (53 addresses, 47 bytecodes)** | Full inclusion set $C$ from USENIX Security '26 |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | **51 / 58 (87.9%)** | Identical 51/51 exploit discovery on all vulnerable delegates |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **0 / 58 (0.0%)** | **6 / 58 (10.3%)** | Aegis rolls back reverting calls to certify no modeled loss |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | **1 / 58 (1.7%)** | Identical abstention on non-modeled selector (`0x628ff693`) |
| **Execution Halted on Revert (`REVERT_ERROR`)** | **6 / 58 (10.3%)** | **0 / 58 (0.0%)** | Linear B₁ halts on revert; Aegis recovers via snapshot rollback |
| **Immediate-Delta Baseline Miss Rate** | 51 / 51 (100%) | 51 / 51 (100%) | B₀ missed all 51 executable loss cases ($\Delta = \$0.00$) |
| **Clean-State Witness Replay Success** | 51 / 51 (100%) | 51 / 51 (100%) | 100% concrete loss reproducibility on fresh snapshots |
| **Post-Recovery Exploit Neutralization** | 51 / 51 (100%) | 51 / 51 (100%) | 100% of replayed exploits neutralized ($L(s_R) = 0$ via Type-4 recovery) |
| **Controlled Protocol-Negative Verification** | **4 / 4 (0 false alarms)** | **4 / 4 (0 false alarms)** | Zero false alarms across 4 negative controls |

#### Resource & Latency Comparison
- **EVM Calls (Median):** B₁ = 2, Aegis CRV = 2 (51 FOUND_LOSS cases)
- **EVM Snapshots (Median):** B₁ = 0, Aegis CRV = 2 (51 FOUND_LOSS cases)
- **Runtime (Median):** B₁ = 63 ms, Aegis CRV = 79 ms (51 FOUND_LOSS cases)

Full 58-case execution details: [`testdata/AEGIS_USENIX_EVALUATION.md`](./testdata/AEGIS_USENIX_EVALUATION.md).

---

## 3. Benchmark B: Controlled Adversarial Capability Benchmark ($B_1$ vs. Aegis CRV)

Executed live via `make test-comparison` (`cd engine && npm run eval:comparison`):

| Fixture | System | Outcome | Visited States | EVM Calls | Snapshots | Backtracks | Local Anvil Latency* | Verdict / Architectural Finding |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **1. Canonical EIP-7702 Sweep** | B₁ (Greedy Forward) | `FOUND_LOSS` | 2 | 2 | 0 | 0 | ~66 ms | **Pass (Optimal on Linear):** Linear forward simulation suffices with zero snapshot overhead |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 2 | 2 | 2 | 2 | ~79 ms | **Pass (Equivalent):** Identifies identical exploit trace; snapshots incur minor overhead |
| **2. Canonical Permit2 Drain** | B₁ (Greedy Forward) | `FOUND_LOSS` | 2 | 2 | 0 | 0 | ~60 ms | **Pass (Depth 2 Equivalent):** Both execute `permit` → `transferFrom` |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 2 | 2 | 2 | 2 | ~76 ms | **Pass (Depth 2 Equivalent):** Identifies identical exploit trace |
| **3. Branching Decoys (Policy Stress Test)** | B₁ (Greedy Forward Policy) | `REVERT_ERROR` | 2 | 2 | 0 | 0 | ~42 ms | **Halted on Revert Decoy:** First-action greedy execution halted on reverting branch |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 4 | 6 | 6 | 6 | ~171 ms | **PASS (True Positive):** Snapshot rollback backtracks around decoys to discover drain |
| **4. Post-Recovery Residual Risk** | B₁ (Single-Trace Replay) | `TRACE_BLOCKED` | 1 | 1 | 0 | 0 | ~20 ms | **Trace Blocked:** Exploit trace $\pi_{7702}$ blocked; makes no claim on overall account safety |
| | Aegis CRV (Re-Search Known Permit2 Cap from $s_R$) | `FOUND_LOSS` | 2 | 2 | 2 | 2 | ~76 ms | **PASS (True Defense):** Re-search on state $s_R$ flags residual Permit2 vulnerability |

*\*Latencies represent single-run measurements on local Anvil nodes and illustrate relative overhead rather than statistical microbenchmarks.*

---

## 4. Deliverable Links

1. **Submission Writeup:** [`SUBMISSION.md`](./SUBMISSION.md)
2. **Interactive Visualizer Code:** [`app/src/App.tsx`](./app/src/App.tsx)
3. **6-Slide Pitch Deck:** [`docs/PITCH_DECK.md`](./docs/PITCH_DECK.md)
4. **3-Minute Video Presentation Script:** [`docs/DEMO_VIDEO_SCRIPT.md`](./docs/DEMO_VIDEO_SCRIPT.md)
5. **Judge Technical Defense & Q&A:** [`docs/JUDGE_QA.md`](./docs/JUDGE_QA.md)
6. **Smart Contracts & Test Suites:** [`contracts/`](./contracts/)
7. **TypeScript Engine & Kill Tests:** [`engine/`](./engine/)

---

## 5. Judge Reproduction Instructions (Quickstart)

```bash
# 1. Clone repository
git clone https://github.com/lewbei/aegis7702.git
cd aegis7702

# 2. Run Foundry Contract Security Suite (14 tests in 13ms)
make test-contracts

# 3. Run TypeScript Reachability Kill Tests & Integration Scenarios
make test-engine

# 4. Run Rigorous Controlled Empirical Baseline Comparison (B1 vs Aegis CRV)
make test-comparison

# 5. Launch Interactive Prototype Dashboard
make demo
# Opens http://localhost:5173 connected to engine on :3099
```

---

## 6. Formal Verification Contract

$$\boxed{L(s_0, T_\pi(s_0)) > 0 \quad\land\quad L(s_R, T_\pi(s_R)) = 0}$$

Aegis7702 proves that:
1. Under initial state $s_0$, an immediate-delta baseline evaluates $\Delta = \$0.00$ (**false negative**).
2. Within bounded search depth $k \le 3$, an executable multi-step exploit sequence $\pi$ produces asset loss $L(s_0, T_\pi(s_0)) > 0$ on live EVM state.
3. The synthesized state-specific recovery transaction $s \to s_R$ invalidates the capability on-chain.
4. When the identical exploit trace $\pi$ is replayed against post-recovery state $s_R$, tracked asset loss is completely eliminated: $L(s_R, T_\pi(s_R)) = 0$.
