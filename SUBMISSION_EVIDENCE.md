# Aegis7702: Immutable Submission Evidence & Audit Package

**Hackathon:** 3rd-Web-Hack Hackathon (TechZap Club, Sept 2026)  
**Project Name:** Aegis7702  
**Tagline:** Catches zero-delta deferred drains in EIP-7702 & Permit2 signatures. Aegis7702 verifies multi-step capability reachability on EVM forks and synthesizes verified on-fork recovery.  
**Repository:** [https://github.com/lewbei/aegis7702](https://github.com/lewbei/aegis7702)  
**Release Tag:** [`hackathon-final-v1.0.0`](https://github.com/lewbei/aegis7702/releases/tag/hackathon-final-v1.0.0)  
**Latest Verified Release CI Run:** [GitHub Actions Run #35972326804](https://github.com/lewbei/aegis7702/actions/runs/35972326804) (4/4 jobs green)  
**Reference Benchmark CI Run:** [GitHub Actions Run #35964170153](https://github.com/lewbei/aegis7702/actions/runs/35964170153)  

---

## 1. Verified CI Execution Package

The complete verification pipeline was executed end-to-end on GitHub Actions CI across all four dedicated jobs:

| CI Job Name | Status | Duration | Scope |
|---|:---:|:---:|---|
| **Foundry Solidity Tests** | ✅ `success` | 25s | 14/14 security tests passing across 4 suites |
| **TypeScript Reachability Engine Kill Tests** | ✅ `success` | 5m 46s | 3 kill tests + 5 adversarial recovery scenarios |
| **React Frontend Build** | ✅ `success` | 18s | Clean Vite 8 + React 19 production build (`0` errors) |
| **USENIX 58-Case Executable Benchmark** | ✅ `success` | 29m 49s | Full Prague-EVM execution across all 58 artifact bytecodes |

---

## 2. Empirical Benchmark Evidence Summary

- **Reference Corpus:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.
- **Inclusion Criterion ($C$):** $C = \text{EOA final detections} \cap \text{sensitive-function detections}$, yielding **58 chain-address cases (53 unique delegate addresses, 47 unique runtime bytecodes)** across 6 production blockchains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon).
- **Execution Methodology:** Original runtime bytecodes extracted directly from the USENIX artifact, deployed via `anvil_setCode` into standardized Prague-EVM snapshots.

### Quantitative Results Matrix

| Metric | Empirical Value | Rigorous Meaning |
|---|:---:|---|
| **Evaluated Real Artifact Contracts** | **58 (53 unique addresses, 47 unique bytecodes)** | Full inclusion set $C$ from USENIX Security '26 |
| **Aegis Modeled Coverage** | **57 / 58 (98.3%)** | Supported capability action semantics |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | Concrete multi-step loss paths proven on EVM state |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **6 / 58 (10.3%)** | Real contract requiring additional preconditions |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | Interface outside current capability generator semantics |
| **Immediate-Delta Baseline Miss Rate** | **51 / 51 (100%)** | Baseline missed all 51 executable loss cases ($\Delta = \$0.00$) |
| **Clean-State Witness Replay Success** | **51 / 51 (100%)** | 100% concrete loss reproducibility on fresh snapshots |
| **Post-Recovery Exploit Neutralization** | **51 / 51 (100%)** | 100% of replayed exploits neutralized ($L(s_R) = 0$) |
| **Controlled Protocol-Negative Accuracy** | **4 / 4 (0 false positives)** | Zero false alarms across 4 negative controls |

Full 58-case execution details: [`testdata/AEGIS_USENIX_EVALUATION.md`](./testdata/AEGIS_USENIX_EVALUATION.md).

---

## 3. Deliverable Links

1. **Submission Writeup:** [`SUBMISSION.md`](./SUBMISSION.md)
2. **Interactive Visualizer Code:** [`app/src/App.tsx`](./app/src/App.tsx)
3. **6-Slide Pitch Deck:** [`docs/PITCH_DECK.md`](./docs/PITCH_DECK.md)
4. **3-Minute Video Presentation Script:** [`docs/DEMO_VIDEO_SCRIPT.md`](./docs/DEMO_VIDEO_SCRIPT.md)
5. **Judge Technical Defense & Q&A:** [`docs/JUDGE_QA.md`](./docs/JUDGE_QA.md)
6. **Smart Contracts & Test Suites:** [`contracts/`](./contracts/)
7. **TypeScript Engine & Kill Tests:** [`engine/`](./engine/)

---

## 4. Judge Reproduction Instructions (Quickstart)

```bash
# 1. Clone repository
git clone https://github.com/lewbei/aegis7702.git
cd aegis7702

# 2. Run Foundry Contract Security Suite (14 tests in 13ms)
make test-contracts

# 3. Run TypeScript Reachability Kill Tests & Adversarial Scenarios (fast local execution)
make test-engine

# 4. Launch Interactive Prototype Dashboard
make demo
# Opens http://localhost:5173 connected to engine on :3099
```

---

## 5. Formal Verification Contract

$$\boxed{L(s_0, T_\pi(s_0)) > 0 \quad\land\quad L(s_R, T_\pi(s_R)) = 0}$$

Aegis7702 proves that:
1. Under initial state $s_0$, an immediate-delta baseline evaluates $\Delta = \$0.00$ (**false negative**).
2. Within bounded search depth $k \le 3$, an executable multi-step exploit sequence $\pi$ produces asset loss $L(s_0, T_\pi(s_0)) > 0$ on live EVM state.
3. The synthesized state-specific recovery transaction $s \to s_R$ invalidates the capability on-chain.
4. When the identical exploit trace $\pi$ is replayed against post-recovery state $s_R$, tracked asset loss is completely eliminated: $L(s_R, T_\pi(s_R)) = 0$.
