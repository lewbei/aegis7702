# Aegis7702-USENIX-Eval: Full 58-Case Empirical Evaluation Results

**Reference Corpus:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.

## Inclusion Methodology & Protocol
- **Dataset Source:** Official artifact from USENIX Security '26 containing 793 EOA detection records (718 unique contract addresses) across 7 production blockchains.
- **Inclusion Criterion:** $C = \text{EOA final detections} \cap \text{sensitive-function detections}$, yielding **58 chain-address cases (53 unique delegate addresses, 47 unique runtime bytecodes)**.
- **Evaluated Scope:** Full inclusion set $C$ of 58 chain-address cases (representing 53 unique delegate addresses and 47 unique runtime-bytecode hashes) across 6 production chains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon), evaluated alongside 4 controlled protocol-negative cases.
- **Execution Pipeline:** Real bytecode deployed via `anvil_setCode` into ephemeral local Anvil Prague EVM state snapshots, evaluated under three deterministic states:
  - `FOUND_LOSS`: Reachability explorer discovers an executable multi-step exploit path causing $L(s_0, s') > 0$.
  - `NO_MODELED_LOSS`: Reachability explorer exhaustively searches supported candidate actions within bounded depth without finding asset loss.
  - `UNMODELED`: Delegate contract interface or calldata structure is outside current modeled capability semantics.
- **Clean-State Witness Replay:** Every discovered counterexample witness $\pi$ is replayed on a fresh EVM state snapshot to verify real loss before synthesizing recovery.

---

## Detailed Execution Matrix

| Benchmark ID | Chain | Delegate Address | Function Archetype | Immediate-Delta Baseline | Aegis7702 Verifier | Reachable Loss | Clean-State Replay Valid? | Replay Blocked by Recovery? |
|---|---|---|---|---|---|---|---|---|
| `USENIX-FULL-001` | `optimism` | `0x2f1211e3...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-002` | `optimism` | `0xbe7ae1e5...` | `sweepTokens(address,uint256)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-003` | `optimism` | `0xf443cf13...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-004` | `optimism` | `0x7f7f0dcb...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-005` | `optimism` | `0x7b6ae45c...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-006` | `optimism` | `0x0c1a9297...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-007` | `optimism` | `0x128f99fc...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-008` | `optimism` | `0x2d274da3...` | `sweepTokens(address)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-009` | `optimism` | `0x280c17a6...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-010` | `optimism` | `0xeacc7e98...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-011` | `optimism` | `0x54827357...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-012` | `arbitrum` | `0x93c1bfc9...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-013` | `arbitrum` | `0xbbc9e641...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-014` | `arbitrum` | `0xa95fe020...` | `sweepTokens(address)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-015` | `arbitrum` | `0x48d17cfd...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-016` | `polygon` | `0x93c1bfc9...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-017` | `bnb` | `0x29ada5cb...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-018` | `bnb` | `0xddb2dbde...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-019` | `bnb` | `0x45cf19a8...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-020` | `bnb` | `0x03d3a033...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-021` | `bnb` | `0x677237ec...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-022` | `bnb` | `0xef7b31f4...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-023` | `bnb` | `0x14d73d97...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-024` | `bnb` | `0x4351d1be...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-025` | `bnb` | `0xef99fc5b...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-026` | `bnb` | `0xdc534312...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-027` | `bnb` | `0xd53f5c32...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-028` | `bnb` | `0x4c3cbefc...` | `sweepTokens(address)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-029` | `base` | `0xecdc0b36...` | `sweepETH() / sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-030` | `base` | `0xfc1e0178...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-031` | `base` | `0x3495fed2...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-032` | `base` | `0xd1d4b213...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-033` | `base` | `0xcc7c302c...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-034` | `base` | `0x52064cea...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-035` | `base` | `0xfc4a4381...` | `sweepETH() / sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-036` | `base` | `0x214070b6...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-037` | `base` | `0x09551d2a...` | `sweepERC20(address)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-038` | `base` | `0x93c1bfc9...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-039` | `base` | `0x628ff693...` | `sweepToken(address)` | `SAFE` | **`UNMODELED`** | 0.00 USDC | - | - |
| `USENIX-FULL-040` | `base` | `0xae9d88d9...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-041` | `base` | `0x49c1d860...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-042` | `ethereum` | `0x544bb1d8...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-043` | `ethereum` | `0x2ae985de...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-044` | `ethereum` | `0xf5fb3834...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-045` | `ethereum` | `0xecdbddd1...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-046` | `ethereum` | `0x47daf8e2...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-047` | `ethereum` | `0x7fbeb059...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-048` | `ethereum` | `0x7f7f0dcb...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-049` | `ethereum` | `0xc39d0c26...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-050` | `ethereum` | `0x8c16769d...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-051` | `ethereum` | `0x93c1bfc9...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-052` | `ethereum` | `0x3d560dad...` | `sweepERC20(address)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-FULL-053` | `ethereum` | `0xf5258ab8...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-054` | `ethereum` | `0x89318ee0...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-055` | `ethereum` | `0xef7b31f4...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-056` | `ethereum` | `0xb7893c1f...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-057` | `ethereum` | `0x912ac7a8...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-FULL-058` | `ethereum` | `0x2a755758...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `CTRL-NEG-001` | `ethereum` | `0x00000000...` | `BENIGN_GUARD_REVERTS` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-002` | `ethereum` | `0x00000000...` | `CLEAN_EOA_NO_DELEGATION` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-003` | `ethereum` | `0x2f1211e3...` | `EXPIRED_NONCE_MISMATCH` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-004` | `ethereum` | `0x48d17cfd...` | `ZERO_VICTIM_BALANCE` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |

---

## Quantitative Evaluation Summary

| Metric | Real-World Empirical Value | Meaning |
|---|---|---|
| **Evaluated Real Artifact Contracts** | **58 (53 unique addresses, 47 unique bytecodes)** | Empirically derived from USENIX Security '26 |
| **Aegis Modeled Coverage** | **57 / 58 (98.3%)** | Percentage of real delegates within supported action semantics |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | Concrete multi-step loss paths proven on EVM state |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **6 / 58 (10.3%)** | Real contract executed without loss under bounded model |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | Honest identification of out-of-scope contract semantics |
| **Immediate-Delta Baseline Miss Rate** | **51 / 51 (100%)** | Missed all 51 executable-loss cases because signing produces zero immediate balance delta |
| **Clean-State Witness Replay Success** | **51 / 51 (100%)** | 100% of discovered counterexamples caused real loss on fresh snapshot replay |
| **Post-Recovery Exploit Neutralization** | **51 / 51 (100%)** | 51/51 replayed witnesses produced zero tracked loss after recovery; replay may revert or execute as a harmless no-op. |
| **Controlled Negative Sanity Checks** | **4 / 4** | 4/4 produced no loss witness across protocol-negative controls |

### Key Scientific Finding
$$\boxed{\text{ImmediateDelta}(c, s_0) = \$0.00 \;\;\not\Rightarrow\;\; \text{SafeFutureCapability}(c, s_0)}$$

Under immediate single-step delta evaluation, **the baseline produced zero loss for all 51 executable-loss cases (\$0.00 loss at Step 0)**. Aegis7702 discovered the multi-step attacker action path, confirmed the loss via clean-state EVM replay, and synthesized protocol-level recovery transactions that neutralized 100% of the replayed attacks.
