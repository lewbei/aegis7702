# Aegis7702-USENIX-Eval: Executable Real-World Benchmark Results

**Reference Corpus:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.

## Inclusion Methodology & Protocol
- **Dataset Source:** Official artifact from USENIX Security '26 containing 793 EOA detection records (718 unique contract addresses) across 7 production blockchains.
- **Inclusion Criterion:** $C = \text{EOA final detections} \cap \text{sensitive-function detections}$, yielding 58 chain-address cases (53 unique addresses).
- **Stratified Evaluation Set:** 16 real-world delegate contracts stratified across 4 threat families and 5 production chains (Optimism, Arbitrum, BNB Chain, Base, Ethereum), evaluated alongside 4 controlled protocol-negative cases.
- **Execution Pipeline:** Real bytecode deployed via `anvil_setCode` into ephemeral local Anvil Prague EVM state snapshots, evaluated under three deterministic states:
  - `FOUND_LOSS`: Reachability explorer discovers an executable multi-step exploit path causing $L(s_0, s') > 0$.
  - `NO_MODELED_LOSS`: Reachability explorer exhaustively searches supported candidate actions within bounded depth without finding asset loss.
  - `UNMODELED`: Delegate contract interface or calldata structure is outside current modeled capability semantics.
- **Independent Witness Replay:** Every discovered counterexample witness $\pi$ is independently replayed on clean EVM state to verify real loss before synthesizing recovery.

---

## Detailed Execution Matrix

| Benchmark ID | Chain | Delegate Address | Function Archetype | Immediate-Delta Baseline | Aegis7702 Verifier | Reachable Loss | Witness Replay Valid? | Replay Blocked by Recovery? |
|---|---|---|---|---|---|---|---|---|
| `USENIX-EOA-001` | `optimism` | `0x2f1211e3...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-002` | `bnb` | `0x29ada5cb...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-003` | `base` | `0xd1d4b213...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-004` | `ethereum` | `0x544bb1d8...` | `sweep(address[])` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-005` | `optimism` | `0xbe7ae1e5...` | `sweepTokens(address,uint256)` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `USENIX-EOA-006` | `optimism` | `0x7f7f0dcb...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-007` | `arbitrum` | `0x93c1bfc9...` | `sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-008` | `base` | `0xfc1e0178...` | `sweepERC20(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-009` | `arbitrum` | `0x48d17cfd...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-010` | `bnb` | `0x45cf19a8...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-011` | `base` | `0xcc7c302c...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-012` | `ethereum` | `0x2ae985de...` | `drainToken(address,uint256)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-013` | `arbitrum` | `0xbbc9e641...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-014` | `base` | `0xecdc0b36...` | `sweepETH() / sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-015` | `base` | `0xfc4a4381...` | `sweepETH() / sweepTokens(address)` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `USENIX-EOA-016` | `ethereum` | `0x89318ee0...` | `sweep(address[]) / sweepEth()` | `SAFE` | **`FOUND_LOSS`** | 10000 USDC | ✅ YES | ✅ YES |
| `CTRL-NEG-001` | `ethereum` | `0x00000000...` | `BENIGN_GUARD_REVERTS` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-002` | `ethereum` | `0x00000000...` | `CLEAN_EOA_NO_DELEGATION` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-003` | `ethereum` | `0x2f1211e3...` | `EXPIRED_NONCE_MISMATCH` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |
| `CTRL-NEG-004` | `ethereum` | `0x48d17cfd...` | `ZERO_VICTIM_BALANCE` | `SAFE` | **`NO_MODELED_LOSS`** | 0.00 USDC | - | - |

---

## Quantitative Evaluation Summary

| Metric | Real-World Empirical Value | Meaning |
|---|---|---|
| **Evaluated Real Artifact Contracts** | **16** | Empirically derived from USENIX Security '26 |
| **Aegis Modeled Coverage** | **16 / 16 (100.0%)** | Percentage of real delegates within supported action semantics |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **15 / 16 (93.8%)** | Concrete multi-step loss paths proven on EVM state |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **0 / 16** | Honest identification of out-of-scope contract semantics |
| **Immediate-Delta Baseline False Negatives** | **15 / 15 (100%)** | Conventional simulators reported SAFE for all 15 vulnerable contracts |
| **Independent Witness Replay Success** | **15 / 15 (100%)** | 100% of discovered counterexamples caused real loss on fresh replay |
| **Post-Recovery Exploit Neutralization** | **15 / 15 (100%)** | 100% of verified exploits reverted on-chain after synthesized recovery |
| **Controlled Protocol-Negative Specificity** | **4 / 4 (100%)** | Zero false positive alarms on safe/guarded EOAs |

### Key Scientific Finding
$$\boxed{\text{SimulateCurrentExecution}(c, s_0) = \$0.00 \;\;\not\Rightarrow\;\; \text{SafeFutureCapability}(c, s_0)}$$

Under immediate single-step simulation, **100% of the 15 vulnerable real-world contracts evaluated as SAFE (\$0.00 loss at Step 0)**. Aegis7702 discovered the multi-step attacker action path, confirmed the loss via independent EVM replay, and synthesized protocol-level recovery transactions that neutralized 100% of the replayed attacks.
