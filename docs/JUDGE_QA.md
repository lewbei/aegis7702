# Aegis7702: Judge Q&A & Technical Defense Guide

This document contains precise, technically defensible answers to the seven most critical questions or adversarial critiques judges may ask during evaluation.

---

### Q1: What is actually novel here? Isn't this just a depth-first search (DFS)?

> **Short Answer:** The novelty is **not** the search algorithm; it is the **formal capability-reachability paradigm, the typed action-space generator for detached authorizations, and the closed-loop recovery synthesis**.

#### Detailed Defense:
- Traditional security tools evaluate transactions under the assumption that signing and execution are concurrent, evaluating $\Delta \text{Balance}(s_0)$.
- In EIP-7702 and Permit2, authorizations are **detached capabilities**: the user signs off-chain, causing zero immediate balance delta, but creates future attacker-controlled state transitions.
- Aegis7702's novelty lies in:
  1. **Typed Capability Extraction:** Translating raw cryptographic signatures into structured capabilities with legal action semantics ($\mathcal{A}_{\text{modeled}}$).
  2. **Executable Counterexample Generation:** Rather than emitting a heuristic "risk score" (e.g. 85/100) or static pattern match, Aegis7702 discovers and returns the concrete multi-step transaction trace that proves loss on an ephemeral Prague EVM state.
  3. **State-Specific Recovery Synthesis:** Dynamically generating the exact protocol-level counter-transaction (nonce advance, delegation clearance, or bitmap flip) that permanently neutralizes the capability on-chain.

---

### Q2: Why is search depth bounded at $k \le 3$? Isn't $k \le 3$ too shallow?

> **Short Answer:** Depth $k \le 3$ is an **explicit bounded verification contract** designed to capture canonical multi-step exploit sequences while keeping EVM state branching linear and fast. Aegis7702 explicitly does not claim unbounded global safety.

#### Detailed Defense:
- A canonical authorization exploit consists of:
  - **Step 1:** Relaying the capability (Type-4 envelope or `permit()`).
  - **Step 2:** Executing the unauthorized action (calling `sweep()` or `transferFrom()`).
  - **Step 3:** Optional post-exploit action (unwinding an approval or secondary transfer).
- Bounding $k \le 3$ is designed to capture the Relay $\to$ Drain $\to$ optional Unwind patterns exercised by our supported semantics and benchmark; we do not claim completeness for all delayed-drain sequences. It keeps branch exploration lightweight while avoiding the combinatorial state explosion of arbitrary EVM call spaces ($2^{256}$ calldata combinations).
- We maintain mathematical honesty through our **asymmetric verification contract**:
  $$\boxed{\text{Found loss path } \pi \implies \text{concrete vulnerability witness under reconstructed state } s_0}$$
  $$\boxed{\text{No path found} \not\implies \text{globally safe (proves } \neg \text{Unsafe}_{\le 3}^{\mathcal{A}_{\text{modeled}}} \text{ only)}}$$
- When a path is found, it is indisputable proof; when no path is found, we do not claim global safety against deeper ($k > 3$) or unmodeled actions.

---

### Q3: Are these real-world attacks, or did you make up the scenarios?

> **Short Answer:** The delegate bytecodes are **original, real-world runtime bytecodes extracted directly from the published USENIX Security 2026 artifact**, evaluated in a standardized Prague-EVM reconstruction.

#### Detailed Defense:
- We do not claim to perform "historical mainnet replays," because many of these malicious contracts were detected across six different L1/L2 chains (Ethereum, Base, BNB, Optimism, Arbitrum, Polygon) with diverse historical block states.
- Instead, we took the complete intersection ($C = 58$ chain-address cases / 53 unique delegate addresses / 47 unique runtime bytecodes) of EOA final-detection records intersected with sensitive-function detections from the published artifact of Huang et al. (USENIX Security 2026).
- We loaded each contract's **exact artifact bytecode** via `anvil_setCode` into an ephemeral Prague-EVM snapshot with a victim account and measured whether the delegate could execute an unauthorized drain under valid EIP-7702 authorization.
- The 58 bytecode hashes match the artifact files exactly and are fully checked into the repository (`testdata/usenix_bytecodes/`) and reproduced in GitHub Actions CI.

---

### Q4: Why is executable witness yield 87.9% (51/58) rather than 100%?

> **Short Answer:** The 87.9% yield reflects actual EVM execution outcomes under the standardized reconstruction. Aegis7702 honestly reports contracts that require unmodeled external state or unsupported interfaces rather than forcing a false verdict.

#### Detailed Defense:
- The 87.9% yield reflects actual EVM execution under the standardized reconstruction: six modeled cases did not reach tracked loss and one interface was unsupported.
- Aegis7702 enforces a strict three-state classification:
  - **`FOUND_LOSS` (51 / 58 = 87.9%):** Discovered an executable multi-step exploit path that successfully drained tracked funds.
  - **`NO_MODELED_LOSS` (6 / 58 = 10.3%):** Explored within bounded depth without finding loss. These contracts (such as certain `sweepTokens(address,uint256)` variants) require specific caller authorizations, non-zero internal contract states, or specific token balances beyond the victim's account. Because those preconditions were not satisfied, the execution safely reverted, and Aegis honestly reported no loss.
  - **`UNMODELED` (1 / 58 = 1.7%):** One delegate (`0x628ff693... sweepToken(address)`) exhibited an interface archetype outside current capability generator semantics, which Aegis correctly and transparently identified as unmodeled.
- For all 51 discovered witnesses, **clean-state replay succeeded 100% (51/51)**, and **post-recovery neutralization was 100% (51/51)**.

---

### Q5: Why not just use existing wallet security tools like MetaMask or Blockaid?

> **Short Answer:** We do not claim existing tools are broken across the board; our experimental comparator is specifically the **immediate-delta / current-execution baseline ($B_0$)**. Aegis7702 addresses a structural blindspot that single-step simulation cannot solve.

#### Detailed Defense:
- We did not benchmark MetaMask, Blockaid, or Tenderly directly. Our measured comparator is $B_0$, an immediate-delta / current-execution baseline evaluating:
  $$\text{Safe}(s_0, \text{tx}) \iff \Delta \text{Balance}(s_0) \ge -\epsilon$$
- Because an off-chain authorization signature (EIP-7702 authorization tuple or detached Permit2 payload) changes **zero balances on-chain at Step 0**, an immediate-delta evaluation evaluates $\Delta = \$0.00$ and reports SAFE.
- In our empirical evaluation of the 51 executable-loss cases in our standardized benchmark, $B_0$ produced zero immediate loss for all 51 executable-loss cases, because signing itself moves no tokens on-chain.
- Aegis7702's differentiator is **executable capability reachability**: exploring downstream reachable attacker transitions rather than stopping at current execution state.

---

### Q6: How does Aegis generalize to out-of-distribution or arbitrary bytecode outside the 58 cases?

> **Short Answer:** Aegis verifies **explicitly modeled capability semantics**; it does not infer new action semantics from arbitrary bytecode. On the 735 holdout contracts from the USENIX EOA corpus, it cleanly abstains (`UNMODELED`).

#### Detailed Defense:
- **Scope of the In-Distribution Benchmark:** The 58-case benchmark evaluates contracts where delegate bytecode exposes modeled capability action semantics (e.g., canonical `sweep` and `drain` interfaces).
- **Out-of-Distribution Semantic-Coverage Test:** When evaluated against the remaining 735 chain-address cases (520 unique runtime-bytecode hashes) in the USENIX EOA final-detection corpus outside $C$ with `hackathon-final-v1.0.0` frozen:
  - **OOD Semantic Coverage:** $0 / 735$ ($0.00\%$)
  - **Abstention Rate (`UNMODELED`):** $735 / 735$ ($100.0\%$)
- **Important Distinction:** `UNMODELED` is an explicit **abstention**, not a claim of safety or a true negative ($\text{UNMODELED} \neq \text{TRUE NEGATIVE}$). The system recognizes that it lacks the action semantics to model the contract's dispatcher (which includes obfuscated drainers like `loserSweepETH_...`, generic call forwarders like `executeCall(address,bytes)`, and multi-sigs like Safe).
- **Defensible Boundary:** Aegis is strong at verifying known capability semantics on live EVM state reconstructions, and currently has zero zero-shot semantic coverage on the USENIX holdout. Generalizing across arbitrary bytecodes requires an automated decompiler layer (e.g. Gigahorse) to synthesize action templates from raw dispatchers, which is our documented post-hackathon roadmap.

---

### Q7: Why do you need tree search with EVM snapshot rollback? Why isn't a state-aware forward simulator ($B_1$) enough?

> **Short Answer:** A greedy forward simulator ($B_1$) is indeed sufficient on monotonic, single-path sweep contracts (where it is faster with zero snapshot overhead). EVM tree search with snapshot rollback provides **robustness against branch-order ambiguity and reverting decoys**, and bounded post-recovery re-search on state $s_R$ addresses **residual multi-capability risk that single-trace replay cannot detect**.

#### Detailed Defense:
- **Where $B_1$ Suffices (Empirical Concession on Benchmark A):**
  - In Benchmark A (58 real-world USENIX Security '26 cases), on all 51 vulnerable contracts, $B_1$ and Aegis CRV achieve **identical detection (51/51 `FOUND_LOSS`)**, each taking exactly 2 EVM calls.
  - Because these real-world contracts feature monotonic, single-path sweep routines, $B_1$ incurs zero snapshot overhead (0 snapshots vs 2 snapshots) and executes faster on local Anvil (63 ms vs 79 ms median latency). We do **not** claim tree search is superior on simple linear topologies.
- **Where Tree Search & Backtracking Provide Structural Robustness:**
  - **Handling Reverting Calls:** In Benchmark A's 6 non-vulnerable cases, contracts revert due to unsatisfied preconditions. Linear $B_1$ halts with `REVERT_ERROR` because it cannot backtrack. Aegis CRV catches the revert, rolls back EVM state via `evm_revert`, and safely certifies `NO_MODELED_LOSS`.
  - **Surviving Branch-Order Decoys (Benchmark B / Fixture 3):** A greedy forward policy is branch-order sensitive. When an adversarial contract presents multiple entrypoints where reverting decoys precede the drain (e.g. `decoyRevert -> decoyPing -> evacuateAsset`), $B_1$ halts on the first reverting call with `REVERT_ERROR`. Aegis CRV uses EVM snapshots (`evm_snapshot` / `evm_revert`) to recover from reverting branches and continue exploration, locating the asset drain (**True Positive**).
- **Why Single-Trace Replay Differs from State Re-Verification (Benchmark B / Fixture 4):**
  - A single-trace verifier evaluates whether the historical exploit trace $\pi^*$ is neutralized (`TRACE_BLOCKED`), making no claim about overall account safety.
  - In accounts exposed to multiple capabilities (e.g. delegated EIP-7702 + unrevoked Permit2 allowance), replaying the EIP-7702 trace after delegation clearance reverts (`TRACE_BLOCKED`). This correctly proves the specific exploit was mitigated, but leaves residual attack surfaces unverified.
  - Re-searching known candidate capabilities on state $s_R$ uncovers the unrevoked Permit2 drain and flags incomplete recovery:
    $$\boxed{\text{Trace-Specific Mitigation Verification} \neq \text{Post-Recovery State Re-Verification}}$$



