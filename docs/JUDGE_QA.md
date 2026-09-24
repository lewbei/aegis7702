# Aegis7702: Judge Q&A & Technical Defense Guide

This document contains precise, technically defensible answers to the five most critical questions or adversarial critiques judges may ask during evaluation.

---

### Q1: What is actually novel here? Isn't this just a depth-first search (DFS)?

> **Short Answer:** The novelty is **not** the search algorithm; it is the **formal capability-reachability paradigm, the typed action-space generator for detached authorizations, and the closed-loop recovery synthesis**.

#### Detailed Defense:
- Traditional security tools evaluate transactions under the assumption that signing and execution are concurrent, evaluating $\Delta \text{Balance}(s_0)$.
- In EIP-7702 and Permit2, authorizations are **detached capabilities**: the user signs off-chain, causing zero immediate balance delta, but creates future attacker-controlled state transitions.
- Aegis7702's novelty lies in:
  1. **Typed Capability Extraction:** Translating raw cryptographic signatures into structured capabilities with legal action semantics ($\mathcal{A}_{\text{modeled}}$).
  2. **Executable Counterexample Generation:** Rather than emitting a heuristic "risk score" (e.g. 85/100) or static pattern match, Aegis7702 discovers and returns the concrete multi-step transaction trace that proves loss on an EVM state fork.
  3. **State-Specific Recovery Synthesis:** Dynamically generating the exact protocol-level counter-transaction (nonce advance, delegation clearance, or bitmap flip) that permanently neutralizes the capability on-chain.

---

### Q2: Why is search depth bounded at $k \le 3$? Isn't $k \le 3$ too shallow?

> **Short Answer:** Depth $k \le 3$ is an **explicit bounded verification contract** designed to capture canonical multi-step exploit sequences while keeping EVM state branching linear and fast. Aegis7702 explicitly does not claim unbounded global safety.

#### Detailed Defense:
- A canonical authorization exploit consists of:
  - **Step 1:** Relaying the capability (Type-4 envelope or `permit()`).
  - **Step 2:** Executing the unauthorized action (calling `sweep()` or `transferFrom()`).
  - **Step 3:** Optional post-exploit action (unwinding an approval or secondary transfer).
- Bounding $k \le 3$ is sufficient to capture 100% of canonical delayed-drain exploit sequences while preventing the combinatorial state explosion of arbitrary EVM call spaces ($2^{256}$ calldata combinations).
- We maintain mathematical honesty through our **asymmetric verification contract**:
  $$\boxed{\text{Found loss path } \pi \implies \text{concrete vulnerability witness under fork state } s_0}$$
  $$\boxed{\text{No path found} \not\implies \text{globally safe (proves } \neg \text{Unsafe}_{\le 3}^{\mathcal{A}_{\text{modeled}}} \text{ only)}}$$
- When a path is found, it is indisputable proof; when no path is found, we do not claim global safety against deeper ($k > 3$) or unmodeled actions.

---

### Q3: Are these real-world attacks, or did you make up the scenarios?

> **Short Answer:** The delegate bytecodes are **original, real-world runtime bytecodes extracted directly from the published USENIX Security 2026 artifact**, evaluated in a standardized Prague-EVM reconstruction.

#### Detailed Defense:
- We do not claim to perform "historical mainnet replays," because many of these malicious contracts were detected across six different L1/L2 chains (Ethereum, Base, BNB, Optimism, Arbitrum, Polygon) with diverse historical block states.
- Instead, we took the complete intersection ($C = 58$ chain-address cases / 53 unique contracts) of confirmed EOA-targeted attacks and sensitive drain functions from the artifact of Huang et al. (USENIX Security 2026).
- We loaded each contract's **exact artifact bytecode** via `anvil_setCode` into an ephemeral Prague-EVM snapshot with a victim account and measured whether the delegate could execute an unauthorized drain under valid EIP-7702 authorization.
- The 58 bytecode hashes match the artifact files exactly and are fully checked into the repository (`testdata/usenix_bytecodes/`) and reproduced in GitHub Actions CI.

---

### Q4: Why is the detection rate 87.9% (51/58) rather than 100%?

> **Short Answer:** The 87.9% rate is **proof of empirical rigor**. Aegis7702 honestly reports contracts that require unmodeled external state or unsupported interfaces rather than forcing a false verdict.

#### Detailed Defense:
- A benchmark that claims 100% on arbitrary real-world contracts is almost always hard-coded or tautological.
- Aegis7702 enforces a strict three-state classification:
  - **`FOUND_LOSS` (51 / 58 = 87.9%):** Discovered an executable multi-step exploit path that successfully drained tracked funds.
  - **`NO_MODELED_LOSS` (6 / 58 = 10.3%):** Explored within bounded depth without finding loss. These contracts (such as certain `sweepTokens(address,uint256)` variants) require specific caller authorizations, non-zero internal contract states, or specific token balances beyond the victim's account. Because those preconditions were not satisfied, the execution safely reverted, and Aegis honestly reported no loss.
  - **`UNMODELED` (1 / 58 = 1.7%):** One delegate (`0x628ff693... sweepToken(address)`) exhibited an interface archetype outside current capability generator semantics, which Aegis correctly and transparently identified as unmodeled.
- For all 51 discovered witnesses, **clean-state replay succeeded 100% (51/51)**, and **post-recovery neutralization was 100% (51/51)**.

---

### Q5: Why not just use existing wallet security tools like MetaMask or Blockaid?

> **Short Answer:** We do not claim existing tools are broken across the board; our experimental comparator is specifically the **immediate-delta / current-execution baseline ($B_0$)**. Aegis7702 addresses a structural blindspot that single-step simulation cannot solve.

#### Detailed Defense:
- Existing wallet firewalls and transaction simulation tools (including Blockaid, Tenderly, and standard wallet RPCs) evaluate transactions by simulating what happens **at the moment of signing**:
  $$\text{Safe}(s_0, \text{tx}) \iff \Delta \text{Balance}(s_0) \ge -\epsilon$$
- Because an off-chain authorization signature (EIP-7702 authorization tuple or detached Permit2 payload) changes **zero balances on-chain at Step 0**, any immediate-delta evaluation evaluates $\Delta = \$0.00$ and reports SAFE.
- In our empirical evaluation of the 51 confirmed vulnerable USENIX delegates, the immediate-delta baseline had a **100% false-negative rate (51/51)**, because signing moves no tokens.
- Aegis7702 does not replace wallet security; it complements it by providing **forward-looking capability reachability search** for detached authorization primitives that cannot be evaluated with single-step simulation.
