# Aegis7702 (Guard7702): Bounded Capability-Reachability Verifier & Recovery Engine

**Project Name:** Aegis7702  
**Tagline / Elevator Pitch:** Catches zero-delta deferred drains in EIP-7702 & Permit2 signatures. Aegis7702 verifies multi-step capability reachability on EVM forks and synthesizes verified 1-click on-chain recovery.

---

## Inspiration

The inspiration for **Aegis7702** originates directly from the tectonic shift occurring in Ethereum's post-Pectra architecture. With the activation of **EIP-7702**, Externally Owned Accounts (EOAs) can now ephemerally delegate their execution logic to arbitrary smart contracts using Type-4 (`0x04`) transaction envelopes and `0xef0100` bytecode pointers. When coupled with the widespread adoption of off-chain signature protocols like Uniswap’s **Permit2** (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`), the Web3 ecosystem has fundamentally decoupled **authorization signing** from **on-chain execution**.

This architectural decoupling broke every mainstream transaction security model. Traditional wallet firewalls and transaction scanners evaluate safety using an immediate, single-step execution heuristic:
$$\text{Safe}(s_0, \text{tx}) \iff \Delta \text{Balance}(s_0) \ge -\epsilon$$

When an attacker tricks a victim into signing an off-chain EIP-7702 authorization tuple:
$$c = (\text{chainId}, \text{address}, \text{nonce}, y, r, s)$$
or a detached Permit2 signature, **zero state changes occur on-chain at Step 0**. Simulators evaluate $\Delta \text{Balance}(s_0) = \$0.00$ and emit a green, reassuring **SAFE** verdict. Hours or days later, the attacker broadcasts the authorization, installs drain bytecode on the victim's EOA, and sweeps the account clean. This is a catastrophic **false negative**.

This crisis is already empirically documented. Research presented at **USENIX Security 2026** (Huang et al.) reveals that across a seven-chain dataset, **over 63% of observed EIP-7702 authorization transactions were associated with malicious EOA-targeted attacks**, identifying 924 malicious contract accounts, **over $2.3M in realized stolen funds**, and **>$10M in exposed assets**.

We built Aegis7702 around a single foundational mathematical thesis:
$$\boxed{\text{SimulateCurrentExecution}(c, s_0) \not\Rightarrow \text{SafeFutureCapability}(c, s_0)}$$

Conventional simulation only reveals what a proposed execution does under a particular current state $s_0$. Detached capabilities demand a completely different question: **What future attacker-controlled state transitions become reachable once this signed capability is released into the wild?**

---

## What it does

**Aegis7702** is a typed, bounded **Capability-Reachability Verifier (CRV)** and **State-Specific Recovery Synthesizer** for EIP-7702 authorizations and Uniswap Permit2 signatures.

Instead of outputting ambiguous, probabilistic "AI risk scores", Aegis7702 executes a closed-loop deterministic verification protocol against live EVM state snapshots:

1. **Typed Capability Extraction:** Decodes signed authorization payloads into structured capabilities $c \in \mathcal{C}$ across three supported domains:
   - EIP-7702 Ephemeral Delegation Tuples
   - Uniswap Permit2 `AllowanceTransfer` (`PermitSingle` / `PermitBatch`)
   - Uniswap Permit2 `SignatureTransfer` (Unordered Nonce Bitmaps)
2. **Bounded Reachability Search ($k \le 3$):** Generates candidate attacker action sequences within modeled semantics $\mathcal{A}_{\text{modeled}}$ and explores downstream EVM state branches:
   $$\text{Unsafe}_{\le k}^{\mathcal A_{\text{modeled}}}(c, s_0) \iff \exists \pi = (a_1, \ldots, a_j), \, j \le k \quad \text{such that} \quad L(s_0, T_\pi(s_0)) > 0$$
   where the loss function evaluates tracked asset deltas:
   $$L(s_0, s') = \sum_{t \in \text{Tracked}} \max(0, \text{Balance}_{t, \text{victim}}(s_0) - \text{Balance}_{t, \text{victim}}(s'))$$
3. **Executable Counterexample Witness:** When a loss path is discovered, Aegis7702 does not just alert the user; it returns the exact, reproducible multi-step exploit trace $\pi$ (e.g., `RelayAuthorization` $\to$ `MaliciousDelegate.sweep`).
4. **State-Specific On-Chain Recovery Synthesis:** Inspects live chain state and automatically synthesizes the protocol-correct counter-transaction:
   - *Unconsumed EIP-7702 Authorization:* Constructs a 0-value self-transaction to increment the victim's account nonce from $n \to n+1$. Because EIP-7702 strictly checks `authority.nonce == auth.nonce`, the stolen authorization is rendered unusable via protocol-level nonce mismatch.
   - *Active EIP-7702 Delegation:* Constructs an EIP-7702 Type-4 transaction with authorization pointing to `address(0)` to wipe the `0xef0100...` delegation indicator back to a clean EOA.
   - *Permit2 Allowance:* Calls canonical `Permit2.invalidateNonces()` to bump nonces before broadcast, or `Permit2.lockdown()` to zero active allowances.
   - *Permit2 Signature:* Calls `Permit2.invalidateUnorderedNonces(wordPos, mask)` to flip the bitmap word position, neutralizing the signature.
5. **Deterministic On-Fork Replay Verification:** Replays the identical attacker exploit trace $\pi$ against the post-recovery fork state $s_R$ and proves on-chain that the exploit reverts:
   $$\boxed{L(s_0, T_\pi(s_0)) > 0 \quad \land \quad \text{Replay}(\pi, s_R) \text{ reverts}}$$
   Tracked asset balances remain completely unchanged under the replayed trace.

---

## How we built it

We implemented a unified, robust, and reproducible three-tier architecture:

```
.
├── contracts/                  # Solidity smart contracts & Foundry security suites
│   ├── src/                    # Guard7702Sentinel, MaliciousDelegate, MockUSDC
│   ├── test/                   # Permit2Allowance, Permit2Signature, EIP7702Attack, Guard7702Sentinel
│   └── foundry.toml            # Solc 0.8.17, via_ir = true, Prague EVM settings
│
├── engine/                     # TypeScript Capability-Reachability Engine
│   └── src/                    # Bounded DFS explorer (k ≤ 3), state-specific recovery synthesizer
│
└── app/                        # Interactive Visualizer Dashboard (React 18 + Vite 8)
    └── src/                    # Immediate-delta baseline contrast, graph view, 1-click on-fork recovery
```

* **Solidity Smart Contracts & Foundry Suite:**
  - Implemented `Guard7702Sentinel.sol` to enable batch Permit2 nonce invalidations within delegated EOA execution contexts.
  - Built `MaliciousDelegate.sol` and `MockUSDC.sol` as precise EVM fixtures for Prague code delegation attacks.
  - Authored 4 comprehensive Foundry test suites comprising **13 tests with 100% pass rate** executing in 8ms:
    - `Permit2AllowanceTest`: 4/4 passed (baseline zero-delta, multi-step drain discovery, nonce invalidation, lockdown).
    - `Permit2SignatureTest`: 3/3 passed (baseline zero-delta, signature drain, unordered nonce invalidation).
    - `EIP7702AttackTest`: 4/4 passed (baseline zero-delta, Type-4 drain, nonce advance recovery, `address(0)` clearance).
    - `Guard7702SentinelTest`: 2/2 passed (delegated batch invalidations).
* **TypeScript Reachability Engine:**
  - Built on Viem and ephemeral Anvil child processes with `--hardfork prague`.
  - Implemented depth-first reachability exploration bounded at $k \le 3$, utilizing lightweight EVM snapshots (`evm_snapshot` / `evm_revert`) to keep branch exploration under 2 seconds.
  - Authored 3 automated, self-contained **Kill Tests** (`killTest.ts`, `killTestSignature.ts`, `killTest7702.ts`) that execute completely offline with zero external RPC dependencies.
* **Interactive Proof Visualizer Dashboard:**
  - Built with React 18, Vite 8, Lucide, and Tailwind CSS.
  - Displays the immediate-delta baseline verdict (`SAFE ✅, Δ = $0.00`) side-by-side with Aegis7702 reachability graph analysis (`CRITICAL EXPLOIT DETECTED 🔴`), interactive trace exploration, and 1-click on-fork recovery execution.

---

## Challenges we ran into

1. **Combinatorial EVM State-Space Explosion:**
   Arbitrary EVM execution has an infinite branching factor ($2^{256}$ possible calldata permutations). Attempting generic state fuzzing in real-time is impossible. We solved this by formulating **typed capability semantics**: rather than brute-forcing arbitrary calls, the engine decodes the exact parameters of the capability (token addresses, spenders, nonces, delegation pointers) and instantiates only legal candidate actions ($\mathcal{A}_{\text{modeled}}$), bounding depth to $k \le 3$ (sufficient to cover *Relay $\to$ Drain $\to$ Unwind*).
2. **Bleeding-Edge Prague Hardfork Tooling:**
   EIP-7702 is newly deployed. Most developer tools, JSON-RPC endpoints, and wallet libraries do not yet have stable native abstractions for Type-4 transaction envelopes and `0xef0100` delegation bytecode. We had to build custom low-level RLP serializers, orchestrate Prague-configured Anvil instances, and write Foundry cheatcode harnesses (`vm.attachDelegation`) to model live delegation mechanics.
3. **Permit2 Caller Identity Constraints:**
   Canonical Permit2 security functions (`invalidateNonces`, `invalidateUnorderedNonces`, and `lockdown`) strictly operate on `msg.sender`. A third-party security contract cannot call them on a victim's behalf. We solved this by structuring recovery transactions to execute directly from the victim EOA or via an EIP-7702 delegated context where `msg.sender == victim`.
4. **Formulating Asymmetric Mathematical Claims:**
   We strictly refused to make indefensible claims of "global safety." Because reachability search is bounded ($k \le 3$), we formalized the critical verification asymmetry:
   $$\boxed{\text{Found loss path} \implies \text{concrete vulnerability witness}}$$
   $$\boxed{\text{No path found} \not\implies \text{globally safe}}$$
   A security verifier cannot prove an authorization is globally safe against unmodeled, 10-hop DeFi composability; but when a path is found, it provides a 100% concrete, reproducible witness.

---

## Accomplishments that we're proud of

1. **Closed-Loop Verification & Recovery:**
   We did not just build a detector that alerts users. We built a closed-loop system: **Capability Extraction $\to$ Reachability Exploration $\to$ Concrete Exploit Witness $\to$ Recovery Synthesis $\to$ Replay Verification Reversion**.
2. **100% Offline Reproducibility with Zero Flakiness:**
   All 13 Foundry contract tests and all 3 TypeScript Anvil kill tests run completely offline without external RPC rate-limits, third-party API keys, or flaky network calls. The entire test suite completes in seconds.
3. **Formal Mathematical Grounding:**
   Directly addressing the USENIX Security 2026 empirical dataset and grounding the authorization architecture in the **Key Sovereignty** framework of Matthias Hauser (arXiv:2605.01210).
4. **Production-Ready Dashboard UI:**
   A high-fidelity, interactive dashboard built in Vite with zero TypeScript compilation errors, allowing technical judges and end users to visually contrast single-step simulation against downstream reachability and trigger 1-click on-fork mitigations.

---

## What we learned

* **Key Sovereignty Axiom:** As proven by Matthias Hauser (arXiv:2605.01210), in account-based ledgers the private key maintains ultimate write sovereignty. Ephemeral code delegation introduces dynamic action spaces that cannot be audited in isolation from the private key that authorized them.
* **Mempool Frontrunning & Transaction Ordering:** A recovery transaction that is mathematically valid on paper can still be frontrun by an adversarial bot if broadcast to the public mempool with standard gas pricing. To ensure real-world protection, recovery transactions must be routed via private relays (Flashbots Protect, MEV-Share) to bypass the public mempool.
* **Deterministic Witnesses vs. Probabilistic Heuristics:** Users and security teams suffer from alert fatigue caused by opaque heuristic scores. Demonstrating a **concrete, executable multi-step counterexample on an EVM state snapshot** provides indisputable proof that bridges the gap between static analysis and live defense.

---

## What's next for Aegis7702

1. **MetaMask Snap & Browser Extension Integration:**
   Package the Aegis7702 reachability engine into a lightweight MetaMask Snap and browser extension to intercept `eth_signTypedData_v4` and EIP-7702 authorization requests in real-time before the user ever signs them.
2. **Expanding Action-Space Semantics ($\mathcal{A}_{\text{modeled}}$):**
   Expand the candidate transition generator to model broader DeFi composability vectors, including Uniswap v3/v4 liquidity pools, Aave and Morpho collateral borrow/liquidate loops, and cross-chain bridge deposit contracts.
3. **Direct Private Bundler Relay Integration:**
   Integrate direct JSON-RPC bundling to Flashbots Protect and private builders, enabling the dashboard's "1-Click Recovery" button to automatically dispatch prioritized MEV bundles that eliminate mempool frontrunning risk.
4. **Symbolic EVM Execution & SMT Integration:**
   Explore integrating symbolic EVM execution engines (such as Halmos or Certora Prover) to prove capability safety beyond bounded depth $k \le 3$, moving towards formal unbounded verification of smart account capabilities.
