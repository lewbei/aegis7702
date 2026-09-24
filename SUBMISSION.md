# Aegis7702: Bounded Capability-Reachability Verifier & Recovery Engine

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

1. **Typed Capability Extraction & Decoding:** Ingests raw wallet signing payloads via dedicated Capability Decoders (`decodePermit2Allowance`, `decodePermit2Signature`, `decode7702`) into structured capabilities $c \in \mathcal{C}$ across three supported domains:
   - EIP-7702 Ephemeral Delegation Tuples
   - Uniswap Permit2 `AllowanceTransfer` (`PermitSingle` / `PermitBatch`)
   - Uniswap Permit2 `SignatureTransfer` (Unordered Nonce Bitmaps)
2. **Bounded Reachability Search ($k \le 3$):** Generates candidate attacker action sequences within modeled semantics $\mathcal{A}_{\text{modeled}}$ and explores downstream EVM state branches:
   $$\text{Unsafe}_{\le k}^{\mathcal A_{\text{modeled}}}(c, s_0) \iff \exists \pi = (a_1, \ldots, a_j), \, j \le k \quad \text{such that} \quad L(s_0, T_\pi(s_0)) > 0$$
   where the loss function evaluates tracked asset deltas:
   $$L(s_0, s') = \sum_{t \in \text{Tracked}} \max(0, \text{Balance}_{t, \text{victim}}(s_0) - \text{Balance}_{t, \text{victim}}(s'))$$
   *(In our MVP, this measures the primary capability-associated ERC-20 token, with multi-asset ETH/ERC-20 aggregate blast radius tracking in our roadmap).*
3. **Executable Counterexample Witness:** When a loss path is discovered, Aegis7702 does not just alert the user; it returns the exact, reproducible multi-step exploit trace $\pi$ (e.g., `RelayAuthorization` $\to$ `MaliciousDelegate.sweep`).
4. **State-Specific On-Chain Recovery Synthesis:** Inspects live chain state and automatically synthesizes the protocol-correct counter-transaction:
   - *Unconsumed EIP-7702 Authorization:* Constructs a 0-value self-transaction to increment the victim's account nonce from $n \to n+1$ (or multiple self-transactions if a future nonce was signed). Because EIP-7702 strictly checks `authority.nonce == auth.nonce`, the stolen authorization is rendered unusable via protocol-level nonce mismatch.
   - *Active EIP-7702 Delegation:* Constructs an EIP-7702 Type-4 transaction with authorization pointing to `address(0)` to wipe the `0xef0100...` delegation indicator back to a clean EOA.
   - *Permit2 Allowance:* Calls canonical `Permit2.invalidateNonces()` to bump nonces past signed nonces before broadcast, or `Permit2.lockdown()` to zero active allowances.
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
│   ├── src/                    # Guard7702Sentinel (with anti-griefing onlySelf), MaliciousDelegate, MockUSDC
│   ├── test/                   # Permit2Allowance, Permit2Signature, EIP7702Attack, Guard7702Sentinel
│   └── foundry.toml            # Solc 0.8.17, via_ir = true, Prague EVM settings
│
├── engine/                     # TypeScript Capability-Reachability Engine & API Server
│   ├── src/capability/         # Dedicated decoders for raw wallet payloads (EIP-712 & EIP-7702)
│   ├── src/search/             # Bounded DFS explorer (k ≤ 3) with EVM snapshots & reverts
│   ├── src/recovery/           # State-specific recovery planners for EIP-7702 and Permit2
│   └── src/server.ts           # HTTP API server bridging engine execution directly to the web dashboard
│
└── app/                        # Interactive Visualizer Dashboard (React 19 + Vite 8)
    └── src/                    # Live Anvil RPC integration, baseline contrast, 1-click on-fork recovery
```

* **Solidity Smart Contracts & Foundry Suite:**
  - Implemented `Guard7702Sentinel.sol` to enable batch Permit2 nonce invalidations within delegated EOA execution contexts, hardened with strict `onlySelf` anti-griefing caller protection.
  - Built `MaliciousDelegate.sol` and `MockUSDC.sol` as precise EVM fixtures for Prague code delegation attacks.
  - Authored 4 comprehensive Foundry test suites comprising **14 tests with 100% pass rate** executing in 13ms:
    - `Permit2AllowanceTest`: 4/4 passed (baseline zero-delta, multi-step drain discovery, nonce invalidation, lockdown).
    - `Permit2SignatureTest`: 3/3 passed (baseline zero-delta, signature drain, unordered nonce invalidation).
    - `EIP7702AttackTest`: 4/4 passed (baseline zero-delta, Type-4 drain, nonce advance recovery, `address(0)` clearance).
    - `Guard7702SentinelTest`: 3/3 passed (delegated batch invalidations, attacker anti-griefing revert verification).
* **TypeScript Reachability Engine:**
  - Built on Viem and ephemeral Anvil child processes with `--hardfork prague` and portable binary configuration (`ANVIL_BIN`).
  - Implemented depth-first reachability exploration bounded at $k \le 3$, utilizing lightweight EVM snapshots (`evm_snapshot` / `evm_revert`) to keep branch exploration under 2 seconds.
  - Authored 3 automated, self-contained **Kill Tests** (`killTest.ts`, `killTestSignature.ts`, `killTest7702.ts`) and **5 Adversarial Recovery Integration Scenarios** (`testIntegration.ts`) that execute completely offline via `npm test` with zero external RPC dependencies.
  - Built a lightweight HTTP backend server (`server.ts`) exposing `/api/analyze`, `/api/recover`, and `/api/replay` for real-time frontend execution on live ephemeral Anvil instances.
* **Interactive Proof Visualizer Dashboard:**
  - Built with React 19, Vite 8, Lucide, and Tailwind CSS.
  - Connects directly to the live Anvil engine server, displaying the immediate-delta baseline verdict (`SAFE ✅, Δ = $0.00`) side-by-side with Aegis7702 reachability graph analysis (`CRITICAL EXPLOIT DETECTED 🔴`), interactive trace exploration, and real on-chain recovery execution with live transaction hashes.
* **Sepolia Testnet Deployment Script:**
  - Authored Foundry script `contracts/script/DeploySentinel.s.sol` to deploy `Guard7702Sentinel` and `MaliciousDelegate` on any public EVM network:
    ```bash
    forge script script/DeploySentinel.s.sol --rpc-url <SEPOLIA_RPC> --broadcast
    ```
* **Official 3-Minute Video Presentation Script:**
  - Complete second-by-second storyboard and voiceover script detailed in [docs/DEMO_VIDEO_SCRIPT.md](./docs/DEMO_VIDEO_SCRIPT.md), centered around the core thesis $\boxed{\$0.00 \text{ Now} \not\Rightarrow \$0.00 \text{ Later}}$.

---

## Empirical Grounding: Aegis7702-USENIX-Eval

To ground Aegis7702 in real-world threat intelligence rather than synthetic toy scenarios, we executed a preregistered empirical evaluation against real smart contract bytecodes derived from **Huang et al. (USENIX Security 2026)** (*Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem*).

### Inclusion Rule & Methodology
From the published USENIX artifact, the EOA-targeted detection pipeline contains **793 chain-address detection records** (718 unique contract addresses) across seven production blockchains. Intersecting the EOA final detections with confirmed sensitive function signatures (`AM_Detect_SensitiveSigName.jsonl`) yields **58 chain-address cases (53 unique real delegate contracts)** exhibiting dangerous drain primitives (`sweep(address[])`, `sweepTokens(address)`, `sweepERC20(address)`, `drainToken(address,uint256)`, etc.).

Aegis7702 was evaluated against the complete 58-case intersection of EOA-targeted detections and sensitive-function detections from the published USENIX Security 2026 artifact, representing 53 unique real delegate contracts across six chains. Using the artifact's original runtime bytecode in a standardized Prague-EVM reconstruction, Aegis7702 produced executable asset-loss witnesses for 51/58 cases (87.9%), returned NO_MODELED_LOSS for six, and explicitly marked one unsupported interface as UNMODELED. All 51 discovered witnesses reproduced asset loss on clean-state replay, and all 51 were neutralized by nonce-based recovery in the benchmark environment.

We evaluated the **full inclusion set of all 58 chain-address cases (53 unique real delegate contracts)** across 6 production blockchains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon) derived from the artifact, evaluated alongside 4 controlled protocol-negative cases. Every contract was deployed via `anvil_setCode` using its actual artifact bytecode on local Prague EVM snapshots and evaluated under a rigorous three-state classification (`FOUND_LOSS`, `NO_MODELED_LOSS`, `UNMODELED`):

| Evaluation Metric | Real-World Empirical Result | Meaning |
|---|---|---|
| **Evaluated Real Artifact Contracts** | **58 (53 unique delegates)** | Full inclusion set $C$ from USENIX Security '26 |
| **Aegis Modeled Coverage** | **57 / 58 (98.3%)** | Percentage of real delegates within supported action semantics |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | Concrete multi-step loss paths discovered on EVM state |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **6 / 58 (10.3%)** | Delegate executed without triggering loss under bounded model |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | Honest identification of out-of-scope contract semantics |
| **Immediate-Delta Baseline Miss Rate** | **51 / 51 (100%)** | Missed all 51 executable-loss cases because signing produces zero immediate balance delta |
| **Clean-State Witness Replay Success** | **51 / 51 (100%)** | 100% of discovered counterexamples caused real loss on fresh snapshot replay |
| **Post-Recovery Exploit Neutralization** | **51 / 51 (100%)** | 100% of verified exploits reverted on-chain after synthesized recovery |
| **Controlled Protocol-Negative Accuracy** | **4 / 4 (0 false positives)** | 0 false positives across four protocol-negative controls |

Reproduce live on local EVM snapshots via: `cd engine && npm run eval:usenix` (full 58-case execution matrix documented in [`testdata/AEGIS_USENIX_EVALUATION.md`](./testdata/AEGIS_USENIX_EVALUATION.md)).

---

## Adversarial Recovery & Boundary Hardening

Aegis7702 includes a dedicated suite of 5 adversarial stress tests verifying boundary resilience on live Prague EVM forks:

1. **EIP-7702 Future Nonce Attack:** When an attacker tricks a victim into signing an authorization tuple for a future nonce ($n_{\text{current}} = 5, n_{\text{auth}} = 8$), Aegis7702 calculates $\Delta = 4$ and automatically synthesizes 4 sequential self-transactions, advancing the account nonce past the stolen authorization and permanently neutralizing it.
2. **EIP-7702 Active Delegation Clearance:** When malicious code is already actively installed (`0xef0100...`), Aegis7702 synthesizes a Type-4 transaction with authorization pointing to `address(0)` signed with `currentNonce + 1`, resetting the account bytecode back to a clean EOA (`0x`) and proving on-chain that subsequent attacker calls revert.
3. **Permit2 Nonce Delta Single-Chunk Boundary ($\Delta = 65,535$):** Successfully executes a maximum single-transaction invalidation on Permit2's `uint48` counter.
4. **Permit2 Nonce Delta Multi-Chunk Boundary ($\Delta = 65,536$):** Detects delta exceeding Permit2's `ExcessiveInvalidation` threshold and splits the recovery into 2 chunked transactions ($65,535 + 1$), avoiding reverts.
5. **Fail-Closed API Rejection:** Invalid or malformed scenario payloads return deterministic HTTP 400 Bad Request responses rather than hanging or emitting false safety verdicts.

---

## Challenges we ran into

1. **Combinatorial EVM State-Space Explosion:**
   Arbitrary EVM execution has an infinite branching factor ($2^{256}$ possible calldata permutations). Attempting generic state fuzzing in real-time is impossible. We solved this by formulating **typed capability semantics**: rather than brute-forcing arbitrary calls, the engine decodes the exact parameters of the capability (token addresses, spenders, nonces, delegation pointers) and instantiates only legal candidate actions ($\mathcal{A}_{\text{modeled}}$), bounding depth to $k \le 3$ (sufficient to cover *Relay $\to$ Drain $\to$ Unwind*).
2. **Bleeding-Edge Prague Hardfork Tooling:**
   EIP-7702 is newly deployed. Most developer tools, JSON-RPC endpoints, and wallet libraries do not yet have stable native abstractions for Type-4 transaction envelopes and `0xef0100` delegation bytecode. We orchestrated Prague-configured Anvil instances, utilized Viem experimental authorization primitives and Type-4 serializers, and wrote Foundry cheatcode harnesses (`vm.attachDelegation`) to model live delegation mechanics.
3. **Permit2 Caller Identity Constraints & Sentinel Griefing:**
   Canonical Permit2 security functions strictly operate on `msg.sender`. While delegating to `Guard7702Sentinel` allows an EOA to batch-invalidate nonces with `address(this) == victim`, unauthenticated callers could potentially grief the victim by invalidating active nonces. We patched this vulnerability by enforcing a strict `onlySelf` modifier (`require(msg.sender == address(this))`), ensuring only transactions originating from the victim's account can execute Sentinel logic.
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
   All 14 Foundry contract tests and all 3 TypeScript Anvil kill tests run completely offline without external RPC rate-limits, third-party API keys, or flaky network calls. The entire test suite completes in seconds.
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
