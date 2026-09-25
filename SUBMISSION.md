# Aegis7702: Bounded Capability-Reachability Verifier & Recovery Engine

**Project Name:** Aegis7702  
**Tagline / Elevator Pitch:** Catches zero-delta deferred drains in EIP-7702 & Permit2 signatures. Aegis7702 verifies multi-step capability reachability in a local EVM environment and synthesizes verified 1-click on-chain recovery.

---

## Inspiration

The inspiration for **Aegis7702** originates directly from the tectonic shift occurring in Ethereum's post-Pectra architecture. With the activation of **EIP-7702**, Externally Owned Accounts (EOAs) can now ephemerally delegate their execution logic to arbitrary smart contracts using Type-4 (`0x04`) transaction envelopes and `0xef0100` bytecode pointers. When coupled with the widespread adoption of off-chain signature protocols like Uniswap’s **Permit2** (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`), the Web3 ecosystem has fundamentally decoupled **authorization signing** from **on-chain execution**.

This architectural decoupling fundamentally challenges conventional single-step transaction security heuristics. Immediate-delta baselines evaluate safety using an immediate balance-delta check:
$$\text{Safe}(s_0, \text{tx}) \iff \Delta \text{Balance}(s_0) \ge -\epsilon$$

When an attacker tricks a victim into signing an off-chain EIP-7702 authorization tuple:
$$c = (\text{chainId}, \text{address}, \text{nonce}, y, r, s)$$
or a detached Permit2 signature, **zero state changes occur on-chain at Step 0**. Immediate-delta baselines evaluate $\Delta \text{Balance}(s_0) = \$0.00$ and emit a SAFE verdict. Hours or days later, the attacker broadcasts the authorization, installs drain bytecode on the victim's EOA, and sweeps the account clean. This is a critical false negative.

This crisis is already empirically documented. Research presented at **USENIX Security 2026** (Huang et al.) reveals that across a seven-chain dataset, **over 63% of observed EIP-7702 authorization transactions were associated with malicious EOA-targeted attacks**, identifying 924 malicious contract accounts, **over $2.3M in realized stolen funds**, and **>$10M in exposed assets**.

We built Aegis7702 around a single foundational mathematical thesis:
$$\boxed{\text{SimulateCurrentExecution}(c, s_0) \not\Rightarrow \text{SafeFutureCapability}(c, s_0)}$$

Conventional simulation only reveals what a proposed execution does under a particular current state $s_0$. Detached capabilities demand a completely different question: **What future attacker-controlled state transitions become reachable once this signed capability is released into the wild?**

---

## What it does

**Aegis7702** is a typed, bounded **Capability-Reachability Verifier (CRV)** and **State-Specific Recovery Synthesizer** for EIP-7702 authorizations and Uniswap Permit2 signatures.

Instead of outputting ambiguous, probabilistic "AI risk scores", Aegis7702 executes a closed-loop deterministic verification protocol against live EVM state snapshots:

1. **Typed Capability Extraction & Cryptographic Validation:** Ingests raw wallet signing payloads via dedicated Capability Decoders (`decodePermit2Allowance`, `decodePermit2Signature`, `decode7702`) into structured capabilities $c \in \mathcal{C}$ across three supported domains:
   - EIP-7702 Ephemeral Delegation Tuples
   - Uniswap Permit2 `AllowanceTransfer` (`PermitSingle` / `PermitBatch`)
   - Uniswap Permit2 `SignatureTransfer` (Unordered Nonce Bitmaps)
   Every payload is validated cryptographically via `CapabilityValidator` (`recoverAuthorizationAddress` and `verifyTypedData`) before reachability search. Forged or mismatched signatures immediately yield `INVALID_CAPABILITY`.
2. **Bounded Reachability Search ($k \le 3$):** Generates candidate attacker action sequences within modeled semantics $\mathcal{A}_{\text{modeled}}$ and explores downstream EVM state branches:
   $$\text{Unsafe}_{\le k}^{\mathcal A_{\text{modeled}}}(c, s_0) \iff \exists \pi = (a_1, \ldots, a_j), \, j \le k \quad \text{such that} \quad L(s_0, T_\pi(s_0)) > 0$$
   where the loss function evaluates tracked asset deltas:
   $$L(s_0, s') = \sum_{t \in \text{Tracked}} \max(0, \text{Balance}_{t, \text{victim}}(s_0) - \text{Balance}_{t, \text{victim}}(s'))$$
   *(In our MVP, this measures the primary capability-associated ERC-20 token, with multi-asset ETH/ERC-20 aggregate blast radius tracking in our roadmap).*
3. **Strict 5-State Verification Domain & Executable Counterexamples:** Reachability exploration returns one of five strict, deterministic outcomes:
   $$\boxed{\text{FOUND\_LOSS} \mid \text{NO\_MODELED\_LOSS} \mid \text{UNMODELED} \mid \text{CONDITIONAL\_RISK} \mid \text{INVALID\_CAPABILITY}}$$
   **No Fabricated Counterexamples:** A physical `counterexample` is returned if and only if $L(s_0, s') > 0$ is actually executed and witnessed on the EVM state. In dormant conditions (such as future nonces $n_{\text{auth}} > n_{\text{onchain}}$), the engine strictly abstains from returning a fake counterexample, emitting `CONDITIONAL_RISK` alongside prospective risk projections (`prospectiveRisk`).
4. **State-Specific On-Chain Recovery Synthesis:** Inspects live chain state and automatically synthesizes the protocol-correct counter-transaction:
   - *Unconsumed EIP-7702 Authorization:* Constructs a 0-value self-transaction to increment the victim's account nonce from $n \to n+1$ (or multiple bounded self-transactions capped at 100 advances with gas estimation if a future nonce was signed). Because EIP-7702 strictly checks `authority.nonce == auth.nonce`, the stolen authorization is rendered unusable via protocol-level nonce mismatch.
   - *Active EIP-7702 Delegation:* Constructs an EIP-7702 Type-4 transaction with authorization pointing to `address(0)` to wipe the `0xef0100...` delegation indicator back to a clean EOA.
   - *Permit2 Allowance:* Calls canonical `Permit2.invalidateNonces()` to bump nonces past signed nonces before broadcast, or `Permit2.lockdown()` to zero active allowances.
   - *Permit2 Signature:* Calls `Permit2.invalidateUnorderedNonces(wordPos, mask)` to flip the bitmap word position, neutralizing the signature.
5. **Post-Recovery Bounded Re-Search & Replay Verification:** Proves safety on-chain through dual verification:
   First, the engine reruns a complete bounded reachability exploration from the post-recovery state $s_R$, formally proving that no remaining exploit path exists:
   $$\boxed{Explore(c, s_R, \mathcal{A}_{\text{modeled}}, k) \equiv \text{NO\_MODELED\_LOSS}}$$
   Second, it replays the candidate exploit trace $\pi$ against $s_R$ to prove neutralization:
   $$\boxed{L(s_0, T_\pi(s_0)) > 0 \quad \land \quad L(s_R, T_\pi(s_R)) = 0}$$
   In execution semantics, this condition is satisfied when the replayed exploit trace either explicitly reverts on-chain (e.g., Permit2 nonce invalidation reverting with `InvalidNonce`) or executes harmlessly with zero tracked asset loss (e.g., EIP-7702 authorization skipped due to nonce mismatch, causing delegated drain calls to revert or become harmless no-ops on a clean EOA). Tracked asset balances remain completely unchanged under the replayed trace.

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
│   ├── src/capability/         # Capability decoders, CapabilityValidator (offline cryptographic verification)
│   ├── src/search/             # Bounded DFS explorer (k ≤ 3), ActionProvider decoupling, ERC20LossOracle
│   ├── src/recovery/           # State-specific recovery planners for EIP-7702 and Permit2
│   └── src/server.ts           # HTTP API server (/api/analyze, /api/recover, /api/replay, /api/analyze-capability)
│
└── app/                        # Interactive Visualizer Dashboard (React 19 + Vite 8)
    └── src/                    # Live Anvil RPC integration, baseline contrast, 1-click on-chain recovery
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
  - Implemented depth-first reachability exploration bounded at $k \le 3$, utilizing lightweight EVM snapshots (`evm_snapshot` / `evm_revert`) to keep branch exploration lightweight and fast.
  - Authored 3 automated, self-contained **Kill Tests** (`killTest.ts`, `killTestSignature.ts`, `killTest7702.ts`) and **5 Adversarial Recovery Integration Scenarios** (`testIntegration.ts`) that execute completely offline via `npm test` with zero external RPC dependencies.
  - Built a lightweight HTTP backend server (`server.ts`) exposing `/api/analyze`, `/api/recover`, and `/api/replay` for real-time frontend execution on live ephemeral Anvil instances.
* **Interactive Prototype Dashboard:**
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

To ground Aegis7702 in real-world threat intelligence rather than hand-crafted toy scenarios, we executed a preregistered empirical evaluation against real smart contract bytecodes derived from **Huang et al. (USENIX Security 2026)** (*Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem*).

### Inclusion Rule & Methodology
From the published USENIX artifact, the EOA-targeted detection pipeline contains **793 chain-address detection records** (718 unique contract addresses) across seven production blockchains. Intersecting the EOA final detections with confirmed sensitive function signatures (`AM_Detect_SensitiveSigName.jsonl`) yields **58 chain-address cases (53 unique delegate addresses, 47 unique runtime bytecodes)** exhibiting dangerous drain primitives (`sweep(address[])`, `sweepTokens(address)`, `sweepERC20(address)`, `drainToken(address,uint256)`, etc.).

### Benchmark A: Real-World Empirical Evaluation on 58 USENIX Delegates ($B_1$ vs. Aegis CRV)

Aegis7702 was evaluated against the complete 58-case intersection of EOA-targeted detections and sensitive-function detections from the published USENIX Security 2026 artifact, representing 53 unique real delegate contracts (47 unique runtime bytecodes) across six chains (Ethereum, Base, BNB Chain, Optimism, Arbitrum, Polygon), alongside 4 controlled protocol-negative cases.

Every contract was deployed via `anvil_setCode` using its actual artifact bytecode on local Prague EVM snapshots and evaluated under identical starting state $s_0$ by **both** the greedy linear forward runner ($B_1$ - `StateAwareGreedyRunner`) and the Aegis reachability explorer (CRV - `ReachabilityExplorer` with $k \le 3$):

| Evaluation Metric | Baseline B₁ (Greedy Forward) | Aegis CRV (Tree Search) | Empirical Delta / Meaning |
|---|:---:|:---:|---|
| **Evaluated Real Artifact Contracts** | **58 (53 addresses, 47 bytecodes)** | **58 (53 addresses, 47 bytecodes)** | Full inclusion set $C$ from USENIX Security '26 |
| **Exploit Witnesses Discovered (`FOUND_LOSS`)** | **51 / 58 (87.9%)** | **51 / 58 (87.9%)** | Identical 51/51 exploit discovery on all vulnerable delegates |
| **Explored Without Loss (`NO_MODELED_LOSS`)** | **0 / 58 (0.0%)** | **6 / 58 (10.3%)** | Aegis rolls back reverting calls to certify no modeled loss |
| **Unmodeled Delegated Interfaces (`UNMODELED`)** | **1 / 58 (1.7%)** | **1 / 58 (1.7%)** | Identical abstention on non-modeled selector (`0x628ff693`) |
| **Execution Halted on Revert (`REVERT_ERROR`)** | **6 / 58 (10.3%)** | **0 / 58 (0.0%)** | Linear B₁ halts on revert; Aegis recovers via snapshot rollback |
| **Structural B₀ Immediate-Delta Comparator** | 51 / 51 ($0.00 delta) | 51 / 51 ($0.00 delta) | B₀ evaluated zero immediate loss at Step 0 for all 51 loss cases |
| **Clean-State Witness Replay Success** | **51 / 51 (100%)** | **51 / 51 (100%)** | Independently measured on fresh snapshots for both systems |
| **Post-Recovery Exploit Neutralization** | **51 / 51 (100%)** | **51 / 51 (100%)** | Independently replayed against state $s_R$; 100% neutralized |
| **Exploit Trace Equivalence ($Trace_{B_1} \equiv Trace_{\text{Aegis}}$)** | **51 / 51 (100%)** | **51 / 51 (100%)** | 100% identical action sequences and calldata across all 51 cases |
| **Max Branching Factor ($b_{\text{modeled}}$)** | **1** | **1** | Candidate profile $[1, 1]$ across all 51 cases (proves linear topology) |
| **Controlled Protocol-Negative Accuracy** | **4 / 4 (0 false positives)** | **4 / 4 (0 false positives)** | 0 false positives across four protocol-negative controls |

#### Resource & Latency Comparison on Real USENIX Corpus

| Resource Metric | Baseline B₁ (All 58 Cases) | Aegis CRV (All 58 Cases) | Baseline B₁ (51 FOUND_LOSS) | Aegis CRV (51 FOUND_LOSS) |
|---|:---:|:---:|:---:|:---:|
| **EVM Calls (Mean / Median)** | 1.97 / 2 | 1.97 / 2 | 2.00 / 2 | 2.00 / 2 |
| **EVM Snapshots (Mean / Median)** | **0.00 / 0** | **1.97 / 2** | **0.00 / 0** | **2.00 / 2** |
| **Runtime ms (Median)** | **57 ms** | **73 ms** | **57 ms** | **73 ms** |

Reproduce live on local EVM snapshots via: `cd engine && npm run eval:usenix` (full 58-case execution matrix documented in [`testdata/AEGIS_USENIX_EVALUATION.md`](./testdata/AEGIS_USENIX_EVALUATION.md)).

---

### Benchmark B: Controlled Adversarial Capability Benchmark ($B_1$ vs. Aegis CRV)

To rigorously isolate the contribution of **bounded tree search with EVM backtracking** from simple forward simulation, we evaluated Aegis against the state-aware reference baseline ($B_1$ - `StateAwareGreedyRunner`) under controlled adversarial fixtures ($k \le 3$):

* **$B_0$ (Immediate-Delta Comparator):** Inspects balance delta at $t = 0$. By construction, detached signatures (EIP-7702, Permit2) yield $\Delta = \$0.00$. Defeating $B_0$ only justifies *multi-step execution*, not *tree search*.
* **$B_1$ (State-Aware Greedy Linear Forward Runner):** Understands EIP-7702 and Permit2, relays Type-4 authorizations when required, but executes candidate actions **greedily and linearly forward without state snapshots (`evm_snapshot` / `evm_revert`)**. Uses single-trace replay for post-recovery verification.
* **Aegis CRV (`ReachabilityExplorer` & `MultiCapabilityAuditor`):** Bounded tree search ($k \le 3$) with state snapshotting, backtracking across reverting and decoy branches, and full post-recovery portfolio auditing from state $s_R$.

#### Empirical Comparison Matrix

Executed live via `make test-comparison` (`npm run eval:comparison`):

| Fixture | System | Outcome | Visited States | EVM Calls | Snapshots | Backtracks | Local Anvil Latency* | Verdict / Architectural Finding |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **1. Canonical EIP-7702 Sweep** | B₁ (Greedy Forward) | `FOUND_LOSS` | 2 | 2 | 0 | 0 | ~62 ms | **Pass (Optimal on Linear):** Linear forward simulation suffices with zero snapshot overhead |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 2 | 2 | 2 | 2 | ~89 ms | **Pass (Equivalent):** Identifies identical exploit trace; snapshots incur minor overhead |
| **2. Canonical Permit2 Drain** | B₁ (Greedy Forward) | `FOUND_LOSS` | 2 | 2 | 0 | 0 | ~58 ms | **Pass (Depth 2 Equivalent):** Both execute `permit` → `transferFrom` |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 2 | 2 | 2 | 2 | ~76 ms | **Pass (Depth 2 Equivalent):** Identifies identical exploit trace |
| **3. Branching Decoys (Policy Stress Test)** | B₁ (Greedy Forward Policy) | `REVERT_ERROR` | 2 | 2 | 0 | 0 | ~43 ms | **Halted on Revert Decoy:** First-action greedy execution halted on reverting branch |
| | Aegis CRV (Tree Search) | `FOUND_LOSS` | 4 | 6 | 6 | 6 | ~171 ms | **PASS (True Positive):** Snapshot rollback backtracks around decoys to discover drain |
| **4. Post-Recovery Residual Risk** | B₁ (Single-Trace Replay) | `TRACE_BLOCKED` | 1 | 1 | 0 | 0 | ~23 ms | **Trace Blocked:** Exploit trace $\pi_{7702}$ blocked; makes no claim on overall account safety |
| | Aegis CRV (`MultiCapabilityAuditor`) | `FOUND_RESIDUAL_LOSS` | 3 | 2 | 2 | 2 | ~109 ms | **PASS (Portfolio Defense):** Evaluates complete account portfolio across isolated snapshots $s_R$; detects unrevoked Permit2 allowance |

*\*Latencies represent single-run measurements on local Anvil nodes and illustrate relative overhead rather than statistical microbenchmarks.*

#### Scientific Takeaways & Honest Concessions
1. **Concession on Linear Chains ($b_{\text{modeled}} = 1$):** Where smart account capabilities feature single-path, monotonic drain routines (such as the 51 executable-loss cases in our standardized USENIX '26 reconstruction), greedy forward simulation ($B_1$) is completely sufficient and executes with lower latency and zero snapshot overhead. Our branching telemetry proves that $b_{\text{modeled}} = 1$ with candidate profiles $[1, 1]$ across all 51 cases. We explicitly do **not** claim tree search is superior on simple linear topologies.
2. **Robustness to Branch-Order Ambiguity (Policy Stress Test):** A first-action greedy execution policy is branch-order sensitive: when an adversarial contract presents multiple entrypoints where decoy or reverting branches precede the drain (Fixture 3), the greedy policy halts on the first revert with `REVERT_ERROR`. Aegis CRV uses EVM snapshots (`evm_snapshot` / `evm_revert`) to recover from reverting branches and continue exploration, making it robust against candidate ordering.
3. **Trace-Specific Mitigation $\neq$ State Re-Verification:** A single-trace verifier evaluates whether the historical exploit trace $\pi^*$ is neutralized (`TRACE_BLOCKED`), making no claim about overall account safety. In accounts with multiple compromised capabilities (Fixture 4: revoked EIP-7702 but unrevoked Permit2 allowance), single-trace replay confirms the EIP-7702 exploit was blocked. `MultiCapabilityAuditor` re-evaluates the account's complete capability portfolio on isolated state snapshots $s_R$, uncovering the unrevoked Permit2 drain and flagging incomplete recovery:
   $$\boxed{\text{Trace-Specific Mitigation Verification} \neq \text{Post-Recovery State Re-Verification}}$$

---

## Adversarial Recovery & Boundary Hardening

Aegis7702 includes a dedicated suite of adversarial stress tests verifying boundary resilience in a standardized local Prague-EVM reconstruction:

1. **EIP-7702 Future Nonce Attack:** When an attacker tricks a victim into signing an authorization tuple for a future nonce ($n_{\text{current}} = 5, n_{\text{auth}} = 8$), Aegis7702 calculates $\Delta = 4$ and automatically synthesizes 4 sequential self-transactions, advancing the account nonce past the stolen authorization and permanently neutralizing it.
2. **EIP-7702 Active Delegation Clearance:** When malicious code is already actively installed (`0xef0100...`), Aegis7702 synthesizes a Type-4 transaction with authorization pointing to `address(0)` signed with `currentNonce + 1`, resetting the account bytecode back to a clean EOA (`0x`) and proving on-chain that subsequent attacker calls revert.
3. **Permit2 Nonce Delta Single-Chunk Boundary ($\Delta = 65,535$):** Successfully executes a maximum single-transaction invalidation on Permit2's `uint48` counter.
4. **Permit2 Nonce Delta Multi-Chunk Boundary ($\Delta = 65,536$):** Detects delta exceeding Permit2's `ExcessiveInvalidation` threshold and splits the recovery into 2 chunked transactions ($65,535 + 1$), avoiding reverts.
5. **SSRF Defense Layer with Asynchronous DNS Resolution:** Validates user-supplied `forkUrl` endpoints via strict hostname/IP parsing and asynchronous DNS resolution (`dns.promises.lookup` with `all: true`), blocking loopback, private RFC1918 IPv4 CIDRs, link-local, cloud instance metadata (`169.254.169.254`, `metadata.google.internal`), and DNS rebinding hostnames (`127.0.0.1.nip.io`).
6. **Worker Pool & Concurrency Limiting:** Restricts concurrent on-demand verification jobs to 4 workers globally at Anvil spawn time (`MAX_CONCURRENT_WORKERS = 4` -> HTTP 429) with a 30s timeout watchdog that explicitly terminates child processes (`SIGKILL`), preventing orphan process leaks.
7. **Wallet-Signable Recovery Plans (`POST /api/recovery-plan`):** Emits unsigned transaction envelopes formatted for `window.ethereum.request` alongside typed on-chain state preconditions for EIP-7702, Permit2 Allowance, and Permit2 Signature.
8. **State-Race Precondition Guards (`STATE_PRECONDITION_FAILED`):** Aborts recovery with HTTP 409 Conflict (`STATE_PRECONDITION_FAILED`) if on-chain state changes before recovery broadcast, covering EIP-7702 account nonces, delegations, bytecode, Permit2 allowance nonces and amounts, and Permit2 signature bitmap words.
9. **Fail-Closed API Rejection:** Invalid or malformed scenario payloads return deterministic HTTP 400 Bad Request responses rather than hanging or emitting false safety verdicts.

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
   We did not just build a detector that alerts users. We built a closed-loop system: **Capability Extraction $\to$ Reachability Exploration $\to$ Concrete Exploit Witness $\to$ Recovery Synthesis $\to$ Replay Neutralization Verification**.
2. **100% Offline Reproducibility with Zero Flakiness:**
   All 14 Foundry contract tests and all 3 TypeScript Anvil kill tests run completely offline without external RPC rate-limits, third-party API keys, or flaky network calls. The contract test suite executes in 13ms, with local engine kill tests completing in under a minute and the full 58-case benchmark reproducing in CI.
3. **Formal Mathematical Grounding:**
   Directly addressing the USENIX Security 2026 empirical dataset and grounding the authorization architecture in the **Key Sovereignty** framework of Matthias Hauser (arXiv:2605.01210).
4. **Interactive Prototype Dashboard:**
   A high-fidelity, interactive dashboard built in Vite with zero TypeScript compilation errors, allowing technical judges and end users to visually contrast single-step simulation against downstream reachability and trigger 1-click on-chain mitigations.

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
