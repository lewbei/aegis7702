# Aegis7702: Capability-Reachability Verifier & Recovery Engine

**Pitch Deck — 3rd-Web-Hack Hackathon (Sept 2026)**  
*Track: Security, Infrastructure & Smart Accounts*  
*GitHub: [github.com/lewbei/aegis7702](https://github.com/lewbei/aegis7702)*

---

## Slide 1: Problem — $0 Now Does Not Imply $0 Later

### The Detached Authorization Trap in Post-Pectra Ethereum

- **The Paradigm Shift:** EIP-7702 (Type-4 delegation tuples) and Uniswap Permit2 decouple **authorization signing** from **on-chain transaction execution**.
- **The Zero-Delta Trap:** When a user signs an off-chain delegation tuple or permit, **zero balance moves on-chain at Step 0**.
- **The Result:** The user believes they signed a harmless message. In reality, they released an asynchronous capability that lets an attacker drain funds hours or days later.

```text
[User Signs Off-Chain] ──► Immediate Balance Delta: $0.00 (Looks Safe)
                                      │
                                (Hours Later)
                                      ▼
[Attacker Broadcasts Tuple] ──► Code Injected ──► $10,000 USDC Drained
```

> **Core Mathematical Flaw:**  
> $$\boxed{\text{SimulateCurrentExecution}(c, s_0) \not\Rightarrow \text{SafeFutureCapability}(c, s_0)}$$

---

## Slide 2: Why Existing Tools Miss the Threat

### Current Simulators Only Evaluate Current State ($s_0$)

- **Single-Step Blindness:** Mainstream wallets and transaction scanners evaluate:
  $$\text{Safe}(s_0, \text{tx}) \iff \Delta \text{Balance}(s_0) \ge -\epsilon$$
- **The Blindspot:** Since signing detached capabilities produces no state delta at depth 0, current-execution baselines emit a green **SAFE** verdict.
- **Real-World Damage:** Research from **USENIX Security 2026** (Huang et al.) reveals that over **63% of observed EIP-7702 authorization transactions** were associated with malicious EOA-targeted attacks, exposing **>$10M in user assets**.
- **What is Needed:** Not another static blacklist or probabilistic "AI risk score", but a **dynamic reachability search** over future attacker-controlled state transitions.

| Dimension | Single-Step Simulation Baseline | Aegis7702 Reachability Engine |
|---|---|---|
| **Temporal Scope** | Current execution state ($s_0$ only) | Downstream state transitions ($k \le 3$) |
| **Zero-Delta Signatures** | Missed (Reports SAFE, $\Delta = \$0.00$) | Explored (Discovers delayed drain path) |
| **Output Type** | Pass / Fail or Heuristic Score | Concrete Executable Exploit Witness $\pi$ |
| **Mitigation** | None (User left vulnerable) | Synthesized 1-Click On-Fork Recovery |

---

## Slide 3: Aegis7702 Architecture

### Closed-Loop Typed Capability Reachability ($k \le 3$)

```text
       Raw Wallet Signing Payload (EIP-7702 / Permit2)
                             │
                             ▼
               [Typed Capability Decoder]
                             │
                             ▼
         [Candidate Transition Generator 𝒜_modeled]
                             │
                             ▼
        [Bounded EVM Reachability Explorer (k ≤ 3)]
        (Ephemeral Anvil Prague State Snapshots & Reverts)
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
       No Loss Found                 Loss Witness Discovered
 (Bounded Safety Contract)         π = (Relay ⟶ Drain ⟶ ...)
                                            │
                                            ▼
                               [Recovery Planner Engine]
                                            │
                                            ▼
                           Synthesize Counter-Tx s ⟶ s_R
                                            │
                                            ▼
                                [On-Fork Replay Proof]
                              L(s_R, T_π(s_R)) = 0 (Neutralized)
```

- **Asymmetric Claim:** A positive path $\pi$ is a **concrete, executable vulnerability witness**. A negative result establishes bounded safety $\neg \text{Unsafe}_{\le 3}^{\mathcal{A}_{\text{modeled}}}$, not an indefensible global guarantee.

---

## Slide 4: Live Attack $\to$ Recovery $\to$ Replay

### Deterministic Stopping Criterion: $L(s_0) > 0 \land L(s_R) = 0$

1. **Step 1: Baseline Contrast:**
   - Single-step simulation shows: $\Delta \text{Balance} = \$0.00$ (**SAFE**).
2. **Step 2: Reachability Discovery:**
   - Aegis7702 discovers multi-step sequence at depth 2:
     `RelayAuthorization` $\to$ `MaliciousDelegate.sweep()`
   - Proven asset loss: **10,000 USDC** ($L(s_0) > 0$).
3. **Step 3: State-Specific Recovery Synthesis:**
   - *EIP-7702 Unconsumed:* Synthesizes 0-value self-transaction to increment account nonce $n \to n+1$. (EIP-7702 strictly invalidates authorization on nonce mismatch).
   - *EIP-7702 Active:* Synthesizes Type-4 recovery pointing to `address(0)` to wipe delegation bytecode back to a clean EOA.
   - *Permit2:* Synthesizes `invalidateNonces` or `invalidateUnorderedNonces(wordPos, mask)`.
4. **Step 4: On-Chain Replay Neutralization:**
   - Replays identical attacker trace $\pi$ against post-recovery fork state $s_R$.
   - **Result:** Attack reverts or no-ops; **10,000 USDC preserved** ($L(s_R) = 0$).

---

## Slide 5: Empirical Evidence: 58-Case USENIX Benchmark

### Grounded in Real Attack Bytecode, Not Hand-Crafted Toys

Evaluated against the complete intersection of EOA detections and sensitive functions from **Huang et al. (USENIX Security 2026)** across 6 production blockchains (Ethereum, Base, BNB, Optimism, Arbitrum, Polygon):

```text
           USENIX '26 Official Artifact (793 EOA Detection Records)
                                      │
              Intersection with Confirmed Drain Interfaces
                                      │
                                      ▼
             Complete Inclusion Set C = 58 Chain-Address Cases
                         (53 Unique Runtime Bytecodes)
```

### Reproducible Results (Executed in GitHub Actions CI):

| Benchmark Metric | Empirical Value | Rigorous Meaning |
|---|:---:|---|
| **Evaluated Real Bytecodes** | **58 cases (53 unique)** | Full inclusion set $C$ from USENIX '26 |
| **Exploit Witnesses Discovered** | **51 / 58 (87.9%)** | Concrete multi-step EVM loss witnesses proven |
| **Explored Without Loss** | **6 / 58 (10.3%)** | Real bytecodes requiring unmodeled state/preconditions |
| **Unmodeled Interface** | **1 / 58 (1.7%)** | Unsupported interface reported honestly |
| **Immediate-Delta Baseline Miss Rate** | **51 / 51 (100%)** | Baseline missed all 51 executable loss cases |
| **Clean-State Witness Replay** | **51 / 51 (100%)** | 100% loss reproducibility on fresh EVM snapshots |
| **Post-Recovery Neutralization** | **51 / 51 (100%)** | 100% of replayed exploits neutralized ($L=0$) |
| **Controlled Negative Accuracy** | **4 / 4 (0 false positives)** | Zero false alarms on safe/guarded EOAs |

> **CI Reproducibility:** Every single case is executed in an automated, reproducible GitHub Actions CI pipeline on ephemeral Anvil Prague forks.

---

## Slide 6: Impact, Scope Bounds & Future Roadmap

### Hackathon Feasibility Today $\to$ Ecosystem Standard Tomorrow

- **What Aegis7702 Solves Today:**
  - Eliminates the single-step simulation blindspot for EIP-7702 and Permit2.
  - Generates verifiable 1-click counter-transactions before the attacker broadcasts.
  - Backed by **14 Foundry tests (13ms)**, **3 Anvil kill tests**, and **5 adversarial integration tests**.

- **Honest Scope Bounds:**
  - Search bounded at $k \le 3$ (covers *Relay $\to$ Drain $\to$ Unwind*).
  - Primary asset loss measured on targeted ERC-20 tokens.
  - Recovery depends on mining order (recommends private RPC / Flashbots Protect in adversarial public mempools).

- **Production Roadmap:**
  1. **MetaMask Snap & Wallet Extension:** Intercept signing payloads before release.
  2. **Private Bundler Integration:** Dispatch recovery transactions directly via Flashbots Protect / MEV-Share to eliminate frontrunning.
  3. **Expanded DeFi Transition Models:** Include Uniswap v3/v4 pools and lending liquidations.

---

### Project Summary

- **Repository:** [github.com/lewbei/aegis7702](https://github.com/lewbei/aegis7702)
- **CI Build:** [GitHub Actions Run #35964170153](https://github.com/lewbei/aegis7702/actions/runs/35964170153)
- **Benchmark Report:** [`testdata/AEGIS_USENIX_EVALUATION.md`](../testdata/AEGIS_USENIX_EVALUATION.md)
- **Interactive UI:** Vite 8 + React 19 Prototype Dashboard
