# Aegis7702 — Three-Minute Interactive Walkthrough Script

Format: Guided presentation of the interactive judge walkthrough (`app/public/judge-demo.html` or `http://localhost:5173/judge-demo.html`).
This walkthrough demonstrates the core mathematical contrast: **$\boxed{\$0.00 \text{ Now} \not\Rightarrow \$0.00 \text{ Later}}$**.

---

## [0:00–0:35] Step 01: The Wallet Trap (The False Safe Sensation)

* **Screen:** Open `judge-demo.html`. Select **Step 01: The Wallet Trap** under EIP-7702 Delegation.
* **Point to Visual:** The mock **Status Quo Wallet Simulator** card showing `Estimated Delta: +0.00 USDC` and `Verdict: SAFE ✅`.
* **Presenter Script:**
  > *"When an Ethereum user signs an off-chain authorization—such as an EIP-7702 delegation tuple or Uniswap Permit2 message—status quo wallet simulators inspect only Step 0. As you can see in this simulated wallet prompt, zero tokens move on-chain right now, so the wallet declares the transaction completely safe.*  
  > *This is the fatal trap of single-step simulation: $0.00 moved now does NOT mean zero risk later. The user clicks confirm, releasing an asynchronous exploit capability directly into the attacker's hands."*

---

## [0:35–1:10] Step 02: The Hidden Attack (Multi-Step Reachable Drain)

* **Screen:** Click **Step 02: The Hidden Attack** (or Next Step).
* **Point to Visual:** The **Executable Exploit Flowchart** rendering Step 1 (`EIP7702.relayAuthorization`) and Step 2 (`MaliciousDelegate.sweep`).
* **Presenter Script:**
  > *"Rather than guessing with an AI score, Aegis7702 explores legal EVM action sequences ($k \le 3$) against an ephemeral Anvil Prague EVM state reconstruction.*  
  > *Aegis7702 discovers the exact downstream exploit path: First, the attacker broadcasts a Type-0x04 transaction installing delegation bytecode. Next, the attacker calls `sweep()` on the victim's account, transferring all 10,000 USDC. Within 150ms, Aegis7702 produces a concrete, executable loss witness."*

---

## [1:10–1:45] Step 03: Proactive Recovery (Dual-Universe Branch Comparison)

* **Screen:** Click **Step 03: Proactive Recovery**.
* **Point to Visual:** The **Universe A vs Universe B** side-by-side branch comparison.
* **Presenter Script:**
  > *"Now observe the two parallel universes. In Universe A, without defense, the exploit executes and the account is wiped out.*  
  > *In Universe B, Aegis7702 synthesizes a state-specific recovery transaction before the attacker consumes the capability. For EIP-7702, the owner sends a self-transaction advancing their account nonce from 2 to 3. Because EIP-7702 strictly checks that authority nonce equals authorization nonce, this invalidates the signed payload forever.*  
  > *Notice: This is evaluated on a clean initial state before loss occurs. It is proactive prevention—not a refund of already stolen money."*

---

## [1:45–2:15] Step 04: The Replay Proof (Deterministic EVM Revert)

* **Screen:** Click **Step 04: The Replay Proof**.
* **Point to Visual:** The **Ephemeral EVM Replay Verifier** terminal showing the revert message and preserved balance.
* **Presenter Script:**
  > *"To formally verify mitigation, Aegis7702 replays the exact same 2-step attacker trace against the post-recovery state.*  
  > *Look at the EVM execution output: The attacker's transaction halts immediately with an EVM revert—`Authorization Nonce Mismatch`. The exploit is completely blocked, and the 10,000 USDC remains 100% preserved. The formal stopping criterion is satisfied."*

---

## [2:15–2:40] Breadth across Permit2 & Technical Deep-Dive

* **Screen:** Toggle **Permit2 Allowance** or **Permit2 Signature**, and click the **EVM Deep-Dive** pill toggle.
* **Presenter Script:**
  > *"The exact same verification pipeline protects Uniswap Permit2. For Permit2 allowance transfers, Aegis7702 synthesizes `invalidateNonces()`. For unordered signature transfers, it flips the exact bit in the Permit2 bitmap slot via `invalidateUnorderedNonces()`. Evaluators can toggle between 'Executive' mode and 'EVM Deep-Dive' to inspect contract calldata, storage slot offsets, and raw opcodes."*

---

## [2:40–3:00] Grounded in USENIX Artifacts & Pinned Release

* **Screen:** Scroll down to the **Physical Evidence** section.
* **Presenter Script:**
  > *"Aegis7702 is not a toy demo. It is grounded in the USENIX Security 2026 dataset, discovering 51 concrete exploit witnesses across 58 cases, with 100% neutralized on clean EVM state. All four CI jobs are green on commit `bd15aecd` in release `hackathon-final-v1.0.13`.*  
  > *Closing takeaway: Single-step simulation is blind to deferred capabilities. Aegis7702 proves the attack and neutralizes the threat."*
