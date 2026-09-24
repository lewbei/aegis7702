# Aegis7702: Official 3-Minute Hackathon Demo Video Script & Walkthrough

> **Total Duration:** 3:00 (180 Seconds)  
> **Core Mathematical Thesis:** $\boxed{\$0.00 \text{ Now} \not\Rightarrow \$0.00 \text{ Later}}$  
> **Core System Value:** Aegis7702 detects the deferred multi-step drain, proves it on an EVM state snapshot, synthesizes state-specific recovery, and verifies that replaying the identical attack reverts.

---

## Storyboard & Second-by-Second Execution

### [0:00 – 0:20] The Problem: The $0.00 False Negative Trap
* **Visual:** Browser showing a wallet prompt requesting a signature for an off-chain Permit2 or EIP-7702 authorization tuple. Balance change shows **+$0.00 / -$0.00**.
* **Voiceover:**
  > *"When a Web3 user signs an off-chain Uniswap Permit2 or EIP-7702 authorization tuple, exactly zero dollars move on-chain right now. But that single signature hands an attacker an asynchronous capability: a future transaction sequence that can drain tens of thousands of dollars hours or days later."*
* **Key On-Screen Text:**
  > **$\Delta \text{Balance} = \$0.00$ at Step 0 $\not\Rightarrow$ Safe Account**

---

### [0:20 – 0:50] The Structural Baseline: Immediate-Delta Comparator B₀
* **Visual:** Split screen. On the left: Structural immediate-delta comparator $B_0$ showing: `Immediate Balance Change: $0.00`.
* **Voiceover:**
  > *"On the left is our structural immediate-delta comparator B₀. We do not claim this reproduces Blockaid, MetaMask, or any commercial wallet-security product. B₀ asks only whether the signing event itself produces immediate tracked-asset loss. For detached authorization, that delta is zero by definition. A zero immediate balance delta cannot establish future capability safety."*
* **Key On-Screen Text:**
  > **Comparator Focus:** $B_0(c, s_0) = \$0.00$ (Immediate Delta Blind to Deferred Capability Exploits)

---

### [0:50 – 1:30] Aegis7702: Bounded Capability Reachability
* **Visual:** Transition to the Aegis7702 Web Dashboard. The user pastes the signed capability payload and clicks **Analyze Reachability**.
* **Action:** The ephemeral Anvil Prague EVM instance executes bounded reachability exploration ($k \le 3$). A bright red warning appears:
  `🚨 CRITICAL EXPLOIT REACHABLE (10,000 USDC LOSS IN 2 STEPS)`.
* **Visual:** The interactive reachability graph renders the discovered 2-step exploit path:
  `Step 1: Permit2.permit() [or EIP-7702.relayAuthorization]` $\to$
  `Step 2: Permit2.transferFrom() [or MaliciousDelegate.sweep()]` $\to$
  `Reachable Victim Loss: 10,000 USDC`.
* **Voiceover:**
  > *"This is Aegis7702. Rather than guessing with an AI risk score, Aegis7702 formalizes capability semantics and executes a bounded reachability search against an ephemeral EVM state reconstruction. Aegis7702 discovers the exact downstream attacker action path: first relaying the capability, then executing the drain, proving that 10,000 USDC is fully reachable."*

---

### [1:30 – 1:50] Executing the Counterexample Witness
* **Visual:** Click **Execute Exploit Witness on EVM**. The dashboard executes the attacker trace against the ephemeral Anvil node.
* **Action:** The Victim USDC balance drops in real time:
  `10,000 USDC` $\longrightarrow$ `0 USDC`.
* **Voiceover:**
  > *"To prove this isn't a theoretical warning, Aegis7702 executes the synthesized counterexample directly on the EVM state snapshot. The victim's balance drops to zero. We have an executable mathematical witness of the vulnerability."*

---

### [1:50 – 2:20] State-Specific Recovery Synthesis
* **Visual:** The **Recommended Recovery Action** panel highlights the synthesized transaction:
  - For Permit2: `invalidateNonces(token, spender, nextNonce)`
  - For EIP-7702: `0-value self-transaction (nonce advance)` or `Type-4 authorization for address(0)` to wipe bytecode back to a clean EOA.
* **Action:** Click **Execute 1-Click On-Chain Recovery**.
* **Visual:** Live transaction confirms with hash `0x73cc...`. Victim nonce advances on-chain or Permit2 bitmap flips.
* **Voiceover:**
  > *"Now, Aegis7702 fixes it before the attacker can broadcast. It inspects live on-chain state and synthesizes the exact protocol-level counter-transaction. In Permit2, it calls invalidateNonces past the signed nonce; in EIP-7702, it increments the victim's account nonce or clears the delegation. With one click, the recovery transaction confirms on-chain."*

---

### [2:20 – 2:40] Exploit Replay Verification
* **Visual:** Click **Replay Discovered Exploit Against Post-Recovery State**.
* **Action:** Terminal / UI shows the attacker attempting to broadcast the exact same exploit trace.
* **Visual:** Red execution badge: `REVERTED ON-CHAIN (receipt.status: 0x0 / reverted)`.
  Victim balance: `10,000 USDC (PRESERVED)`.
* **Voiceover:**
  > *"Finally, the closed-loop proof: Aegis7702 replays the identical attacker exploit trace against the post-recovery state. On-chain, the transaction reverts immediately due to nonce invalidation. The attack is permanently neutralized, and the victim's 10,000 USDC remains 100% safe."*

---

### [2:40 – 3:00] Real-World Grounding & Architecture
* **Visual:** Show the Aegis7702-USENIX-Eval empirical benchmark table and terminal execution (`npm run eval:usenix` and `forge test`).
* **Voiceover:**
  > *"These are not toy delegate contracts. Grounded in research from USENIX Security 2026, we evaluated the original runtime bytecode from 58 USENIX-derived real-world delegate cases across six production blockchains in a standardized Prague-EVM reconstruction. Aegis7702 found executable loss paths in 51 cases—87.9%. Every discovered witness reproduced the loss on clean-state replay, and all 51 were neutralized by state-specific recovery. The immediate-delta baseline missed all 51 executable-loss cases because signing itself changes no on-chain balance. Backed by 14 Foundry contract tests and live Prague EVM integration, Aegis7702 turns zero-delta signing traps into executable loss proofs with verified, state-specific recovery. Thank you."*

---

## Video Recording Checklist

- [ ] **Resolution:** 1080p or 4K, 60fps.
- [ ] **Audio:** Clear microphone with background noise suppression.
- [ ] **Pacing:** Strict adherence to the 3:00 time limit (judges stop listening past 3 minutes).
- [ ] **Tab Setup:**
  - Tab 1: Aegis7702 Web Dashboard (`http://localhost:5173`) connected to engine (`http://localhost:3099`).
  - Tab 2: Terminal showing `npm test` and `npm run eval:usenix` passing.
  - Tab 3: GitHub repository (`https://github.com/lewbei/aegis7702`).
