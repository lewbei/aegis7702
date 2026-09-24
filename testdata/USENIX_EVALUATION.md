# USENIX Security 2026 Empirical EIP-7702 Benchmark Results

**Reference:** Huang et al. (USENIX Security 2026), *"Revealing the Dark Side of Smart Accounts: An Empirical Study of EIP-7702 Incurred Risks in Blockchain Ecosystem"*.

## Benchmark Overview
The USENIX Security 2026 empirical study audited EIP-7702 across 7 production EVM blockchains, identifying:
- **924 confirmed malicious contract accounts**
- **>63% of observed EIP-7702 authorization transactions tied to attacks**
- **>$2.3M in realized stolen funds** and **>$10M in exposed user assets**

This benchmark evaluates **Aegis7702** across 20 representative EIP-7702 delegate contract archetypes (16 malicious attack variants across 4 threat categories, plus 4 benign reference smart accounts).

## Evaluation Matrix

| ID | Contract Archetype | Threat Classification | Immediate-Delta Baseline | Aegis7702 Reachability Verifier | Exploit Witness | Synthesized Recovery |
|---|---|---|---|---|---|---|
| `USENIX-7702-001` | **PinkDrainer EIP-7702 Direct Sweeper** | `MALICIOUS_DRAINER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-002` | **InfernoDrainer Multi-Token Sweeper** | `MALICIOUS_DRAINER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-003` | **AngelDrainer Account Drainer** | `MALICIOUS_DRAINER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-004` | **Phishing Disguised Transfer Delegate** | `MALICIOUS_DRAINER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-005` | **Backdoor Emergency Asset Exfiltration** | `MALICIOUS_DRAINER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-006` | **Unrestricted Arbitrary Calldata Forwarder** | `MALICIOUS_FORWARDER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-007` | **Unauthenticated Multicall Dispatcher** | `MALICIOUS_FORWARDER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-008` | **Batch Token Transfer Forwarder** | `MALICIOUS_FORWARDER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-009` | **Delegated Forward Call Backdoor** | `MALICIOUS_FORWARDER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-010` | **Trojan Privilege Takeover Delegate** | `MALICIOUS_FORWARDER` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-011` | **Permit2 + 7702 Hybrid Permit-and-Sweep** | `HYBRID_PERMIT2` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-012` | **Permit2 SignatureTransfer Context Forwarder** | `HYBRID_PERMIT2` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-013` | **Infinite Allowance Delegated Injector** | `HYBRID_PERMIT2` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-014` | **Permit2 Allowance Reset Bypass** | `HYBRID_PERMIT2` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `ADVANCE_NONCE_OR_CLEAR` |
| `USENIX-7702-015` | **Dormant Future-Nonce EIP-7702 Trap (+3)** | `DORMANT_NONCE_TRAP` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `FUTURE_NONCE_MULTI_ADVANCE` |
| `USENIX-7702-016` | **Dormant Future-Nonce EIP-7702 Trap (+10)** | `DORMANT_NONCE_TRAP` | `SAFE (0.00 USDC)` | **🚨 CRITICAL REACHABLE DRAIN** | `YES (k=2 steps)` | `FUTURE_NONCE_MULTI_ADVANCE` |
| `USENIX-7702-017` | **Safe 7702 Smart Account Module (Reference)** | `BENIGN_ACCOUNT` | `SAFE (0.00 USDC)` | **✅ CLEAN / CONTROL** | `NO (k<=3 clean)` | `NOOP (Safe Account)` |
| `USENIX-7702-018` | **Biconomy Nexus 7702 Smart Account (Reference)** | `BENIGN_ACCOUNT` | `SAFE (0.00 USDC)` | **✅ CLEAN / CONTROL** | `NO (k<=3 clean)` | `NOOP (Safe Account)` |
| `USENIX-7702-019` | **ZeroDev Kernel v3 WebAuthn Delegate (Reference)** | `BENIGN_ACCOUNT` | `SAFE (0.00 USDC)` | **✅ CLEAN / CONTROL** | `NO (k<=3 clean)` | `NOOP (Safe Account)` |
| `USENIX-7702-020` | **ERC-7579 Modular Account Implementation (Reference)** | `BENIGN_ACCOUNT` | `SAFE (0.00 USDC)` | **✅ CLEAN / CONTROL** | `NO (k<=3 clean)` | `NOOP (Safe Account)` |

## Quantitative Findings & Comparative Advantage

| Metric | Immediate-Delta Simulation (Blockaid/MetaMask Baseline) | Aegis7702 Capability-Reachability Verifier |
|---|---|---|
| **Step 0 Balance Delta** | $0.00 (Evaluates to SAFE) | $0.00 (Recognized as Detached Capability) |
| **Explored Depth** | $k = 1$ (Current Execution Only) | $k \le 3$ (Future Attacker State Space) |
| **False Negative Rate** | **100.0% (16/16 Missed)** | **0.0% (0/16 Missed)** |
| **True Positive Sensitivity** | **0.0% (0/16 Caught)** | **100.0% (16/16 Caught)** |
| **Benign Account Specificity** | 100.0% (4/4 Safe) | 100.0% (4/4 Safe) |
| **Exploit Counterexample Witness** | ❌ None (Opaque Heuristic) | ✅ **100% Concrete Multi-Step Trace** |
| **On-Chain Recovery Action** | ❌ None | ✅ **100% Synthesized & On-Fork Verified** |

### Mathematical Implication
$$\boxed{\text{SimulateCurrentExecution}(c, s_0) = \$0.00 \;\;\not\Rightarrow\;\; \text{SafeFutureCapability}(c, s_0)}$$

Every evaluated malicious EIP-7702 delegate executes zero state transitions at authorization time. Conventional single-step simulation is fundamentally structurally blind to deferred authorization exploits. Aegis7702 deterministically explores reachable downstream attacker transitions, producing an executable counterexample witness and synthesizing state-specific on-chain neutralization.
