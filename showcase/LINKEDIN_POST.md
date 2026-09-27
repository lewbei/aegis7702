Can research rigor and AI collaboration turn an unfamiliar domain into a production-grade hackathon project? 🚀

A few weeks ago, Ethereum Prague's EIP-7702 and Uniswap Permit2 security were outside my core technical specialization.

Yet, this week, I submitted Aegis7702 to the 3rd-Web-Hack Hackathon — a capability-aware reachability verifier and proactive recovery engine for detached off-chain authorizations.

Here is how core research discipline and collaborative AI engineering made this possible:

1. THE PROBLEM: THE SINGLE-STEP SIMULATION FALLACY

Conventional wallet transaction simulators (MetaMask, PocketUniverse, Blowfish) only inspect Step 0. When an off-chain authorization is signed, zero tokens move on-chain at the signing moment:

Immediate Balance Change = $0.00 -> Verdict: SAFE ✅

This creates a fatal false sense of security. Research from USENIX Security 2026 (Huang et al.) revealed that over 63% of observed EIP-7702 transactions were associated with malicious EOA takeovers (over $10M in exposed assets).

The risk is not what executes immediately at signing — it is what multi-step attacker transitions become reachable later.

2. RESEARCH-FIRST PROBLEM DECOMPOSITION

Rather than building a toy heuristic, I approached the challenge through formal research methodology:
• Formal Verification Contract: A discovered exploit path is an executable counterexample witness; finding no path within depth k ≤ 3 is a bounded proof, never an over-claimed promise of global safety.
• Empirical Grounding: Tested the verifier directly against all 58 real-world EOA-targeted exploit cases from the USENIX Security 2026 dataset, discovering 51 executable EVM loss witnesses and proving post-recovery neutralization.
• Multi-Protocol Breadth: Modeled both EIP-7702 delegation traps and Uniswap Permit2 (sequential allowances and 256-bit unordered nonce bitmaps).

3. AI AS A HIGH-SPEED TECHNICAL COPILOT

Web3 security cannot tolerate AI hallucinations. That is why the technical division of labor was strictly defined:
• Zero LLM in the Core Verifier: The reachability engine runs deterministically on local Prague EVM state snapshots (Anvil) and Viem/Solidity code. No language model is in the runtime verification loop.
• AI as an Engineering Accelerator: Leveraged Gemini 3.8 Flash and ChatGPT Web (GPT 5.6 Sol) as technical copilots to rapidly scaffold Foundry test suites, orchestrate Anvil child-process workers, and iterate on documentation and visual storyboards.
• Test-Driven Rigor: Backed every claim with physical proof — 14/14 passing Foundry security tests, full TypeScript reachability kill tests, and automated CI pipelines.

KEY TAKEAWAY

In modern software engineering, you don't need a decade of legacy experience in a niche subfield to build impactful, technically sound systems.

If you bring structured research skills, rigorous problem decomposition, and disciplined AI collaboration, you can dive into bleeding-edge technology and deliver production-grade results in days.

---

PROJECT LINKS:
• Watch the Demo Walkthrough (YouTube): https://youtu.be/lUrXpTSM36Q
• Inspect the Code & Pitch Deck (GitHub): https://github.com/lewbei/aegis7702

How are you integrating collaborative AI into your domain research and development workflows? I'd love to hear your thoughts!

#Web3 #Ethereum #SmartContractSecurity #EIP7702 #Permit2 #AICollaboration #Hackathon #ResearchEngineering #SoftwareEngineering
