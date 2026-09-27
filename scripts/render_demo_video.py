#!/usr/bin/env python3
"""Aegis7702 - High-Resolution Demo Video Generator

Captures pixel-perfect full-HD frames from the live application and compiles a
cinematic walkthrough video (1920x1080 @ 30fps MP4) complete with keynote chapter
cards, on-screen narration subtitles, stage indicators, and smooth cross-fades.

Follows the Aegis7702 Video Production Plan:
- Act I: The Zero-Delta Fallacy & Problem Statement
- Act II: Sample 1 (EIP-7702 Prague Delegation Trap)
- Act III: Sample 2 (Uniswap Permit2 Allowance)
- Act IV: Sample 3 (Uniswap Permit2 Signature Transfer)
- Act V: Empirical Evidence (USENIX Security 2026 Artifacts)
- Act VI: Judge Quickstart & Outro
"""

import os
import subprocess
import time
import cv2
import numpy as np

OUTPUT_DIR = "/home/lewbei/Downloads"
FRAMES_DIR = "/home/lewbei/Downloads/video_frames"
VIDEO_PATH = os.path.join(OUTPUT_DIR, "aegis7702-demo-walkthrough.mp4")

os.makedirs(FRAMES_DIR, exist_ok=True)

# 20 Storyboard Elements (16 Viewport Scenes + 4 Keynote Chapter Title Cards)
STORYBOARD = [
    # Act I: The Hook & Core Fallacy
    {
        "type": "scene",
        "id": "act1_01_hero",
        "url": "http://localhost:5173/judge-demo.html",
        "duration_sec": 6.0,
        "title": "Aegis7702: Capability-Aware Reachability Verifier",
        "subtitle": "The Core Flaw: $0.00 Now Does NOT Mean $0.00 Later",
        "script": "When an off-chain authorization is signed, zero tokens move on-chain at Step 0. Status quo wallets declare the transaction safe. Aegis7702 asks what loss paths become reachable later."
    },
    {
        "type": "scene",
        "id": "act1_02_wallet_trap",
        "url": "http://localhost:5173/?tab=verifier&scenario=eip7702_prague&stage=0",
        "duration_sec": 6.0,
        "title": "Stage 01: Off-Chain Signing (The False Safe Trap)",
        "subtitle": "Immediate Delta: +0.00 USDC | Status Quo Scanner: SAFE",
        "script": "Standard simulators inspect only the signing moment. Because no bytecode executes immediately, the user is misled into releasing a lethal capability into the attacker's hands."
    },

    # Act II: Sample 1 (EIP-7702 Delegation)
    {
        "type": "chapter",
        "id": "chapter_sample1",
        "chapter_num": "01",
        "duration_sec": 3.0,
        "title": "SAMPLE 1: EIP-7702 DELEGATION TRAP",
        "subtitle": "Ethereum Prague Account Delegation · Multi-Step Attacker Sweep",
        "bullets": [
            "Signed Authorization: (chainId: 31337, delegate: 0x84641..., nonce: 2)",
            "Discovered Exploit: Relay delegation -> Attacker sweeps 10,000 USDC",
            "Synthesized Recovery: Advance account nonce 2 -> 3 before consumption",
            "Replay Verification: Replay halts on-chain with Nonce Mismatch (0 Loss)"
        ]
    },
    {
        "type": "scene",
        "id": "sample1_stage1_exploit",
        "url": "http://localhost:5173/?tab=verifier&scenario=eip7702_prague&stage=1",
        "duration_sec": 6.5,
        "title": "Sample 1 / Stage 02: Bounded Reachability Exploit Discovery",
        "subtitle": "Concrete Exploit Witness: 2-Step Drain (10,000 USDC Loss)",
        "script": "Aegis7702 explores legal EVM action sequences: Attacker broadcasts Type-0x04 authorization, then calls sweep() on victim context to drain all 10,000 USDC."
    },
    {
        "type": "scene",
        "id": "sample1_stage2_recovery",
        "url": "http://localhost:5173/?tab=verifier&scenario=eip7702_prague&stage=2",
        "duration_sec": 6.5,
        "title": "Sample 1 / Stage 03: State-Specific Proactive Recovery",
        "subtitle": "ADVANCE_NONCE: Owner increments account nonce 2 -> 3 on clean state",
        "script": "Recovery is synthesized on a clean state branch before loss occurs. Under EIP-7702 rules, advancing the account nonce permanently invalidates the stolen authorization."
    },
    {
        "type": "scene",
        "id": "sample1_stage3_replay",
        "url": "http://localhost:5173/?tab=verifier&scenario=eip7702_prague&stage=3",
        "duration_sec": 6.5,
        "title": "Sample 1 / Stage 04: Deterministic Replay Neutralization Proof",
        "subtitle": "Stopping Rule: L(s0, T_pi) > 0 and L(sR, T_pi) = 0 | 10,000 USDC Preserved",
        "script": "Replaying the identical exploit against the post-recovery state halts on-chain with Authorization Nonce Mismatch. All 10,000 USDC remains 100% intact."
    },

    # Act III: Sample 2 (Uniswap Permit2 Allowance)
    {
        "type": "chapter",
        "id": "chapter_sample2",
        "chapter_num": "02",
        "duration_sec": 3.0,
        "title": "SAMPLE 2: UNISWAP PERMIT2 ALLOWANCE",
        "subtitle": "AllowanceTransfer Protocol · Asynchronous Multi-Step Permit Relay",
        "bullets": [
            "Signed Authorization: PermitSingle EIP-712 message (10,000 USDC allowance)",
            "Discovered Exploit: Attacker calls permit() -> Drains via transferFrom()",
            "Synthesized Recovery: Call invalidateNonces(token, spender, newNonce: 1)",
            "Replay Verification: Replay halts on-chain with InvalidNonce() (0 Loss)"
        ]
    },
    {
        "type": "scene",
        "id": "sample2_stage0_signing",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_allowance&stage=0",
        "duration_sec": 5.5,
        "title": "Sample 2 / Stage 01: Off-Chain PermitSingle Signing",
        "subtitle": "Precondition: Active ERC-20 approval to Permit2 contract",
        "script": "Sample 2 models Uniswap Permit2 AllowanceTransfer. The user signs an off-chain permit. Zero tokens move immediately, masking the pending allowance risk."
    },
    {
        "type": "scene",
        "id": "sample2_stage1_exploit",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_allowance&stage=1",
        "duration_sec": 6.0,
        "title": "Sample 2 / Stage 02: Asynchronous Permit + TransferFrom Drain",
        "subtitle": "Reachable Loss: 2-Step Drain (10,000 USDC Loss)",
        "script": "Aegis7702 discovers the downstream exploit: the attacker injects the permit into Permit2, then drains the 10,000 USDC allowance using transferFrom."
    },
    {
        "type": "scene",
        "id": "sample2_stage2_recovery",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_allowance&stage=2",
        "duration_sec": 6.0,
        "title": "Sample 2 / Stage 03: Proactive Nonce Invalidation",
        "subtitle": "Synthesized Action: invalidateNonces(token, spender, newNonce: 1)",
        "script": "Aegis7702 synthesizes an on-chain nonce bump directly on the Permit2 contract before the attacker's transaction can be included."
    },
    {
        "type": "scene",
        "id": "sample2_stage3_replay",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_allowance&stage=3",
        "duration_sec": 6.0,
        "title": "Sample 2 / Stage 04: Replay Neutralization Proof",
        "subtitle": "Stopping Rule Verified: Replay fails with InvalidNonce | 10,000 USDC Preserved",
        "script": "When the attacker attempts to replay their permit, Permit2 rejects it with InvalidNonce. The exploit is neutralized, leaving 10,000 USDC safe."
    },

    # Act IV: Sample 3 (Uniswap Permit2 Signature)
    {
        "type": "chapter",
        "id": "chapter_sample3",
        "chapter_num": "03",
        "duration_sec": 3.0,
        "title": "SAMPLE 3: PERMIT2 SIGNATURE TRANSFER",
        "subtitle": "SignatureTransfer Protocol · 256-bit Unordered Nonce Bitmask Exploit",
        "bullets": [
            "Signed Authorization: PermitTransferFrom (one-time signature, nonce 1025)",
            "Discovered Exploit: Direct permitTransferFrom execution sweeps tokens",
            "Synthesized Recovery: invalidateUnorderedNonces(wordPos: 4, mask: 2)",
            "Replay Verification: Replay halts on-chain with InvalidNonce() (0 Loss)"
        ]
    },
    {
        "type": "scene",
        "id": "sample3_stage0_signing",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_signature&stage=0",
        "duration_sec": 5.5,
        "title": "Sample 3 / Stage 01: One-Time Transfer Authorization Signing",
        "subtitle": "Unordered Nonce: 1025 (Word Position: 4, Bit: 1)",
        "script": "Sample 3 targets Permit2 SignatureTransfer used in DEX swaps. Unlike sequential allowances, these use 256-bit unordered nonce bitmaps."
    },
    {
        "type": "scene",
        "id": "sample3_stage1_exploit",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_signature&stage=1",
        "duration_sec": 6.0,
        "title": "Sample 3 / Stage 02: One-Step Signature Consumption Drain",
        "subtitle": "Reachable Loss: Direct Consumption Witness (10,000 USDC Loss)",
        "script": "Consuming the one-time transfer signature directly sweeps the victim's tokens in a single execution step, wiping out the balance."
    },
    {
        "type": "scene",
        "id": "sample3_stage2_recovery",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_signature&stage=2",
        "duration_sec": 6.0,
        "title": "Sample 3 / Stage 03: Precise Bitmask Nonce Cancellation",
        "subtitle": "Synthesized Action: invalidateUnorderedNonces(wordPos: 4, mask: 2)",
        "script": "Aegis7702 calculates the exact storage bitmask and synthesizes invalidateUnorderedNonces without affecting any unrelated signatures."
    },
    {
        "type": "scene",
        "id": "sample3_stage3_replay",
        "url": "http://localhost:5173/?tab=verifier&scenario=permit2_signature&stage=3",
        "duration_sec": 6.0,
        "title": "Sample 3 / Stage 04: Replay Neutralization Proof",
        "subtitle": "Stopping Rule Verified: Replay fails with InvalidNonce | 10,000 USDC Preserved",
        "script": "Replaying the transfer fails immediately on-chain. The specific nonce bit is set, blocking the exploit while preserving all 10,000 USDC."
    },

    # Act V: Empirical Evidence & Formal Architecture
    {
        "type": "chapter",
        "id": "chapter_evidence",
        "chapter_num": "04",
        "duration_sec": 3.0,
        "title": "EMPIRICAL EVIDENCE & ARCHITECTURE",
        "subtitle": "USENIX Security 2026 Artifacts · Bounded Verifier Stopping Rule",
        "bullets": [
            "58 Real-World USENIX Cases across 6 chains (Ethereum, Arbitrum, Base...)",
            "51 / 58 Executable Vulnerability Witnesses Discovered (87.9% Yield)",
            "51 / 51 Clean-State Witness Replay Verified (100% Loss Reproduction)",
            "51 / 51 Proactively Neutralized via Synthesized On-Chain Recovery"
        ]
    },
    {
        "type": "scene",
        "id": "act5_benchmark",
        "url": "http://localhost:5173/?tab=benchmark",
        "duration_sec": 7.0,
        "title": "Empirical Benchmark: USENIX Security 2026 Dataset",
        "subtitle": "58 Cases -> 51 Exploit Witnesses (87.9%) -> 51 Neutralized (100%)",
        "script": "Aegis7702 is tested against real-world USENIX 2026 EIP-7702 exploits in CI run #36149170988. All four jobs green on immutable release hackathon-final-v1.0.13."
    },
    {
        "type": "scene",
        "id": "act5_architecture",
        "url": "http://localhost:5173/?tab=architecture",
        "duration_sec": 6.5,
        "title": "Formal Verifier Architecture & Stopping Criterion",
        "subtitle": "Strict Contract: NO_MODELED_LOSS is bounded; UNMODELED is never masked",
        "script": "A found loss path is a concrete witness; no loss found is not global safety. Unknown actions and infrastructure errors fail closed with explicit UNMODELED status."
    },

    # Act VI: Outro & Quickstart
    {
        "type": "scene",
        "id": "act6_quickstart",
        "url": "http://localhost:5173/judge-demo.html#evidence",
        "duration_sec": 6.5,
        "title": "Judge Quickstart & Standalone Offline Walkthrough",
        "subtitle": "make test-contracts | make test-engine | make demo | make video",
        "script": "Judges can test the entire pipeline in under 60 seconds with make test-contracts and make test-engine, or explore judge-demo.html offline. Thank you."
    }
]

def capture_frames():
    """Captures all web viewport frames using headless Brave."""
    print("Capturing high-resolution viewport frames using headless Brave...")
    scenes_to_capture = [s for s in STORYBOARD if s["type"] == "scene"]
    for idx, scene in enumerate(scenes_to_capture):
        img_path = os.path.join(FRAMES_DIR, f"{scene['id']}.png")
        cmd = [
            "/snap/bin/brave",
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--window-size=1920,1080",
            f"--screenshot={img_path}",
            scene["url"]
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if os.path.exists(img_path) and os.path.getsize(img_path) > 10000:
            print(f"[{idx+1}/{len(scenes_to_capture)}] Captured {scene['id']} ({os.path.getsize(img_path):,} bytes)")
        else:
            raise RuntimeError(f"Failed to capture frame for {scene['id']}: {res.stderr}")

def create_chapter_card(entry):
    """Creates a keynote-style chapter transition title card."""
    card = np.zeros((1080, 1920, 3), dtype=np.uint8)
    card[:] = (13, 17, 7)  # #07110d background

    # Subtle inner container
    cv2.rectangle(card, (160, 160), (1760, 920), (25, 39, 20), -1)
    cv2.rectangle(card, (160, 160), (1760, 920), (133, 238, 182), 2)

    # Chapter Tag
    pill_text = f"CHAPTER {entry['chapter_num']} / 04"
    cv2.rectangle(card, (220, 220), (480, 270), (133, 238, 182), -1)
    cv2.putText(card, pill_text, (240, 255), cv2.FONT_HERSHEY_DUPLEX, 0.75, (7, 17, 13), 2, cv2.LINE_AA)

    # Title & Subtitle
    cv2.putText(card, entry["title"], (220, 360), cv2.FONT_HERSHEY_DUPLEX, 1.4, (133, 238, 182), 2, cv2.LINE_AA)
    cv2.putText(card, entry["subtitle"], (220, 420), cv2.FONT_HERSHEY_DUPLEX, 0.85, (238, 246, 238), 1, cv2.LINE_AA)

    # Divider
    cv2.line(card, (220, 460), (1700, 460), (45, 74, 55), 2)

    # Bullet points
    y = 540
    for bullet in entry.get("bullets", []):
        cv2.circle(card, (240, y - 8), 6, (133, 238, 182), -1)
        cv2.putText(card, bullet, (270, y), cv2.FONT_HERSHEY_SIMPLEX, 0.75, (215, 235, 220), 2, cv2.LINE_AA)
        y += 75

    return card

def create_scene_frame(base_img, scene, current_time_str):
    """Draws brand top-bar and multi-line lower-third subtitles."""
    h, w, _ = base_img.shape
    frame = base_img.copy()

    # 1. Top Header Banner
    overlay = frame.copy()
    cv2.rectangle(overlay, (0, 0), (w, 64), (7, 17, 13), -1)
    cv2.addWeighted(overlay, 0.90, frame, 0.10, 0, frame)
    cv2.line(frame, (0, 64), (w, 64), (45, 74, 55), 1)

    # Top Brand & Section Title
    cv2.putText(frame, "AEGIS7702", (36, 42), cv2.FONT_HERSHEY_DUPLEX, 0.85, (133, 238, 182), 2, cv2.LINE_AA)
    cv2.putText(frame, "|  " + scene["title"], (205, 41), cv2.FONT_HERSHEY_DUPLEX, 0.65, (238, 246, 238), 1, cv2.LINE_AA)
    cv2.putText(frame, current_time_str, (w - 200, 41), cv2.FONT_HERSHEY_DUPLEX, 0.65, (157, 179, 164), 1, cv2.LINE_AA)

    # 2. Bottom Narration / Subtitle Lower Third
    banner_h = 135
    banner_y = h - banner_h
    overlay = frame.copy()
    cv2.rectangle(overlay, (0, banner_y), (w, h), (7, 17, 13), -1)
    cv2.addWeighted(overlay, 0.95, frame, 0.05, 0, frame)
    cv2.line(frame, (0, banner_y), (w, banner_y), (133, 238, 182), 2)

    # Subtitle Highlight
    cv2.putText(frame, scene["subtitle"], (40, banner_y + 40), cv2.FONT_HERSHEY_DUPLEX, 0.75, (133, 238, 182), 2, cv2.LINE_AA)

    # Narration Script with auto line wrapping
    words = scene["script"].split(" ")
    lines = []
    curr_line = ""
    for word in words:
        if len(curr_line + " " + word) > 115:
            lines.append(curr_line)
            curr_line = word
        else:
            curr_line = (curr_line + " " + word).strip()
    if curr_line:
        lines.append(curr_line)

    sub_y = banner_y + 78
    for line in lines[:2]:
        cv2.putText(frame, line, (40, sub_y), cv2.FONT_HERSHEY_SIMPLEX, 0.65, (230, 242, 230), 1, cv2.LINE_AA)
        sub_y += 30

    return frame

def render_video():
    """Renders all storyboard scenes and chapter cards into MP4."""
    fps = 30
    transition_frames = 12  # 0.4s crossfade
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(VIDEO_PATH, fourcc, float(fps), (1920, 1080))

    if not out.isOpened():
        raise RuntimeError(f"Could not open VideoWriter for {VIDEO_PATH}")

    total_duration = sum(s["duration_sec"] for s in STORYBOARD)
    print(f"Rendering {len(STORYBOARD)} storyboard items to {VIDEO_PATH} at {fps} fps...")
    print(f"Total planned duration: {total_duration:.1f}s (~{total_duration/60:.2f} mins)")
    start_time = time.time()

    # Pre-generate / load base images
    elements = []
    for item in STORYBOARD:
        if item["type"] == "chapter":
            card_img = create_chapter_card(item)
            elements.append((card_img, item))
        else:
            img_path = os.path.join(FRAMES_DIR, f"{item['id']}.png")
            raw_img = cv2.imread(img_path)
            if raw_img is None:
                raise FileNotFoundError(f"Missing frame image: {img_path}")
            raw_img = cv2.resize(raw_img, (1920, 1080))
            elements.append((raw_img, item))

    frame_count = 0
    total_elapsed_sec = 0.0

    for idx, (img, item) in enumerate(elements):
        item_dur = item["duration_sec"]
        item_frames = int(item_dur * fps)

        for f_idx in range(item_frames):
            sec_now = int(total_elapsed_sec + (f_idx / fps))
            time_str = f"[{sec_now // 60}:{sec_now % 60:02d} / {int(total_duration) // 60}:{int(total_duration) % 60:02d}]"

            if item["type"] == "chapter":
                curr_frame = img.copy()
            else:
                curr_frame = create_scene_frame(img, item, time_str)

            # Cross-fade with previous item at start
            if idx > 0 and f_idx < transition_frames:
                alpha = f_idx / float(transition_frames)
                prev_img, prev_item = elements[idx - 1]
                if prev_item["type"] == "chapter":
                    prev_frame = prev_img.copy()
                else:
                    prev_frame = create_scene_frame(prev_img, prev_item, time_str)
                blended = cv2.addWeighted(curr_frame, alpha, prev_frame, 1.0 - alpha, 0)
                out.write(blended)
            else:
                out.write(curr_frame)

            frame_count += 1

        total_elapsed_sec += item_dur
        name = item.get("title", item.get("id"))
        print(f"[{idx+1}/{len(elements)}] Rendered: {name} ({item_frames} frames)")

    out.release()
    elapsed = time.time() - start_time
    file_size_mb = os.path.getsize(VIDEO_PATH) / (1024 * 1024)
    print(f"\n=======================================================")
    print(f"✅ Video render complete in {elapsed:.1f}s ({frame_count / elapsed:.1f} fps)")
    print(f"📁 Video file: {VIDEO_PATH}")
    print(f"📦 File size: {file_size_mb:.2f} MB")
    print(f"⏱️ Total duration: {total_elapsed_sec:.1f}s ({frame_count} frames)")
    print(f"=======================================================")

if __name__ == "__main__":
    capture_frames()
    render_video()
