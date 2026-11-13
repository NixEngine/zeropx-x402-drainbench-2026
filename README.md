[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24201802.svg)](https://doi.org/10.5281/zenodo.24201802) [![HF Space](https://img.shields.io/badge/HuggingFace-Live_x402_Verifier-blue)](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier) [![PyPI](https://img.shields.io/pypi/v/zeropx-receipt-chain.svg)](https://pypi.org/project/zeropx-receipt-chain/) [![License: CC BY-ND 4.0](https://img.shields.io/badge/Report_License-CC_BY--ND_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nd/4.0/)

> **Official CERN / Zenodo Permanent Citation:** Cunha Júnior, V. G. R. (2026). *x402-DrainBench-2026: Eight Structural Pre-Settlement Treasury Exposure Classes in Autonomous HTTP 402 & Model Context Protocol (MCP) Financial Agents*. Zenodo. **DOI: [10.5281/zenodo.24201802](https://doi.org/10.5281/zenodo.24201802)**
> **Companion FDA/GxP Benchmark:** **DOI: [10.5281/zenodo.24201727](https://doi.org/10.5281/zenodo.24201727)** | **Interactive Verifier:** [https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier)

# x402-DrainBench-2026: Agentic Wallet & MCP Treasury Conformance Benchmark

[![PyPI - zeropx-poseidon2-goldilocks](https://img.shields.io/pypi/v/zeropx-poseidon2-goldilocks?label=zeropx-poseidon2-goldilocks&color=indigo)](https://pypi.org/project/zeropx-poseidon2-goldilocks/)
[![PyPI - zeropx-receipt-chain](https://img.shields.io/pypi/v/zeropx-receipt-chain?label=zeropx-receipt-chain&color=blue)](https://pypi.org/project/zeropx-receipt-chain/)
[![PyPI - zeropx-layercomp](https://img.shields.io/pypi/v/zeropx-layercomp?label=zeropx-layercomp&color=teal)](https://pypi.org/project/zeropx-layercomp/)
[![PyPI - zeropx-gguf-inspect](https://img.shields.io/pypi/v/zeropx-gguf-inspect?label=zeropx-gguf-inspect&color=navy)](https://pypi.org/project/zeropx-gguf-inspect/)
[![HF Space Verifier](https://img.shields.io/badge/Hugging%20Face%20Space-Live%20Poseidon2%20Verifier-ffd21e)](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier)
[![Benchmark Spec: CC-BY-ND-4.0](https://img.shields.io/badge/Benchmark%20Spec-CC--BY--ND--4.0-darkred)](./LICENSE)
[![Verifier Code: Apache-2.0](https://img.shields.io/badge/Verifier%20Code-Apache--2.0-green)](./LICENSE)

**Author & Sole Scientific/Systems Signatory:** **Dr. Vander Geraldo Rodrigues da Cunha Júnior, M.D.** (`CRM/MG 58.130`, Brazil) — Principal Architect, **ZeroPx Core** (`vgrcjr@gmail.com`)

---

## Why `x402-DrainBench-2026` Matters for AI Agents, Payment Gateways & Institutional Quant Desks

Autonomous agents executing machine-to-machine (`M2M`) stablecoin settlements over **`HTTP 402 Payment Required` (`x402`)**, **`EIP-3009` (`transferWithAuthorization`)**, **Solana `SPL`**, and **`Model Context Protocol` (`MCP 2025-11-25`)** sign irreversible transfer authorizations in milliseconds. Without a deterministic, out-of-band **Pre-Settlement Policy Enforcement Point (`PEP`)**, stateless HTTP auto-retry wrappers and prompt-level guardrails fail across **8 Structural Agentic Treasury Exposure Classes (`EC-01`–`EC-08`)**:

| Exposure Class | Protocol Surface | Default Unprotected `x402 / MCP` Stack | `ZeroPx C++20 PEP R35 CircuitBreaker Enterprise` |
| :---: | :--- | :---: | :---: |
| **`EC-01`** | Unpinned Origin & Untrusted MCP Context Override | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-02`** | Uncapped `HTTP 402` Header Price Escalation (`50 USDC` vs `0.10 USDC` cap) | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-03`** | Post-Preflight `HTTP 307/308` Redirect Origin/Beneficiary Rebinding | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-04`** | `402` `payTo` vs. `EIP-3009` Beneficiary Allowlist Divergence | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-05`** | Silent `ERC-20` Contract Substitution & `18`-Decimal Magnitude Drift | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-06`** | Sub-Cap Cumulative Micro-Payment Velocity Exhaustion (Epoch Drift) | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-07`** | Cross-Epoch `EIP-3009` Nonce Replay & Excessive `24h` Validity Horizon | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **`EC-08`** | In-Band Signing-Material Contamination & Hot/Cold Vault Boundary | `0 / 1` (Exposed) | **`1 / 1` Halted Pre-Settlement** |
| **TOTAL** | **`10,000`-Evaluation Endurance Benchmark (`p50 = 0.78 ms`, `p99 = 0.99 ms`)** | **`0 / 8` (`0.0%`)** | **`8 / 8` (`100.0%` @ `1,255.34 ops/s`)** |

---

## 60-Second Cryptographic Receipt Verification

```bash
pip install zeropx-poseidon2-goldilocks==0.2.0 zeropx-receipt-chain==0.3.0
python verify_x402_drainbench.py --self-test
python verify_x402_drainbench.py --vector EC-02
```

## Repository Contents (`Verifier-Only` Open Release)

- [`REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.pdf`](./REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.pdf) & [`.md`](./REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.md) — Full CISO & protocol conformance benchmark report (`CC-BY-ND-4.0`).
- [`x402_drainbench_2026_diagnostic_vectors.json`](./x402_drainbench_2026_diagnostic_vectors.json) — 12 benign synthetic protocol conformance diagnostic vectors (`SV-01`–`SV-12`).
- [`x402_drainbench_ledger.jsonl`](./x402_drainbench_ledger.jsonl) — Sealed `SHA-256` + `Poseidon2-Goldilocks` ledger (`Post-Seal Root: e08b02ac86a241ac299e060626f4a2bb7d6f989e8632a34daa40a5215b8d375a`).
- [`verify_x402_drainbench.py`](./verify_x402_drainbench.py) — Standalone Verifier-Only auditor (`Apache-2.0`).

## Enterprise Licensing (`ZeroPx C++20 PEP R35 CircuitBreaker Enterprise`)
This repository contains diagnostic conformance vectors and cryptographic verifiers only (`0.00%` enforcement code disclosure). For commercial CISO, payment-facilitator, and quantitative treasury licensing of the native sub-millisecond `C++20 PEP R35` binary and `MCP 2025-11-25` sidecar, contact **`vgrcjr@gmail.com`**.

---
*Sole Human Author: **Dr. Vander Geraldo Rodrigues da Cunha Júnior, M.D. (`CRM/MG 58.130`)**. Technical & AI-Assisted Provenance Disclosure: Auxiliary simulation and `Poseidon2-Goldilocks` sealing verified `1:1` under sole human authorship (`CFM Res. 2.454/2026`, Arts. 4-V & 7; `ICMJE`). Governed by Brazilian Law No. 12.965/2014 (Art. 11) & Law No. 13.810/2019.*


## Structural On-Chain Settlement Bifurcation (`x402 v2` `EIP-3009` vs. `ERC-7579` / `ERC-1271 STATICCALL`)

A critical architectural finding for CISOs deploying autonomous payment agents over `x402 v2` (`scheme: exact`, EVM `EIP-3009` `transferWithAuthorization`):
1. **Smart-Account Hook Bypass:** In `EIP-3009`, the facilitator submits the signed authorization directly to the token contract (`USDC`), **completely bypassing `ERC-7579` `execute` hooks** on the smart account.
2. **The `ERC-1271` `STATICCALL` Accounting Trap:** Even on tokens supporting `ERC-1271` contract signatures (e.g., USDC v2.2), the token invokes `isValidSignature` via EVM `STATICCALL`, prohibiting `SSTORE` state writes and making **cumulative per-epoch on-chain spending counters impossible inside `ERC-1271`**.
3. **The `UNKNOWN` Settlement Reservation Law ($S_e + R + v \le B_e$):** Releasing local budget reservations upon HTTP timeout or `HTTP 200` without confirmed facilitator settlement (`PAYMENT-RESPONSE` + finalized on-chain nonce check `block.timestamp >= validBefore && !authorizationState(payer, nonce)`) exposes agent treasuries to deterministic double-spend exhaustion once exposed `EIP-3009` signatures settle asynchronously.

*(Open release provides diagnostic conformance vectors and `Poseidon2-Goldilocks` receipt verifiers only — `0.00%` of the proprietary `ZeroPx x402-CircuitBreaker` pre-signer state-machine & reconciler runtime is disclosed; commercial licensing via `vgrcjr@gmail.com`.)*
