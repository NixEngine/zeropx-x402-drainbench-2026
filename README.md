[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24201802.svg)](https://doi.org/10.5281/zenodo.24201802) [![HF Space](https://img.shields.io/badge/HuggingFace-Live_x402_Verifier_v1.2-blue)](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier) [![PyPI](https://img.shields.io/pypi/v/zeropx-receipt-chain.svg)](https://pypi.org/project/zeropx-receipt-chain/) [![License: CC BY-ND 4.0](https://img.shields.io/badge/Report_License-CC_BY--ND_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nd/4.0/)

> **Archival Citation (Archived on Zenodo with DOI and Published Checksums):** Cunha Júnior, V. G. R. (2026). *x402-DrainBench-2026: Eight Structural Pre-Settlement Treasury Exposure Classes in Autonomous HTTP 402 & Model Context Protocol (MCP) Financial Agents*. Zenodo. **DOI: [10.5281/zenodo.24201802](https://doi.org/10.5281/zenodo.24201802)** *(Hosting on Zenodo provides archival DOIs and published file checksums at the CERN Data Centre; it does not constitute scientific or cryptographic endorsement by CERN.)*
> **Companion Regulatory Benchmark:** **DOI: [10.5281/zenodo.24201727](https://doi.org/10.5281/zenodo.24201727)** | **Interactive Browser Verifier (`v1.2`):** [https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier)

# x402-DrainBench-2026: Synthetic Diagnostic Taxonomy & Integrity Verifier (`Release v1.2`)

[![PyPI - zeropx-poseidon2-goldilocks](https://img.shields.io/pypi/v/zeropx-poseidon2-goldilocks?label=zeropx-poseidon2-goldilocks&color=indigo)](https://pypi.org/project/zeropx-poseidon2-goldilocks/)
[![PyPI - zeropx-receipt-chain](https://img.shields.io/pypi/v/zeropx-receipt-chain?label=zeropx-receipt-chain&color=blue)](https://pypi.org/project/zeropx-receipt-chain/)
[![PyPI - zeropx-layercomp](https://img.shields.io/pypi/v/zeropx-layercomp?label=zeropx-layercomp&color=teal)](https://pypi.org/project/zeropx-layercomp/)
[![PyPI - zeropx-gguf-inspect](https://img.shields.io/pypi/v/zeropx-gguf-inspect?label=zeropx-gguf-inspect&color=navy)](https://pypi.org/project/zeropx-gguf-inspect/)
[![HF Space Verifier](https://img.shields.io/badge/Hugging%20Face%20Space-Live%20Poseidon2%20Verifier%20v1.2-ffd21e)](https://huggingface.co/spaces/junior-br/zeropx-2026-fda-x402-verifier)
[![Benchmark Spec: CC-BY-ND-4.0](https://img.shields.io/badge/Benchmark%20Spec-CC--BY--ND--4.0-darkred)](./LICENSE)
[![Verifier Code: Apache-2.0](https://img.shields.io/badge/Verifier%20Code-Apache--2.0-green)](./LICENSE)

**Sole Human Author:** **Vander Geraldo Rodrigues da Cunha Júnior** — Principal, **ZeroPx Core** (`vgrcjr@gmail.com`)

---

## Methodology & Release `v1.2` Reconciliation Note (13 November 2026)

1. **Exact 64-Bit Goldilocks Integer Restoration (`100%` Zenodo `24201802` Byte Parity):**  
   An initial web upload to GitHub serialized `x402_drainbench_2026_diagnostic_vectors.json` through browser `JSON.parse`/`JSON.stringify`, rounding 24 64-bit Goldilocks field integers (`> 2^53 - 1`). Release `v1.2` restores the exact binary file archived on Zenodo Record `24201802` (`18,325` bytes, `MD5: 326d4c247dcea3f6cfad0dd5f7b7a770`, `SHA-256: 21685da31a90059f424cf9185af43238b3bd09cd92dd6d87751eeda446ca7eb0`) and adds `verify_strict_v1_2.py` + `MANIFEST_SHA256_v1_2.json` to assert exact 64-bit little-endian integer-to-hex correspondence across all Merkle proofs.
2. **Scope of the Diagnostic Taxonomy & Public Verifier (`Verifier-Only`):**  
   `x402_drainbench_2026_diagnostic_vectors.json` defines **12 synthetic diagnostic vectors**: **4 positive conformant baselines (`SV-01`–`SV-04`, expected `ALLOW_SIGN`)** and **8 treasury-exposure audit vectors (`SV-05`–`SV-12`, expected `DENY_PRE_SETTLEMENT` across `EC-01`–`EC-08`)**. The public Python and browser verifiers check recorded `SHA-256` hash chains and algebraic `Poseidon2-Goldilocks` (`p = 2^64 - 2^32 + 1`) Merkle commitments (`0.00%` proprietary PEP enforcement runtime disclosure); they do not rerun the proprietary enforcement engine or independently benchmark every third-party `@x402` / MCP SDK configuration.

---

## Diagnostic Exposure Taxonomy (`EC-01`–`EC-08` + `4` Positive Baselines)

| Vector / Class | Synthetic Diagnostic Surface | Unchecked Stateless Retry Baseline | Target Policy Outcome (`ZeroPx PEP`) |
| :---: | :--- | :---: | :---: |
| **`SV-01`–`SV-04`** | **Positive Conformant Controls** (Pinned HTTPS origin, within-cap `USDC`, valid beneficiary & epoch budget) | Allowed | **`ALLOW_SIGN` (`4 / 4` Baselines)** |
| **`SV-05` (`EC-01`)** | Unpinned Origin & Untrusted MCP Context Override | Exposed if origin unpinned | **`DENY_PRE_SETTLEMENT`** |
| **`SV-06` (`EC-02`)** | Uncapped `HTTP 402` Header Price Escalation (`50 USDC` vs. `0.10 USDC` policy cap) | Exposed if header uncapped | **`DENY_PRE_SETTLEMENT`** |
| **`SV-07` (`EC-03`)** | Post-Preflight `HTTP 307/308` Redirect Origin/Beneficiary Rebinding | Exposed if redirect unbound | **`DENY_PRE_SETTLEMENT`** |
| **`SV-08` (`EC-04`)** | `402` `payTo` vs. `EIP-3009` Beneficiary Allowlist Divergence | Exposed if `payTo` unchecked | **`DENY_PRE_SETTLEMENT`** |
| **`SV-09` (`EC-05`)** | Silent `ERC-20` Asset Contract Substitution & `18`-Decimal Magnitude Drift | Exposed if asset tuple unverified | **`DENY_PRE_SETTLEMENT`** |
| **`SV-10` (`EC-06`)** | Concurrent Multi-Worker Micro-Payment Budget Over-Allocation Across Distinct Nonces | Exposed without atomic WAL lock | **`DENY_PRE_SETTLEMENT`** |
| **`SV-11` (`EC-07`)** | Excessive `EIP-3009` `validBefore` Horizon & Cross-Epoch Reservation Drift | Exposed if horizon unbounded | **`DENY_PRE_SETTLEMENT`** |
| **`SV-12` (`EC-08`)** | In-Band Signing-Material Contamination & Signer Boundary Violation | Exposed if key in agent memory | **`DENY_PRE_SETTLEMENT`** |

*(Reported metrics from local synthetic harness over injected/simulated signing and transport interfaces: `10,000` evaluations at `p50 = 0.78 ms`, `p99 = 0.99 ms`, `59` local unit/property tests passing.)*

---

## Concrete Authorization & Settlement Route Analysis (`EIP-3009`, `ERC-7579`, `ERC-1271`)

1. **Direct Token Settlement vs. `account.execute()` Hooks:**  
   When an `x402` facilitator settles a signed `EIP-3009` (`transferWithAuthorization`) payload directly on the token contract, execution does not traverse hooks attached **only** to `account.execute()` on a smart account for that route.
2. **Read-Only `ERC-1271` Validation (`STATICCALL`):**  
   On tokens supporting `ERC-1271` contract-signature validation, `isValidSignature` executes under EVM `STATICCALL`: it **can read on-chain state**, **but cannot by itself write state (`SSTORE`) to atomically reserve and cumulatively consume budget across concurrent off-chain authorizations** without a mandatory stateful authorization or settlement path. Note that concurrent authorizations exceeding an epoch budget represent **budget over-allocation across distinct nonces**, not double-settlement of the same `EIP-3009` nonce on a conformant token.
3. **Atomic Pre-Signature Reservation & `UNKNOWN` Retention (`S_e + R + v <= B_e`):**  
   While single-process SDK hooks (e.g., `onBeforePaymentCreation`) enforce per-call checks locally, multi-worker fleets require serialized pre-signature reservation:

```text
p = 2^64 - 2^32 + 1
S_e + R + v <= B_e
```

   Here `S_e` is settled spend charged to the epoch, `R` is outstanding reserved exposure, `v` is the new authorization, and `B_e` is the policy limit. Once a signed authorization is transmitted, an HTTP timeout or unverified response leaves a live authorization in flight; `R` must remain locked in `UNKNOWN` across epoch boundaries until reconciled against finalized chain state bound to that exact `(payer, nonce)` — e.g., `block.timestamp > validBefore && !authorizationState(payer, nonce)` (a `+1s` guard covering both Circle `FiatTokenV2`'s strict `now < validBefore` check and inclusive `<= validBefore` `EIP-3009` implementations).

---

## Zero-Setup Offline Integrity Verification

Both `poseidon2_goldilocks` (`0.2.0`) and `receipt_chain` (`0.3.0`) are vendored directly in-repo so verification runs offline with Python 3.11+ standard library:

```bash
python verify_x402_drainbench.py --self-test
python verify_strict_v1_2.py
```

*Cryptographic Terminology Note:* Published roots (`Pre-Seal Root: 0724341e...`, `Post-Seal Root: e08b02ac86a241ac299e060626f4a2bb7d6f989e8632a34daa40a5215b8d375a`) are algebraic `Poseidon2-Goldilocks` Merkle commitments and `SHA-256` hash chains, not SNARK/STARK zero-knowledge proofs or asymmetric PKI signatures.

## Repository Contents

- [`MANIFEST_SHA256_v1_2.json`](./MANIFEST_SHA256_v1_2.json) & [`verify_strict_v1_2.py`](./verify_strict_v1_2.py) — `v1.2` SHA-256 manifest and strict 64-bit integer/ledger consistency verifier.
- [`REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.pdf`](./REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.pdf) & [`.md`](./REPORT_02_X402_DRAINBENCH_2026_AGENTIC_WALLET_SECURITY.md) — Preserved `v1.0` Zenodo `24201802` report (`CC-BY-ND-4.0`, read alongside the `v1.2` Methodology Note above).
- [`x402_drainbench_2026_diagnostic_vectors.json`](./x402_drainbench_2026_diagnostic_vectors.json) — Exact Zenodo `24201802` 12 synthetic diagnostic vectors (`SV-01`–`SV-12`, all 24 64-bit Goldilocks integers intact).
- [`x402_drainbench_ledger.jsonl`](./x402_drainbench_ledger.jsonl) & [`verify_x402_drainbench.py`](./verify_x402_drainbench.py) — Preserved `v1.0` Zenodo ledger and standalone verifier (`Apache-2.0`).

## Scoped Engineering Reviews & Licensing (`vgrcjr@gmail.com`)
Fixed-scope reviews of buyer/facilitator `x402` & `MCP` payment integrations (intent-to-authorization binding, concurrent pre-signer budget reservation, `UNKNOWN`-state retention, and finalized-chain reconciliation against your concrete token and network).

---
*Sole Human Author: **Vander Geraldo Rodrigues da Cunha Júnior** (`CRM/MG 58.130`, Brazil — Principal, ZeroPx Core). Technical & AI-Assisted Provenance Disclosure: Auxiliary synthetic vector simulation, Z3 bit-vector checks, and `Poseidon2-Goldilocks` commitment generation were executed as subordinate computational tools under `1:1` independent human verification (`CFM Res. 2.454/2026`, Arts. 4-V & 7; `ICMJE`). Governed by Brazilian Law No. 12.965/2014 (Art. 11) & Law No. 13.810/2019.*
