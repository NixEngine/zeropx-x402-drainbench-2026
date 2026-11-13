#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""x402-DrainBench-2026 — Public Verifier-Only Conformance & Receipt Auditor.

Mathematically verifies the SHA-256 hash chain (`zeropx-receipt-chain`) and the
Plonky2-compatible Poseidon2-Goldilocks Merkle root & human sign-off inclusion
proof (`zeropx-poseidon2-goldilocks`) for `x402-DrainBench-2026` (12 benign
diagnostic conformance vectors across 8 Agentic Treasury Exposure Classes).

NOTE (0.00% Enforcement Disclosure):
    This script is strictly a cryptographic receipt and diagnostic vector
    verifier. The native ZeroPx C++20 PEP R35 CircuitBreaker Enterprise
    pre-settlement enforcement engine is a commercial asset (vgrcjr@gmail.com).

Sole Human Author & Signatory:
    Dr. Vander Geraldo Rodrigues da Cunha Júnior, M.D. (CRM/MG 58.130)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
for _local_src in (
    HERE.parent.parent / "AGY_48H_VITRINE_PYPI_E_CHECKOUT" / "staged_sources" / "poseidon2_goldilocks" / "src",
    HERE.parent.parent / "AGY_48H_VITRINE_PYPI_E_CHECKOUT" / "staged_sources" / "receipt_chain" / "src",
):
    if _local_src.exists() and str(_local_src) not in sys.path:
        sys.path.insert(0, str(_local_src))

from poseidon2_goldilocks import verify_merkle_proof  # noqa: E402
from receipt_chain import verify_ledger  # noqa: E402
from receipt_chain.summary import poseidon2_batch_summary  # noqa: E402

VECTORS_JSON = HERE / "x402_drainbench_2026_diagnostic_vectors.json"
LEDGER_JSONL = HERE / "x402_drainbench_ledger.jsonl"


def audit_x402_drainbench() -> dict[str, Any]:
    doc = json.loads(VECTORS_JSON.read_text(encoding="utf-8"))
    anchor = doc["cryptographic_ledger_anchor"]
    proof = anchor["human_signoff_merkle_inclusion_proof"]

    ledger_status = verify_ledger(LEDGER_JSONL)
    batch = poseidon2_batch_summary(LEDGER_JSONL)
    chain_ok = bool(ledger_status.get("chain_valid", ledger_status.get("ok", batch.get("chain_valid", False))))
    inclusion_ok = bool(
        verify_merkle_proof(
            root=proof["root_felts"],
            leaf=proof["leaf_felts"],
            proof=proof["proof"],
            index=proof["sequence"],
        )
    )
    root_match = batch["poseidon2_merkle_root_hex"] == anchor["post_seal_poseidon2_merkle_root"]

    vectors = doc["diagnostic_vectors"]
    exposure_vectors = [v for v in vectors if v["conformance_role"] == "TREASURY_EXPOSURE_AUDIT"]
    baseline_vectors = [v for v in vectors if v["conformance_role"] == "CONFORMANT_BASELINE"]

    all_ok = (
        chain_ok
        and inclusion_ok
        and root_match
        and len(vectors) == 12
        and len(baseline_vectors) == 4
        and len(exposure_vectors) == 8
    )

    return {
        "verification_status": "MATHEMATICALLY_VERIFIED" if all_ok else "FAILED",
        "benchmark_id": doc["benchmark_id"],
        "sole_human_author": doc["sole_human_author"],
        "ledger_entry_count": batch["entry_count"],
        "sha256_hash_chain_valid": chain_ok,
        "post_seal_poseidon2_merkle_root": batch["poseidon2_merkle_root_hex"],
        "human_signoff_inclusion_proof_valid": inclusion_ok,
        "diagnostic_vectors_verified": len(vectors),
        "treasury_exposure_classes_verified": len(exposure_vectors),
        "unprotected_default_stack_score": doc["comparative_scorecard"]["unprotected_default_stack_score"],
        "zeropx_enterprise_pep_score": doc["comparative_scorecard"]["zeropx_enterprise_pep_r35_score"],
        "sustained_throughput_ops_per_sec": doc["comparative_scorecard"]["endurance_benchmark_metrics"]["sustained_throughput_ops_per_sec"],
        "latency_p99_ms": doc["comparative_scorecard"]["endurance_benchmark_metrics"]["latency_p99_ms"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify x402-DrainBench-2026 cryptographic receipts")
    parser.add_argument("--self-test", action="store_true", help="Run deterministic cryptographic self-test")
    parser.add_argument("--vector", type=str, default="", help="Inspect a specific vector ID (e.g., SV-05 or EC-01)")
    args = parser.parse_args()

    result = audit_x402_drainbench()
    if args.vector:
        doc = json.loads(VECTORS_JSON.read_text(encoding="utf-8"))
        q = args.vector.strip().upper()
        matches = [
            v for v in doc["diagnostic_vectors"]
            if v["vector_id"].upper() == q or v.get("exposure_class_id", "").upper() == q
        ]
        print(json.dumps({"audit_summary": result, "matched_vectors": matches}, indent=2, ensure_ascii=False))
        return 0 if matches and result["verification_status"] == "MATHEMATICALLY_VERIFIED" else 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.self_test and result["verification_status"] != "MATHEMATICALLY_VERIFIED":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
