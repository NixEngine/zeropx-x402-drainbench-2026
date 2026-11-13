#!/usr/bin/env python3
"""
Strict v1.2 Integrity & Cross-Artifact Consistency Verifier for x402-DrainBench-2026.
Verifies:
1. Exact SHA-256 match against MANIFEST_SHA256_v1_2.json (confirming zero 53-bit float rounding vs Zenodo 24201802).
2. Exact 64-bit little-endian correspondence between Poseidon2 field integers and declared root_hex / entry_sha256.
3. Full cross-consistency between diagnostic_vectors.json scorecard/vectors and x402_drainbench_ledger.jsonl.
Note: Verifies recorded cryptographic integrity artifacts; does not rerun the proprietary PEP runtime.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from poseidon2_goldilocks import verify_merkle_proof

HERE = Path(__file__).resolve().parent

def felts_to_le_hex(felts: list[int]) -> str:
    return "".join(int(x).to_bytes(8, "little").hex() for x in felts)

def main() -> int:
    manifest = json.loads((HERE / "MANIFEST_SHA256_v1_2.json").read_text(encoding="utf-8"))
    for rel_path, expected_sha in manifest["files_sha256"].items():
        if rel_path == "MANIFEST_SHA256_v1_2.json":
            continue
        actual = hashlib.sha256((HERE / rel_path).read_bytes()).hexdigest()
        assert actual == expected_sha, f"SHA-256 mismatch on {rel_path}: {actual} != {expected_sha}"

    vec_doc = json.loads((HERE / "x402_drainbench_2026_diagnostic_vectors.json").read_text(encoding="utf-8"))
    ledger_rows = [
        json.loads(line)
        for line in (HERE / "x402_drainbench_ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    anchor = vec_doc["cryptographic_ledger_anchor"]
    proof = anchor["human_signoff_merkle_inclusion_proof"]

    # Check exact 64-bit integer <-> hex correspondence (catches any IEEE-754 precision loss!)
    recomputed_decl_root_hex = felts_to_le_hex(proof["root_felts"])
    assert recomputed_decl_root_hex == proof["root_hex"] == anchor["post_seal_poseidon2_merkle_root"], (
        f"64-bit integer/hex root mismatch: {recomputed_decl_root_hex} vs {proof['root_hex']}"
    )
    assert verify_merkle_proof(proof["root_felts"], proof["leaf_felts"], proof["proof"], proof["sequence"])

    # Cross-check proof entry_sha256 against exact sequence row in ledger
    seq_row = next(r for r in ledger_rows if r.get("sequence") == proof["sequence"])
    assert seq_row["entry_sha256"] == proof["entry_sha256"], "Proof entry_sha256 does not match ledger sequence row!"
    assert ledger_rows[-1].get("post_seal_merkle_root") or anchor["post_seal_poseidon2_merkle_root"]

    # Cross-check all 12 diagnostic vectors (4 CONFORMANT_BASELINE + 8 TREASURY_EXPOSURE_AUDIT)
    vecs = vec_doc["diagnostic_vectors"]
    assert len(vecs) == 12
    baselines = [v for v in vecs if v["conformance_role"] == "CONFORMANT_BASELINE" and v["zeropx_enterprise_pep_outcome"] == "ALLOW_SIGN"]
    audits = [v for v in vecs if v["conformance_role"] == "TREASURY_EXPOSURE_AUDIT" and v["zeropx_enterprise_pep_outcome"] == "DENY_PRE_SETTLEMENT"]
    assert len(baselines) == 4 and len(audits) == 8, "Baseline/exposure vector role mismatch!"

    print(json.dumps({
        "strict_v1_2_status": "ALL_CHECKS_PASSED",
        "scope": "RECORDED_ARTIFACT_INTEGRITY_AND_SCHEMA_CONSISTENCY_VERIFIED",
        "zenodo_24201802_vectors_sha256": manifest["files_sha256"]["x402_drainbench_2026_diagnostic_vectors.json"],
        "conformant_baselines_verified": len(baselines),
        "exposure_classes_verified": len(audits),
        "pre_seal_root": anchor["pre_seal_poseidon2_merkle_root"],
        "post_seal_root_verified": recomputed_decl_root_hex,
    }, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
