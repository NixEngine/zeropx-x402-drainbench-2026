"""Command-line entry point for receipt-chain."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .ledger import append_event, verify_ledger
from .seal import seal_ledger, list_seals, verify_seal_reference


def _parse_required(raw: str | None) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="receipt-chain",
        description=(
            "Append-only, hash-chained JSON-lines ledger. Each entry "
            "carries its own SHA-256 and a link to the previous entry's "
            "SHA-256 — tampering with any entry breaks the chain at that "
            "point. Zero dependencies, single file per ledger."
        ),
    )
    sub = ap.add_subparsers(dest="op", required=True)

    ap_append = sub.add_parser("append", help="Append one event to the ledger")
    ap_append.add_argument("--path", required=True, type=Path, help="Ledger file path (.jsonl)")
    ap_append.add_argument("--event", required=True, type=Path, help="JSON file with the event to append")
    ap_append.add_argument("--tag", help="Optional ledger_tag scope for this ledger")
    ap_append.add_argument(
        "--required",
        help="Comma-separated required event fields (in addition to event_id, observed_at_utc)",
    )

    ap_verify = sub.add_parser("verify", help="Verify hash chain and sequence")
    ap_verify.add_argument("--path", required=True, type=Path)
    ap_verify.add_argument("--tag")
    ap_verify.add_argument("--required")

    ap_seal = sub.add_parser(
        "seal",
        help="Append a seal event that freezes the current head-hash",
    )
    ap_seal.add_argument("--path", required=True, type=Path)
    ap_seal.add_argument("--tag")
    ap_seal.add_argument(
        "--anchor-json",
        type=Path,
        help="Optional JSON file whose contents become the seal's external_anchor "
             "(e.g. an OpenTimestamps proof, an RFC-3161 tsr token, a blockchain txid)",
    )

    ap_list_seals = sub.add_parser(
        "list-seals",
        help="Enumerate every seal event in the ledger",
    )
    ap_list_seals.add_argument("--path", required=True, type=Path)

    ap_verify_seal = sub.add_parser(
        "verify-seal",
        help="Confirm that the ledger's chain contains a given head hash",
    )
    ap_verify_seal.add_argument("--path", required=True, type=Path)
    ap_verify_seal.add_argument(
        "--sealed-head",
        required=True,
        help="The entry_sha256 that was sealed / published externally",
    )

    ap_p2 = sub.add_parser(
        "poseidon2-summary",
        help="Compute the Poseidon2 Merkle root over all entry_sha256s (requires poseidon2-goldilocks)",
    )
    ap_p2.add_argument("--path", required=True, type=Path)
    ap_p2.add_argument(
        "--inclusion-of",
        type=int,
        metavar="SEQ",
        help="Also emit an inclusion proof for the entry at this sequence",
    )

    ap.add_argument("--version", action="version", version=f"receipt-chain {__version__}")
    a = ap.parse_args(argv)

    try:
        if a.op == "append":
            event = json.loads(a.event.read_text(encoding="utf-8"))
            result = append_event(
                a.path,
                event,
                tag=a.tag,
                required=_parse_required(a.required),
            )
        elif a.op == "verify":
            result = verify_ledger(
                a.path,
                tag=a.tag,
                required=_parse_required(a.required),
            )
        elif a.op == "seal":
            anchor = None
            if a.anchor_json is not None:
                anchor = json.loads(a.anchor_json.read_text(encoding="utf-8"))
                if not isinstance(anchor, dict):
                    print("error: --anchor-json must contain a JSON object", file=sys.stderr)
                    return 2
            result = seal_ledger(a.path, tag=a.tag, external_anchor=anchor)
        elif a.op == "list-seals":
            result = {"seals": list_seals(a.path)}
        elif a.op == "verify-seal":
            result = verify_seal_reference(a.path, a.sealed_head)
        elif a.op == "poseidon2-summary":
            from .summary import poseidon2_batch_summary, poseidon2_inclusion_proof
            summary_res = poseidon2_batch_summary(a.path)
            if a.inclusion_of is not None:
                inc = poseidon2_inclusion_proof(a.path, a.inclusion_of)
                result = {"summary": summary_res, "inclusion_proof": inc}
            else:
                result = summary_res
        else:
            print(f"error: unknown op {a.op!r}", file=sys.stderr)
            return 2
    except Exception as e:  # noqa: BLE001
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
