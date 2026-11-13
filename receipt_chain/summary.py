"""Cross-package Poseidon2 Merkle summary for a receipt-chain ledger.

This is an OPTIONAL feature. It requires the sibling package
`poseidon2-goldilocks` to be installed. Install both with:

    pip install receipt-chain[poseidon2]

or:

    pip install receipt-chain poseidon2-goldilocks

The idea: each ledger entry already carries a `entry_sha256` (32
bytes). Hash-chaining those into a single "batch commitment" via a
Poseidon2 Merkle tree gives you a succinct root that:

- Can be anchored externally (via `seal_ledger(external_anchor=root)`).
- Lets you prove membership of any historical entry with a
  logarithmic-size inclusion proof.
- Is byte-for-byte compatible with the Plonky2 / Quantus ecosystem, so
  the same commitment can be verified by a Rust prover.

This module wraps that composition. The dependency stays optional so
receipt-chain proper remains zero-dep.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Tuple

from .ledger import read_entries, verify_ledger


def _entry_hash_to_leaf(entry_hash_hex: str) -> Tuple[int, int, int, int]:
    """Convert a 64-hex-char SHA-256 into a 4-felt Poseidon2 digest.

    Interprets the 32 bytes as four little-endian u64 limbs — the same
    encoding qp-poseidon-core uses for `bytes_to_digest`. Two entries
    with the same SHA-256 produce the same leaf; two distinct hashes
    always produce distinct leaves (SHA-256's 32-byte space is well
    below the (2^64)^4 field-element space, so injectivity is not at
    risk here).
    """
    b = bytes.fromhex(entry_hash_hex)
    if len(b) != 32:
        raise ValueError(f"entry hash must decode to 32 bytes, got {len(b)}")
    return tuple(  # type: ignore[return-value]
        int.from_bytes(b[i : i + 8], "little") for i in range(0, 32, 8)
    )


def _leaf_to_hex(leaf: Tuple[int, int, int, int]) -> str:
    """Serialise a 4-felt digest back to a 64-hex-char string, LE per felt.

    Applies canonical u64 masking so a non-canonical (>= p) felt still
    round-trips to a well-defined 32-byte value.
    """
    return b"".join(
        int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") for v in leaf
    ).hex()


def poseidon2_batch_summary(path: Path) -> dict[str, Any]:
    """Compute the Poseidon2 binary-Merkle root over the ledger's entry hashes.

    Requires `poseidon2-goldilocks`. Returns a summary dict:

    - `entry_count`: number of entries in the ledger.
    - `head_entry_sha256`: SHA-256 of the last entry (or None for empty).
    - `poseidon2_merkle_root_hex`: 64-char lowercase hex of the Poseidon2
      root, encoded 8 bytes per felt in little-endian.
    - `poseidon2_merkle_root_felts`: the 4 raw felt values (list of int).
    - `chain_valid`: True — the ledger is verified as a precondition;
      this call raises if the chain is broken.

    Building the tree first calls `verify_ledger(path)` — you cannot
    summarise a tampered ledger.
    """
    try:
        from poseidon2_goldilocks import merkle_root
    except ImportError as exc:  # noqa: F841
        raise ImportError(
            "poseidon2-goldilocks is required for the batch summary. "
            "Install with: pip install receipt-chain[poseidon2]"
        ) from exc

    summary = verify_ledger(path)  # raises on tamper
    entries = read_entries(path)

    if not entries:
        # Empty ledger — return an empty summary rather than a coerced root
        return {
            "operation": "poseidon2_batch_summary",
            "entry_count": 0,
            "head_entry_sha256": None,
            "poseidon2_merkle_root_hex": None,
            "poseidon2_merkle_root_felts": None,
            "chain_valid": True,
        }

    leaves = [_entry_hash_to_leaf(e["entry_sha256"]) for e in entries]
    root = merkle_root(leaves)
    root_hex = _leaf_to_hex(tuple(root))  # type: ignore[arg-type]

    return {
        "operation": "poseidon2_batch_summary",
        "entry_count": summary["entry_count"],
        "head_entry_sha256": summary["head_entry_sha256"],
        "poseidon2_merkle_root_hex": root_hex,
        "poseidon2_merkle_root_felts": list(root),
        "chain_valid": True,
    }


def poseidon2_inclusion_proof(
    path: Path, sequence: int
) -> dict[str, Any]:
    """Generate a Poseidon2 Merkle inclusion proof for the entry at `sequence`.

    Requires `poseidon2-goldilocks`. Returns:

    - `sequence`: the requested sequence number.
    - `entry_sha256`: the entry's own hash (for the caller's records).
    - `leaf_felts`: the 4-felt Poseidon2 leaf derived from that hash.
    - `proof`: authentication path as `[[sibling_felts, "L"|"R"], ...]`,
      the same shape `poseidon2_goldilocks.verify_merkle_proof` expects.
    - `root_hex`: the batch root the proof was generated against.

    Verify the returned proof standalone with:

        from poseidon2_goldilocks import verify_merkle_proof
        assert verify_merkle_proof(
            root=proof["root_felts"],
            leaf=proof["leaf_felts"],
            proof=proof["proof"],
            index=proof["sequence"],
        )

    Chain integrity is verified before proof generation — a broken
    chain raises.
    """
    try:
        from poseidon2_goldilocks import merkle_root, merkle_proof
    except ImportError as exc:  # noqa: F841
        raise ImportError(
            "poseidon2-goldilocks is required for inclusion proofs. "
            "Install with: pip install receipt-chain[poseidon2]"
        ) from exc

    verify_ledger(path)
    entries = read_entries(path)
    if not (0 <= sequence < len(entries)):
        raise IndexError(
            f"sequence {sequence} out of range for {len(entries)} entries"
        )

    leaves = [_entry_hash_to_leaf(e["entry_sha256"]) for e in entries]
    root = merkle_root(leaves)
    root_hex = _leaf_to_hex(tuple(root))  # type: ignore[arg-type]
    path_entries = merkle_proof(leaves, sequence)

    return {
        "operation": "poseidon2_inclusion_proof",
        "sequence": sequence,
        "entry_sha256": entries[sequence]["entry_sha256"],
        "leaf_felts": list(leaves[sequence]),
        "proof": [
            [list(sib), side] for (sib, side) in path_entries
        ],
        "root_hex": root_hex,
        "root_felts": list(root),
    }
