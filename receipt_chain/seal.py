"""Segment sealing — freeze the ledger head at a point in time.

A "seal" is a specially-shaped event appended to the ledger that
records the ledger's own head-hash at the moment of sealing, plus an
optional externally-supplied anchor (e.g. an OpenTimestamps proof, a
git commit SHA, an RFC-3161 tsr token, a blockchain txid, a signed
email you sent yourself). Once a seal is appended, everything BEFORE
it is provably older than the anchor.

The anchor value is opaque to this module — receipt-chain does not
know or care what kind of external commitment you made. It just
records the bytes, keys the seal on `sealed_head_sha256`, and lets you
enumerate seals later so you can prove "here's what the ledger looked
like when I published hash X".

## Event shape

A seal is stored as a normal ledger entry whose `event` looks like:

    {
        "event_id":         "seal-<sealed_head_sha256[:16]>-<recorded_at_utc>",
        "observed_at_utc":  <ISO-8601>,
        "kind":             "seal",
        "sealed_head_sha256": <the entry_sha256 of the entry BEFORE this seal>,
        "sealed_at_sequence": <sequence of the entry BEFORE this seal>,
        "external_anchor":  <caller-supplied dict or null>,
        "receipt_sha256":   <auto>,
    }

`sealed_head_sha256` is always the head-hash *at the moment sealing
was requested* — i.e. before this seal itself was appended.
`sealed_at_sequence` is the sequence number of that head entry
(0-indexed; `None` for a seal appended to an empty ledger).

Sealing an empty ledger is allowed — it just records
`sealed_head_sha256: null` and lets you attach an anchor to the
"nothing has happened yet" state.

## What sealing does NOT do

- It doesn't call any external service. If you want an
  OpenTimestamps proof, you compute it yourself and pass the bytes
  as `external_anchor={"kind": "ots", "bytes_hex": "..."}`.
- It doesn't prevent further appends after the seal. The chain
  keeps going. To prove a document existed by a certain moment,
  point to the seal and its anchor, then walk from sequence 0 to
  `sealed_at_sequence`.
- It doesn't detach or archive the pre-seal segment. See
  `export_segment` (not yet implemented; v0.3+).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Optional

from .core import LedgerError
from .ledger import append_event, read_entries, verify_ledger


def seal_ledger(
    path: Path,
    tag: str | None = None,
    external_anchor: Optional[Mapping[str, Any]] = None,
    recorded_at_utc: str | None = None,
) -> dict[str, Any]:
    """Append a `kind: "seal"` event that freezes the current head.

    - If the ledger already has at least one entry, `sealed_head_sha256`
      is set to that entry's `entry_sha256`; `sealed_at_sequence` is
      that entry's `sequence`.
    - If the ledger is empty (or does not exist yet), both are `null`.
    - `external_anchor` is stored verbatim if provided; must be
      JSON-serialisable via canonical encoding (dict-of-strings/ints).

    Returns the appended seal entry.
    """
    entries = read_entries(path)
    if entries:
        # Verify chain integrity before sealing — refuse to seal a broken chain.
        verify_ledger(path, tag=tag)
        head_entry = entries[-1]
        sealed_head = head_entry.get("entry_sha256")
        sealed_seq: Optional[int] = head_entry.get("sequence")
    else:
        sealed_head = None
        sealed_seq = None

    when = recorded_at_utc or datetime.now(UTC).isoformat()
    # event_id keys on head+timestamp so re-sealing the same head later gets
    # a distinct id (safe append) but sealing twice at the same instant
    # would idempotently no-op.
    ev_id_head = sealed_head[:16] if sealed_head else "genesis"
    event: dict[str, Any] = {
        "event_id": f"seal-{ev_id_head}-{when}",
        "observed_at_utc": when,
        "kind": "seal",
        "sealed_head_sha256": sealed_head,
        "sealed_at_sequence": sealed_seq,
    }
    if external_anchor is not None:
        event["external_anchor"] = dict(external_anchor)

    return append_event(
        path,
        event,
        tag=tag,
        # No `required` — the seal event is self-contained by construction.
        recorded_at_utc=when,
    )


def list_seals(path: Path) -> list[dict[str, Any]]:
    """Return every seal event in the ledger, in insertion order.

    Each element is a dict with `sequence` (the seal's own sequence in
    the chain), `sealed_head_sha256`, `sealed_at_sequence`,
    `observed_at_utc`, `external_anchor` (if present), and
    `entry_sha256` (the seal's own entry hash).

    Non-seal entries are skipped. Empty ledger returns [].
    """
    out: list[dict[str, Any]] = []
    for entry in read_entries(path):
        ev = entry.get("event", {})
        if ev.get("kind") != "seal":
            continue
        item: dict[str, Any] = {
            "sequence": entry.get("sequence"),
            "entry_sha256": entry.get("entry_sha256"),
            "sealed_head_sha256": ev.get("sealed_head_sha256"),
            "sealed_at_sequence": ev.get("sealed_at_sequence"),
            "observed_at_utc": ev.get("observed_at_utc"),
        }
        if "external_anchor" in ev:
            item["external_anchor"] = ev["external_anchor"]
        out.append(item)
    return out


def latest_seal(path: Path) -> dict[str, Any] | None:
    """Return the most-recently-appended seal, or `None` if there are none."""
    seals = list_seals(path)
    return seals[-1] if seals else None


def verify_seal_reference(
    path: Path,
    sealed_head_sha256: str,
) -> dict[str, Any]:
    """Confirm that the ledger's chain reaches `sealed_head_sha256`.

    Walks entries in order and returns a summary once the target hash
    is found. Raises `LedgerError` if:
    - the ledger fails standard chain verification, OR
    - the hash is never seen among any entry_sha256.

    Useful when you have only the seal's head hash (e.g. published it
    externally) and want to prove that this ledger is the one that
    produced it.
    """
    summary = verify_ledger(path)  # will raise on tamper
    for entry in read_entries(path):
        if entry.get("entry_sha256") == sealed_head_sha256:
            return {
                "chain_valid": True,
                "sealed_head_sha256": sealed_head_sha256,
                "found_at_sequence": entry.get("sequence"),
                "entry_count": summary["entry_count"],
                "current_head_sha256": summary["head_entry_sha256"],
            }
    raise LedgerError(
        f"sealed_head_sha256 {sealed_head_sha256!r} not found in ledger"
    )
