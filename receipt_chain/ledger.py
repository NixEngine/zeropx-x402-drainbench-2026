"""Append-only, hash-chained JSON-lines ledger.

Storage model:
- One JSON entry per line, UTF-8-safe ASCII, LF-terminated.
- Each entry has: `sequence` (0-indexed), `previous_entry_sha256`,
  `recorded_at_utc`, `event`, and `entry_sha256` (self-hash).
- Optional `ledger_tag` scopes the ledger; verify enforces it.
- Append is atomic (fsync); verify walks the whole file.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .core import (
    content_sha256,
    validate_event,
    LedgerError,
)


SCHEMA_VERSION = "1.0"


def read_entries(path: Path) -> list[dict[str, Any]]:
    """Parse every JSON line of `path` into a list of dicts.

    Non-existent path returns []. Blank lines are skipped. A malformed
    line raises `LedgerError` with the 1-indexed line number.
    """
    if not path.exists():
        return []
    entries: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise LedgerError(f"invalid JSON at line {line_number}: {e}") from e
    return entries


def verify_ledger(
    path: Path,
    tag: str | None = None,
    required: Sequence[str] = (),
) -> dict[str, Any]:
    """Verify every entry hash, chain link, and sequence in `path`.

    Returns a summary dict:
    - schema_version, operation, tag, entry_count, head_entry_sha256,
      chain_valid, receipt_sha256

    Raises `LedgerError` at the first inconsistency (entry-hash
    mismatch, chain break, sequence gap, duplicate event, tag mismatch,
    or event validation failure).
    """
    entries = read_entries(path)
    previous: str | None = None
    seen_receipts: set[str] = set()
    for index, entry in enumerate(entries):
        claimed_entry_hash = entry.get("entry_sha256")
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        computed_entry_hash = content_sha256(body)
        if claimed_entry_hash != computed_entry_hash:
            raise LedgerError(f"entry hash mismatch at sequence {index}")
        if entry.get("sequence") != index:
            raise LedgerError(f"sequence mismatch at sequence {index}")
        if entry.get("previous_entry_sha256") != previous:
            raise LedgerError(f"chain break at sequence {index}")
        if tag is not None and entry.get("ledger_tag") != tag:
            raise LedgerError(
                f"ledger_tag mismatch at sequence {index}: "
                f"expected {tag!r}, got {entry.get('ledger_tag')!r}"
            )
        validated = validate_event(entry.get("event", {}), required=required, tag=tag)
        if validated["receipt_sha256"] in seen_receipts:
            raise LedgerError(f"duplicate event receipt at sequence {index}")
        seen_receipts.add(validated["receipt_sha256"])
        previous = claimed_entry_hash

    result = {
        "schema_version": SCHEMA_VERSION,
        "operation": "verify_ledger",
        "tag": tag,
        "entry_count": len(entries),
        "head_entry_sha256": previous,
        "chain_valid": True,
    }
    result["receipt_sha256"] = content_sha256(result)
    return result


def append_event(
    path: Path,
    event: Mapping[str, Any],
    tag: str | None = None,
    required: Sequence[str] = (),
    recorded_at_utc: str | None = None,
) -> dict[str, Any]:
    """Validate `event`, verify existing chain, atomically append one entry.

    Idempotency:
    - If an existing entry has the same event.receipt_sha256, that
      entry is returned untouched (no duplicate append).
    - If an existing entry has the same event.event_id but a DIFFERENT
      receipt, `LedgerError` is raised (event_id reuse forbidden).

    Returns the entry that is now in the ledger (either the pre-existing
    duplicate or the newly appended one).
    """
    validated = validate_event(event, required=required, tag=tag)

    path.parent.mkdir(parents=True, exist_ok=True)
    entries = read_entries(path)
    if entries:
        verify_ledger(path, tag=tag, required=required)

    for existing in entries:
        ev = existing.get("event", {})
        if ev.get("receipt_sha256") == validated["receipt_sha256"]:
            return existing
        if ev.get("event_id") == validated["event_id"]:
            raise LedgerError(
                f"event_id reuse with different receipt: {validated['event_id']!r}"
            )

    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "sequence": len(entries),
        "previous_entry_sha256": entries[-1]["entry_sha256"] if entries else None,
        "recorded_at_utc": recorded_at_utc or datetime.now(UTC).isoformat(),
        "event": validated,
    }
    if tag is not None:
        body["ledger_tag"] = tag
    body["entry_sha256"] = content_sha256(body)

    encoded = json.dumps(body, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    with path.open("a", encoding="ascii", newline="\n") as f:
        f.write(encoded + "\n")
        f.flush()
        os.fsync(f.fileno())
    return body
