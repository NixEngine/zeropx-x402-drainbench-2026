"""Canonical hashing and single-event validation.

The whole design pivots on `canonical_bytes` being deterministic across
platforms and Python versions: same dict in → same bytes out → same
hash. Deviate from this and the whole chain-verify contract breaks.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence


class LedgerError(Exception):
    """Base error for anything wrong with a ledger file or its entries."""


class EventError(LedgerError):
    """Raised when a single event fails validation."""


REQUIRED_EVENT_FIELDS = ("event_id", "observed_at_utc")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Deterministic JSON encoding suitable for hashing.

    ASCII-safe, minimal separators, keys sorted. The exact bytes fed
    into `content_sha256`. Two different processes on two different
    hosts must be able to produce these same bytes from the same dict.
    """
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def content_sha256(value: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of the canonical encoding of `value`."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def is_sha256_hex(value: object) -> bool:
    """True iff `value` is a str of exactly 64 lowercase hex characters."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def validate_event(
    event: Mapping[str, Any],
    required: Sequence[str] = (),
    tag: str | None = None,
) -> dict[str, Any]:
    """Return a copy of `event` if it passes validation, else raise EventError.

    Rules:
    - `event_id` and `observed_at_utc` are always required (base fields).
    - `receipt_sha256`, if present, MUST equal `content_sha256(event
      minus receipt_sha256)`. It is the event's self-signature.
    - If the event has no `receipt_sha256` it is stamped with one.
    - Every `*_sha256` field must be lowercase 64-hex.
    - Each name in `required` must be a non-empty field of the event.
    - If `tag` is given, the event must carry `ledger_tag: <tag>` OR
      have no `ledger_tag` at all (in which case one is stamped in).

    Returns the validated event dict (a copy, with `receipt_sha256`
    and possibly `ledger_tag` filled in).
    """
    value = dict(event)

    for base in REQUIRED_EVENT_FIELDS:
        if not value.get(base):
            raise EventError(f"missing base event field: {base}")

    for name in required:
        if name not in value or value[name] in (None, "", [], {}):
            raise EventError(f"missing required field: {name}")

    if tag is not None:
        existing = value.get("ledger_tag")
        if existing is None:
            value["ledger_tag"] = tag
        elif existing != tag:
            raise EventError(
                f"event ledger_tag {existing!r} does not match ledger tag {tag!r}"
            )

    for k, v in value.items():
        # `_sha256` fields must be lowercase 64-hex when present. An
        # explicit `None` is allowed and treated as "field not applicable
        # yet" — e.g. a seal event over an empty ledger records
        # `sealed_head_sha256: null` because there is nothing to seal.
        if k.endswith("_sha256") and k != "receipt_sha256" and v is not None:
            if not is_sha256_hex(v):
                raise EventError(f"{k} must be lowercase 64-hex SHA-256")

    claimed = value.pop("receipt_sha256", None)
    computed = content_sha256(value)
    if claimed is not None and claimed != computed:
        raise EventError("event receipt mismatch")
    value["receipt_sha256"] = computed
    return value
