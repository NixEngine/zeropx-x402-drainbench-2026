"""receipt-chain — append-only hash-chained event ledger, zero deps.

Primitives:

- `canonical_bytes(value)` — deterministic JSON encoding (ASCII, sorted
  keys, minimal separators). What goes into the SHA-256.
- `content_sha256(value)` — canonical SHA-256 hex digest.
- `is_sha256_hex(value)` — lowercase 64-hex-char validator.
- `validate_event(event, required=(), tag=None)` — sanity + own-receipt
  check on one event dict.

Ledger operations:

- `append_event(path, event, tag=None, required=(), recorded_at_utc=None)`
  — atomic fsync append, enforces sequence, previous-hash chain, and no
  duplicate event receipts.
- `verify_ledger(path, tag=None, required=())` — walk every entry, check
  every hash + chain + sequence, return summary receipt.
- `read_entries(path)` — parse every JSON-line entry (no verification).

All state lives in a single UTF-8 JSON-lines file. No database, no
schema server, no external dependencies. Suitable for CI audit trails,
compliance evidence, tamper-evident event logs shipped alongside code.
"""

from .core import (
    canonical_bytes,
    content_sha256,
    is_sha256_hex,
    validate_event,
    EventError,
    LedgerError,
)
from .ledger import append_event, verify_ledger, read_entries
from .seal import seal_ledger, list_seals, latest_seal, verify_seal_reference

__version__ = "0.3.0"
__all__ = [
    "canonical_bytes",
    "content_sha256",
    "is_sha256_hex",
    "validate_event",
    "append_event",
    "verify_ledger",
    "read_entries",
    "seal_ledger",
    "list_seals",
    "latest_seal",
    "verify_seal_reference",
    "EventError",
    "LedgerError",
    "__version__",
]
