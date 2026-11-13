"""poseidon2-goldilocks — pure-Python Poseidon2 over the Goldilocks field (width=12).

Byte-for-byte compatible with the qp-poseidon-core v3.1.0 reference
used by Plonky2 and the Quantus Substrate runtime. Zero runtime
dependencies. Pure Python — no C extensions, no `galois`, no
`numpy`. Intended for auditors, cross-check tooling, ZK-circuit
debugging, and light Poseidon2 use where a heavyweight FFI stack is
overkill.

Not intended as a production prover backend: pure Python is 100x-1000x
slower than an optimised Rust/C implementation. Use it to verify
someone else's output, not to prove your own.

Public API:

    from poseidon2_goldilocks import permute, hash_no_pad, GOLDILOCKS_PRIME

    # 12-element field state -> 12-element field state
    out = permute([0] * 12)

    # arbitrary field-element input -> 4-element digest
    digest = hash_no_pad([1, 2, 3, 4, 5])

    # arbitrary bytes -> 32-byte digest (8 bytes/felt, little-endian)
    from poseidon2_goldilocks import hash_bytes
    d32 = hash_bytes(b"hello world")
"""

from __future__ import annotations

__version__ = "0.2.0"

from .goldilocks import (
    GOLDILOCKS_PRIME,
    canonical,
    exp7,
    to_canonical_u64,
)
from .permutation import (
    permute,
    permute_mut,
    external_linear_layer,
    internal_linear_layer,
)
from .constants import (
    SPONGE_WIDTH,
    SPONGE_RATE,
    SPONGE_CAPACITY,
)
from .sponge import (
    hash_no_pad,
    hash_bytes,
    POSEIDON2_OUTPUT,
)
from .merkle import (
    hash_pair,
    merkle_root,
    merkle_proof,
    verify_merkle_proof,
    EMPTY_DIGEST,
)

__all__ = [
    "__version__",
    # field
    "GOLDILOCKS_PRIME",
    "canonical",
    "exp7",
    "to_canonical_u64",
    # permutation
    "permute",
    "permute_mut",
    "external_linear_layer",
    "internal_linear_layer",
    "SPONGE_WIDTH",
    "SPONGE_RATE",
    "SPONGE_CAPACITY",
    # sponge / hashing
    "hash_no_pad",
    "hash_bytes",
    "POSEIDON2_OUTPUT",
    # binary merkle tree
    "hash_pair",
    "merkle_root",
    "merkle_proof",
    "verify_merkle_proof",
    "EMPTY_DIGEST",
]
