"""Sponge construction on top of the Poseidon2 permutation.

`hash_no_pad` is the plonky2-style variable-input hasher: absorb
`SPONGE_RATE` (=8) field elements per permutation, squeeze
`POSEIDON2_OUTPUT` (=4) elements from the rate portion of the final
state. No padding — the caller is responsible for framing.

`hash_bytes` is a convenience: 8-bytes-per-felt little-endian
serialisation of the input, one Poseidon2 hash, 8-bytes-per-felt
little-endian serialisation of the 4-element digest back to 32 bytes.
Matches `bytes_to_digest` + `permute` + `digest_to_bytes` in the
reference qp-zk-circuits/common/src/serialization.rs — the same
composition Quantus uses to hash a header preimage.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

from .constants import (
    SPONGE_WIDTH,
    SPONGE_RATE,
    POSEIDON2_OUTPUT,
)
from .permutation import permute_mut


def hash_no_pad(inputs: Sequence[int]) -> List[int]:
    """Poseidon2 variable-input hash, no padding.

    Absorbs `inputs` `SPONGE_RATE` at a time. If the last chunk is
    partial, remaining lanes stay unchanged (that's the reference
    behaviour — the caller is expected to have done any framing they
    need before calling).

    Returns `POSEIDON2_OUTPUT` (=4) field elements from the rate lanes
    of the final state.
    """
    state: List[int] = [0] * SPONGE_WIDTH
    inputs = list(inputs)

    if not inputs:
        # Empty input: one permutation of the all-zero state, then squeeze.
        permute_mut(state)
        return state[:POSEIDON2_OUTPUT]

    for start in range(0, len(inputs), SPONGE_RATE):
        chunk = inputs[start:start + SPONGE_RATE]
        for i, v in enumerate(chunk):
            state[i] += v
        permute_mut(state)

    return state[:POSEIDON2_OUTPUT]


def _bytes_to_felts_8(data: bytes) -> List[int]:
    """Split `data` into 8-byte little-endian u64 chunks, pad zero.

    Matches `bytes_to_digest` when len(data) == 32 (4 felts). For
    inputs of any length this pads the last chunk with zero bytes so
    the field-element view is deterministic.
    """
    if len(data) % 8 != 0:
        pad = 8 - (len(data) % 8)
        data = data + b"\x00" * pad
    return [int.from_bytes(data[i:i + 8], "little") for i in range(0, len(data), 8)]


def _felts_to_bytes_8(felts: Iterable[int]) -> bytes:
    """Concatenate each felt as 8 little-endian bytes."""
    return b"".join(int(v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little") for v in felts)


def hash_bytes(data: bytes) -> bytes:
    """Hash a byte string to a 32-byte digest via the 8-bytes-per-felt route.

    This is a straight composition — `bytes -> felts` (8 bytes each,
    little-endian, zero-padded), Poseidon2 `hash_no_pad`, `felts -> bytes`
    (canonical u64, 8 bytes each, little-endian). It matches what the
    Quantus wormhole aggregator does for its header preimage; use it
    when you want cross-check parity with the Rust reference.

    Any 8-byte little-endian chunk of `data` that decodes to a u64
    >= GOLDILOCKS_PRIME will be reduced silently — this is the exact
    non-canonicality caveat documented in qp-poseidon-core; guards at
    higher layers (e.g. `BytesDigest::try_from`) should reject
    non-canonical input before calling this if they need injectivity.
    """
    felts = _bytes_to_felts_8(data)
    digest = hash_no_pad(felts)
    return _felts_to_bytes_8(digest)
