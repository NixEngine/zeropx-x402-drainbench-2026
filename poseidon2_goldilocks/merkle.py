"""Binary Merkle tree over Poseidon2 digests.

A digest here is a length-4 tuple of Goldilocks field elements — the
same 256-bit output shape that `hash_no_pad` and `hash_bytes` produce.
The tree pads to the next power of two with a fixed "empty" digest
(all zero) so proofs have constant length for a fixed leaf-count
target.

The intended use is auditor-side: verify someone else's Merkle
inclusion proof against an announced root, without loading a Rust
prover. Building trees over millions of leaves in pure Python is slow;
this module is not aimed at that.

## Layout

- Leaves are digests: `list[tuple[int, int, int, int]]`, length is any
  positive integer up to 2^32.
- The tree height is `ceil(log2(len(leaves)))` — the tree is padded to
  the next power of two with `EMPTY_DIGEST` so pair-hashing is
  well-defined at every level.
- `merkle_proof(leaves, index)` returns the authentication path: a list
  of `(sibling, side)` where `side` is `"L"` or `"R"` indicating
  whether the sibling sits on the left or the right of the current node
  as you walk toward the root.
- `verify_merkle_proof(root, leaf, proof, index)` re-derives the root
  by pair-hashing along the path and compares. `index` is redundant
  given `side` labels, but is validated for consistency.

## Domain separation

`hash_pair` concatenates left+right (each 4 felts) into an 8-felt input
and squeezes 4 felts back. It uses `hash_no_pad` — so it shares the
sponge behaviour with `hash_no_pad([felts])` for other 8-felt inputs.
If your protocol needs stricter domain separation between "leaf" and
"internal-node" hashes, prefix your leaves with a distinct tag before
computing their digests and let the internal-node hash of two "tagged"
digests stay untagged. This module deliberately does not bake in a
tagging scheme — the community disagrees on which one to pick, and the
choice is protocol-level, not primitive-level.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

from .constants import POSEIDON2_OUTPUT
from .sponge import hash_no_pad


Digest = Tuple[int, int, int, int]

EMPTY_DIGEST: Digest = (0, 0, 0, 0)


def _to_digest(x: Sequence[int]) -> Digest:
    """Coerce a length-4 iterable to a tuple, raising if the shape is wrong."""
    t = tuple(int(v) for v in x)
    if len(t) != POSEIDON2_OUTPUT:
        raise ValueError(
            f"digest must have {POSEIDON2_OUTPUT} elements, got {len(t)}"
        )
    return t  # type: ignore[return-value]


def hash_pair(left: Sequence[int], right: Sequence[int]) -> Digest:
    """Hash two 4-element digests into a single 4-element digest.

    Concatenates the eight input felts left-then-right and squeezes
    four felts via `hash_no_pad`.
    """
    l = _to_digest(left)
    r = _to_digest(right)
    combined = list(l) + list(r)
    return tuple(hash_no_pad(combined))  # type: ignore[return-value]


def _next_pow2(n: int) -> int:
    """Smallest power of two >= max(n, 1). `_next_pow2(0) == 1`."""
    if n <= 1:
        return 1
    return 1 << (n - 1).bit_length()


def _pad_leaves(leaves: Sequence[Sequence[int]]) -> List[Digest]:
    """Coerce every leaf to a digest tuple and pad to the next power of two."""
    if len(leaves) == 0:
        return [EMPTY_DIGEST]
    coerced = [_to_digest(l) for l in leaves]
    target = _next_pow2(len(coerced))
    while len(coerced) < target:
        coerced.append(EMPTY_DIGEST)
    return coerced


def merkle_root(leaves: Sequence[Sequence[int]]) -> Digest:
    """Compute the Merkle root of `leaves`.

    Leaves are padded to the next power of two with `EMPTY_DIGEST`.
    An empty leaf list returns `hash_pair(EMPTY_DIGEST, EMPTY_DIGEST)`
    — the root of the smallest well-defined tree. (The single-leaf
    tree also returns `hash_pair(leaf, EMPTY_DIGEST)` for the same
    reason: every valid tree has at least one pairing.)

    Wait — that's a hazard. Reconsidered: a single-leaf tree
    conventionally returns the leaf itself. This module follows the
    convention `merkle_root([leaf]) == leaf` because it matches what a
    verifier who receives an empty proof list for a single-leaf tree
    expects. The `_pad_leaves` step therefore only kicks in for
    `len(leaves) >= 2`.
    """
    if len(leaves) == 0:
        # Empty tree: return the pair of two empty digests. Uncommon case;
        # documented so callers can special-case it if they prefer.
        return hash_pair(EMPTY_DIGEST, EMPTY_DIGEST)
    if len(leaves) == 1:
        return _to_digest(leaves[0])

    level = _pad_leaves(leaves)
    while len(level) > 1:
        next_level: List[Digest] = []
        for i in range(0, len(level), 2):
            next_level.append(hash_pair(level[i], level[i + 1]))
        level = next_level
    return level[0]


def merkle_proof(
    leaves: Sequence[Sequence[int]], index: int
) -> List[Tuple[Digest, str]]:
    """Return the authentication path for the leaf at `index`.

    Each path element is `(sibling_digest, side)` where `side` is
    `"L"` (the sibling is to the LEFT of the current node) or `"R"`
    (the sibling is to the RIGHT).

    For a single-leaf tree the path is empty (no siblings to hash
    with). For an empty tree, `IndexError`.
    """
    if len(leaves) == 0:
        raise IndexError("cannot generate a proof for an empty tree")
    if not (0 <= index < len(leaves)):
        raise IndexError(
            f"index {index} out of range for {len(leaves)} leaves"
        )
    if len(leaves) == 1:
        return []

    level = _pad_leaves(leaves)
    cur = index
    path: List[Tuple[Digest, str]] = []

    while len(level) > 1:
        # Sibling index: if `cur` is even, sibling is on the right;
        # if `cur` is odd, sibling is on the left.
        if cur % 2 == 0:
            sibling = level[cur + 1]
            side = "R"
        else:
            sibling = level[cur - 1]
            side = "L"
        path.append((sibling, side))
        # Move up
        next_level = [
            hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
        level = next_level
        cur //= 2

    return path


def verify_merkle_proof(
    root: Sequence[int],
    leaf: Sequence[int],
    proof: Sequence[Tuple[Sequence[int], str]],
    index: int,
) -> bool:
    """Verify that `leaf` is at position `index` in a tree with root `root`.

    Re-derives the root by pair-hashing `leaf` with each proof sibling
    in order, folding the `"L"`/`"R"` labels to place the sibling on
    the correct side at each level. Returns `True` iff the recomputed
    root matches the announced one.

    `index` is validated against the `side` labels — if bit `i` of
    `index` disagrees with `proof[i].side`, the proof is rejected. This
    catches proofs generated for a different position that would
    otherwise hash to the same root by coincidence.
    """
    r_target = _to_digest(root)
    current = _to_digest(leaf)

    for i, (sibling_raw, side) in enumerate(proof):
        sibling = _to_digest(sibling_raw)
        bit = (index >> i) & 1
        if side == "R":
            if bit != 0:
                return False  # index says we should be the right child, side disagrees
            current = hash_pair(current, sibling)
        elif side == "L":
            if bit != 1:
                return False
            current = hash_pair(sibling, current)
        else:
            raise ValueError(f"side at level {i} must be 'L' or 'R', got {side!r}")

    return current == r_target
