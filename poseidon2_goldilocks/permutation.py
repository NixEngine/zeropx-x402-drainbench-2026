"""Poseidon2 permutation over the Goldilocks field, width=12.

Follows the Plonky2 reference structure exactly:

    permute(state):
        external_linear_layer(state)                # initial MDS
        for r in range(4):
            state = external_round(state, INITIAL_EXTERNAL_CONSTANTS[r])
        for r in range(22):
            state = internal_round(state, INTERNAL_CONSTANTS[r])
        for r in range(4):
            state = external_round(state, TERMINAL_EXTERNAL_CONSTANTS[r])

The external linear layer applies the 4x4 MDS matrix

    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]

to each 4-element chunk of the 12-element state, then adds the
column-sums of the chunks back into the state (the outer circulant).
The internal linear layer computes `state[i] = sum(state) + state[i]
* MATRIX_DIAG[i]`. The S-box is `x -> x^7`. See
https://eprint.iacr.org/2023/323 for the design rationale.
"""

from __future__ import annotations

from typing import List, Sequence

from .constants import (
    SPONGE_WIDTH,
    INTERNAL_ROUNDS,
    HALF_EXTERNAL_ROUNDS,
    INTERNAL_CONSTANTS,
    MATRIX_DIAG,
    INITIAL_EXTERNAL_CONSTANTS,
    TERMINAL_EXTERNAL_CONSTANTS,
)
from .goldilocks import GOLDILOCKS_PRIME, exp7


def _apply_mat4(x0: int, x1: int, x2: int, x3: int) -> tuple[int, int, int, int]:
    """Apply the 4x4 MDS matrix in one pass, matching the reference order.

    The reference implementation is careful about the order of assignments
    so `x[0]` and `x[2]` are only written after `x[1]` and `x[3]` are read.
    That same discipline is not strictly necessary in Python (we compute
    into a fresh tuple) but keeping the same intermediate names makes
    line-by-line comparison with the Rust reference straightforward.
    """
    P = GOLDILOCKS_PRIME
    t01 = (x0 + x1) % P
    t23 = (x2 + x3) % P
    t0123 = (t01 + t23) % P
    t01123 = (t0123 + x1) % P
    t01233 = (t0123 + x3) % P

    new_x3 = (t01233 + 2 * x0) % P    # 3*x0 + x1 + x2 + 2*x3
    new_x1 = (t01123 + 2 * x2) % P    # x0 + 2*x1 + 3*x2 + x3
    new_x0 = (t01123 + t01) % P        # 2*x0 + 3*x1 + x2 + x3
    new_x2 = (t01233 + t23) % P        # x0 + x1 + 2*x2 + 3*x3
    return new_x0, new_x1, new_x2, new_x3


def external_linear_layer(state: List[int]) -> None:
    """Apply the external linear layer in-place.

    Composition: `M_4 to each 4-chunk` + `add column-sums across chunks`.
    """
    P = GOLDILOCKS_PRIME
    # Apply M_4 to each 4-element chunk (three chunks: 0..4, 4..8, 8..12)
    for base in (0, 4, 8):
        state[base], state[base + 1], state[base + 2], state[base + 3] = _apply_mat4(
            state[base], state[base + 1], state[base + 2], state[base + 3]
        )

    # Compute per-column sums across the three chunks:
    # sums[k] = state[0+k] + state[4+k] + state[8+k]
    sums = [
        (state[0] + state[4] + state[8]) % P,
        (state[1] + state[5] + state[9]) % P,
        (state[2] + state[6] + state[10]) % P,
        (state[3] + state[7] + state[11]) % P,
    ]

    # Add the corresponding sum back into every element (outer circulant)
    for i in range(SPONGE_WIDTH):
        state[i] = (state[i] + sums[i & 3]) % P


def internal_linear_layer(state: List[int]) -> None:
    """Apply the internal linear layer in-place.

    `state[i] = sum(state) + state[i] * MATRIX_DIAG[i]`.
    """
    P = GOLDILOCKS_PRIME
    total = sum(state) % P
    for i in range(SPONGE_WIDTH):
        state[i] = (total + state[i] * MATRIX_DIAG[i]) % P


def _external_round(state: List[int], rc: Sequence[int]) -> None:
    """Add per-element round constants, apply x^7, then external linear layer."""
    P = GOLDILOCKS_PRIME
    for i in range(SPONGE_WIDTH):
        v = (state[i] + rc[i]) % P
        state[i] = exp7(v)
    external_linear_layer(state)


def _internal_round(state: List[int], rc: int) -> None:
    """Add round constant to state[0], apply x^7 to state[0], then internal linear layer."""
    P = GOLDILOCKS_PRIME
    state[0] = exp7((state[0] + rc) % P)
    internal_linear_layer(state)


def permute(input_state: Sequence[int]) -> List[int]:
    """Apply the Poseidon2 permutation to a 12-element input, return a new list.

    Input length must be exactly `SPONGE_WIDTH` (= 12). Each input is
    reduced mod GOLDILOCKS_PRIME on entry.
    """
    if len(input_state) != SPONGE_WIDTH:
        raise ValueError(f"Poseidon2 permute expects {SPONGE_WIDTH} elements, got {len(input_state)}")
    P = GOLDILOCKS_PRIME
    state = [(x % P) for x in input_state]

    external_linear_layer(state)

    for r in range(HALF_EXTERNAL_ROUNDS):
        _external_round(state, INITIAL_EXTERNAL_CONSTANTS[r])

    for r in range(INTERNAL_ROUNDS):
        _internal_round(state, INTERNAL_CONSTANTS[r])

    for r in range(HALF_EXTERNAL_ROUNDS):
        _external_round(state, TERMINAL_EXTERNAL_CONSTANTS[r])

    return state


def permute_mut(state: List[int]) -> None:
    """In-place variant of `permute` for callers that want to reuse a buffer."""
    if len(state) != SPONGE_WIDTH:
        raise ValueError(f"Poseidon2 permute_mut expects {SPONGE_WIDTH} elements, got {len(state)}")
    P = GOLDILOCKS_PRIME
    for i in range(SPONGE_WIDTH):
        state[i] %= P

    external_linear_layer(state)
    for r in range(HALF_EXTERNAL_ROUNDS):
        _external_round(state, INITIAL_EXTERNAL_CONSTANTS[r])
    for r in range(INTERNAL_ROUNDS):
        _internal_round(state, INTERNAL_CONSTANTS[r])
    for r in range(HALF_EXTERNAL_ROUNDS):
        _external_round(state, TERMINAL_EXTERNAL_CONSTANTS[r])
