"""Arithmetic over the Goldilocks prime field.

The Goldilocks prime is p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001.

This module implements just enough field arithmetic to run the
Poseidon2 permutation: addition, multiplication, seventh power,
double, and a canonical-form projection. Everything is expressed as
plain Python ints and uses `% GOLDILOCKS_PRIME` for reduction. No
external dependencies, no assumptions beyond Python's arbitrary
precision ints.

Values used inside the permutation are ALWAYS reduced to
`[0, GOLDILOCKS_PRIME)` before being returned or stored, so
`poseidon2` observers can compare with the reference implementation's
canonical-u64 output without additional normalisation.
"""

from __future__ import annotations

GOLDILOCKS_PRIME: int = (1 << 64) - (1 << 32) + 1  # 0xFFFFFFFF00000001


def canonical(x: int) -> int:
    """Return the canonical representative of `x` mod GOLDILOCKS_PRIME."""
    r = x % GOLDILOCKS_PRIME
    if r < 0:
        r += GOLDILOCKS_PRIME
    return r


def add(a: int, b: int) -> int:
    return (a + b) % GOLDILOCKS_PRIME


def sub(a: int, b: int) -> int:
    return (a - b) % GOLDILOCKS_PRIME


def mul(a: int, b: int) -> int:
    return (a * b) % GOLDILOCKS_PRIME


def double(a: int) -> int:
    return (a + a) % GOLDILOCKS_PRIME


def exp7(a: int) -> int:
    """Compute a^7 mod p. The Poseidon2 S-box.

    Implemented as `a * a` cubed then multiplied by `a` — six field
    multiplications total. Matches the reference `Goldilocks::exp7`.
    """
    a2 = (a * a) % GOLDILOCKS_PRIME
    a4 = (a2 * a2) % GOLDILOCKS_PRIME
    a6 = (a4 * a2) % GOLDILOCKS_PRIME
    return (a6 * a) % GOLDILOCKS_PRIME


def from_u64(x: int) -> int:
    """Interpret an arbitrary 64-bit integer as a field element.

    Follows the reference `Goldilocks::new(u64)` behaviour — no range
    check on the input; caller supplies a value that already fits a
    u64. Reduction to canonical form happens lazily during arithmetic.
    """
    return x & 0xFFFFFFFFFFFFFFFF


def to_canonical_u64(a: int) -> int:
    """Project a field element to its canonical `u64` representative."""
    return canonical(a)
