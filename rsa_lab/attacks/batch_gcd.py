"""Batch GCD for collections of public RSA moduli.

Uses a product tree followed by a remainder tree (modulo each node's
square), rather than computing all O(k^2) pairwise GCDs. The attack
needs only public moduli. This is demonstration code, not a production
cryptographic key-auditing library.

If a modulus has *both* factors represented among the other moduli,
the batch GCD value can equal the entire modulus. We explicitly report
that ambiguity rather than incorrectly claiming to have recovered a
factor. A pairwise follow-up can then resolve it.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True)
class BatchGCDResult:
    """Non-trivial factors indexed by public key ID, plus ambiguous cases."""

    factors: dict[str, int]
    ambiguous_key_ids: tuple[str, ...]
    product_tree_levels: int


def attack(public_keys: list[dict]) -> BatchGCDResult:
    """Find shared factors in a public RSA key collection using batch GCD.

    Algorithm:
      P = product(n_i)
      r_i = P mod n_i**2          (computed via a remainder tree)
      g_i = gcd(n_i, r_i // n_i)

    With a non-trivial factor 1 < g_i < n_i, key i is factorable.
    When g_i == n_i the batch result is ambiguous (it may share both
    primes with different keys, or be duplicated); do not silently mark
    it as uncompromised or claim factor recovery.
    """
    if not public_keys:
        return BatchGCDResult({}, (), 0)
    ids = [item['id'] for item in public_keys]
    if len(ids) != len(set(ids)):
        raise ValueError('public key IDs must be unique')
    moduli = [int(k['n'], 0) if isinstance(k['n'], str) else k['n'] for k in public_keys]
    if any(not isinstance(n, int) or n <= 1 for n in moduli):
        raise ValueError('public moduli must be integers greater than 1')

    # Leaves first, root last. At most O(log k) levels.
    product_tree = [moduli]
    while len(product_tree[-1]) > 1:
        row = product_tree[-1]
        product_tree.append([row[i] * row[i + 1] if i + 1 < len(row) else row[i]
                             for i in range(0, len(row), 2)])

    # Starting with P modulo P^2 (which equals P), push remainders down.
    remainders = [product_tree[-1][0]]
    for level in range(len(product_tree) - 2, -1, -1):
        children = product_tree[level]
        remainders = [remainders[i // 2] % (n * n)
                      for i, n in enumerate(children)]

    factors: dict[str, int] = {}
    ambiguous = []
    for key_id, n, r in zip(ids, moduli, remainders):
        assert r % n == 0, 'product-tree invariant violated'
        g = gcd(n, r // n)
        if 1 < g < n:
            factors[key_id] = g
        elif g == n:
            ambiguous.append(key_id)
    return BatchGCDResult(factors, tuple(ambiguous), len(product_tree))
