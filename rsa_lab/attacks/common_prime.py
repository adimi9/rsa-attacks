"""Act I: pairwise GCD baseline, companion to batch_gcd.py."""
from __future__ import annotations
from itertools import combinations
from math import gcd


def attack(public_keys: list[dict]) -> list[dict]:
    """Find shared factors from PUBLIC n values; no secret factors are passed in.

    Pairwise GCD uses O(k^2) comparisons; the distinct product/remainder-tree
    batch algorithm lives in rsa_lab/attacks/batch_gcd.py.
    """
    findings = []
    for a, b in combinations(public_keys, 2):
        n1, n2 = int(a['n'], 0) if isinstance(a['n'], str) else a['n'], int(b['n'], 0) if isinstance(b['n'], str) else b['n']
        g = gcd(n1, n2)
        if 1 < g < min(n1, n2) and n1 % g == n2 % g == 0:
            findings.append({
                'key_a': a['id'], 'key_b': b['id'],
                'shared_factor': g, 'other_factor_a': n1 // g, 'other_factor_b': n2 // g,
            })
    return findings
