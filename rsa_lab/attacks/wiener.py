"""Act II: classic Wiener's continued-fraction attack on a short RSA d."""
from __future__ import annotations
from math import isqrt
from dataclasses import dataclass


@dataclass(frozen=True)
class WienerResult:
    d: int | None
    p: int | None
    q: int | None
    convergents_examined: int

    @property
    def success(self) -> bool:
        return self.d is not None


def convergents(numerator: int, denominator: int):
    """Emit numerator/denominator pairs of exact convergents of e/n."""
    h_older, h_old = 0, 1
    k_older, k_old = 1, 0
    while denominator:
        quotient = numerator // denominator
        numerator, denominator = denominator, numerator % denominator
        h = quotient * h_old + h_older
        k = quotient * k_old + k_older
        yield h, k
        h_older, h_old = h_old, h
        k_older, k_old = k_old, k


def attack(n: int, e: int) -> WienerResult:
    """Recover private exponent from PUBLIC (n,e), if the Wiener condition holds.

    Unlike checking whether a decrypted message 'looks English', this verifies
    candidates by reconstructing phi(n) and recovering actual prime factors.
    """
    count = 0
    for k, d in convergents(e, n):
        count += 1
        if k == 0 or d <= 1 or (e*d - 1) % k:
            continue
        phi = (e * d - 1) // k
        sum_pq = n - phi + 1
        discriminant = sum_pq * sum_pq - 4 * n
        if discriminant < 0:
            continue
        root = isqrt(discriminant)
        if root * root != discriminant or (sum_pq - root) % 2:
            continue
        p = (sum_pq - root) // 2
        q = (sum_pq + root) // 2
        if p > 1 and q > 1 and p*q == n:
            return WienerResult(d, min(p, q), max(p, q), count)
    return WienerResult(None, None, None, count)
