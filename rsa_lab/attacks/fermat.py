"""Act I: Fermat factorization when the two RSA primes are too close."""
from dataclasses import dataclass
from math import isqrt


@dataclass(frozen=True)
class FermatResult:
    p: int | None
    q: int | None
    iterations: int

    @property
    def success(self) -> bool:
        return self.p is not None


def attack(n: int, max_iterations: int = 100_000) -> FermatResult:
    """Seek a^2-b^2=n; bounded search prevents hanging on normal keys."""
    if n < 3 or n % 2 == 0:
        raise ValueError('expected an odd composite RSA modulus')
    a = isqrt(n)
    if a * a < n:
        a += 1
    for attempts in range(max_iterations + 1):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return FermatResult(min(p, q), max(p, q), attempts)
        a += 1
    return FermatResult(None, None, max_iterations + 1)
