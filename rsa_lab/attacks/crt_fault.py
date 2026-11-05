"""Act IV: RSA-CRT fault recovery from a single faulty signature."""
from math import gcd


def attack(n: int, e: int, encoded_message: int, faulty_signature: int) -> tuple[int, int] | None:
    """Bellcore/Lenstra-style gcd factor recovery from a faulty RSA signature.

    Inputs (n,e), encoded message representative, and a publicly leaked
    faulty signature; does not read p, q, or private signing exponents.
    """
    if not (0 < encoded_message < n and 0 < faulty_signature < n):
        raise ValueError('invalid encoded message or signature representative')
    factor = gcd((pow(faulty_signature, e, n) - encoded_message) % n, n)
    if 1 < factor < n:
        return min(factor, n // factor), max(factor, n // factor)
    return None


def simulate_fault(encoded_message: int, p: int, q: int, d: int) -> tuple[int, int]:
    """LAB GENERATOR ONLY: simulated corruption of one RSA-CRT residue.

    This is neither a hardware fault injector nor a signing oracle.
    """
    n = p * q
    dp, dq = d % (p - 1), d % (q - 1)
    sp, sq = pow(encoded_message, dp, p), pow(encoded_message, dq, q)
    good = (sq + q * ((sp - sq) * pow(q, -1, p) % p)) % n
    corrupted_sp = (sp + 1) % p
    faulty = (sq + q * ((corrupted_sp - sq) * pow(q, -1, p) % p)) % n
    assert faulty != good
    return good, faulty
