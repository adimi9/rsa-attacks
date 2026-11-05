"""Act III: textbook RSA common-modulus attack with coprime exponents."""
from math import gcd
from rsa_lab.mathutils import egcd, signed_modexp


def attack(n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    """Return m when c1=m^e1 and c2=m^e2 modulo the SAME n.

    Assumes gcd(e1,e2)=1 and message invertible mod n where required.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError('public exponents must be coprime')
    if not (0 < c1 < n and 0 < c2 < n):
        raise ValueError('invalid ciphertext')
    return (signed_modexp(c1, a, n) * signed_modexp(c2, b, n)) % n
