"""Mathematics shared by independent educational RSA attack implementations.

Do not use this module for production cryptography.
"""
from __future__ import annotations
from math import gcd, isqrt


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (g, x, y) with ax + by = g = gcd(a,b)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def modinv(a: int, n: int) -> int:
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % n


def signed_modexp(base: int, exponent: int, modulus: int) -> int:
    """Compute base**exponent mod modulus, including negative exponents."""
    if exponent < 0:
        return pow(modinv(base, modulus), -exponent, modulus)
    return pow(base, exponent, modulus)


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError('nonnegative integers only')
    return n.to_bytes(length if length is not None else max(1, (n.bit_length() + 7) // 8), 'big')


def bytes_to_int(message: bytes) -> int:
    return int.from_bytes(message, 'big')


def recover_private(n: int, e: int, p: int, q: int) -> int:
    if p <= 1 or q <= 1 or p * q != n:
        raise ValueError('factors do not multiply to n')
    # Test keys are products of two distinct primes, confirmed at generation time.
    return modinv(e, (p - 1) * (q - 1))


def cube_root_exact(value: int) -> int | None:
    """Integer cube root (binary search), no floating point on huge integers."""
    if value < 0:
        raise ValueError('nonnegative only')
    if value < 2:
        return value
    low, high = 0, 1 << ((value.bit_length() + 2) // 3 + 1)
    while low <= high:
        mid = (low + high) // 2
        v = mid ** 3
        if v == value:
            return mid
        if v < value:
            low = mid + 1
        else:
            high = mid - 1
    return None


def rsa_ciphertext(message: bytes, n: int, e: int) -> int:
    m = bytes_to_int(message)
    if not (0 < m < n):
        raise ValueError('plaintext must be a positive integer below n')
    return pow(m, e, n)


def decrypt_bytes(ciphertext: int, n: int, d: int, length: int | None = None) -> bytes:
    return int_to_bytes(pow(ciphertext, d, n), length)
