"""Act III: small-exponent cube-root and Håstad broadcast attacks (e=3)."""
from math import gcd
from itertools import combinations
from rsa_lab.mathutils import cube_root_exact, modinv


def cube_root_attack(n: int, ciphertext: int, e: int = 3) -> int | None:
    """Recover a small unpadded message from ONE ciphertext when m**3 < n.

    This deliberately narrow attack does not require CRT. A valid
    integer cube root of c alone is not sufficient to establish a
    general RSA break: the exact plaintext must be verified.
    """
    if e != 3:
        raise ValueError('this demonstration only supports e=3')
    if not (n > 1 and 0 <= ciphertext < n):
        raise ValueError('expected an RSA ciphertext in [0, n)')
    root = cube_root_exact(ciphertext)
    return root if root is not None and pow(root, 3, n) == ciphertext else None



def attack(moduli: list[int], ciphertexts: list[int], e: int = 3) -> int | None:
    """Recover the same unpadded integer m from e distinct RSA ciphertexts.

    CRT reconstructs m**e modulo product; since 0<m<each n and exactly
    e recipients, 0 < m**e < product. Requires pairwise coprime moduli.
    """
    if e < 2 or len(moduli) != e or len(ciphertexts) != e:
        raise ValueError('this demonstration requires exactly e recipient moduli')
    if any(gcd(a, b) != 1 for a, b in combinations(moduli, 2)):
        raise ValueError('moduli must be pairwise coprime')
    N = 1
    for n in moduli:
        N *= n
    combined = 0
    for n, c in zip(moduli, ciphertexts):
        partial = N // n
        combined = (combined + c * partial * modinv(partial, n)) % N
    if e != 3:
        raise NotImplementedError('integer roots implemented only for e=3')
    root = cube_root_exact(combined)
    if root is not None and all(pow(root, e, n) == c for n, c in zip(moduli, ciphertexts)):
        return root
    return None
