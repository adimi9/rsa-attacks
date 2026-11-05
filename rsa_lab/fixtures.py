"""Generate synthetic weak RSA keys and PUBLIC-ONLY 2048-bit lab fixtures.

No real services, certificates, data, or keys are targeted. Secrets are
in-memory during generation and are intentionally NOT stored in fixtures.
"""
from __future__ import annotations
import hashlib
import json
import secrets
from datetime import datetime, timezone
from math import gcd
from pathlib import Path
from sympy import nextprime
from cryptography.hazmat.primitives.asymmetric import rsa

from rsa_lab.attacks.crt_fault import simulate_fault
from rsa_lab.mathutils import bytes_to_int, modinv, rsa_ciphertext

BITS = 2048
PRIME_BITS = BITS // 2
E = 65537
DEFAULT = Path(__file__).resolve().parent.parent / 'fixtures' / 'demo_cases.json'
AUDIT_DEFAULT = Path(__file__).resolve().parent.parent / 'fixtures' / 'public_key_audit_100.json'


def lab_prime(bits: int = PRIME_BITS) -> int:
    """Return one prime from an independently generated standard RSA keypair.

    OpenSSL-backed generation via cryptography is much faster than calling
    arbitrary-precision pure-Python primality tests for every test case.
    The other prime is discarded; all material is synthetic for this lab.
    """
    if bits != PRIME_BITS:
        raise ValueError('this 2048-bit demonstration uses 1024-bit factors only')
    key = rsa.generate_private_key(public_exponent=E, key_size=BITS)
    return key.private_numbers().p


def rsa_primes(e: int = E) -> tuple[int, int, int]:
    while True:
        # For standard e=3 or e=65537 OpenSSL selects primes for that exponent.
        # For the educational e=65537*17 coprimality test, select a normal key
        # then reject until phi also supports 17.
        generator_e = e if e in (3, E) else E
        key = rsa.generate_private_key(public_exponent=generator_e, key_size=BITS)
        params = key.private_numbers()
        p, q = params.p, params.q
        n = p * q
        if p != q and n.bit_length() == BITS and gcd(e, (p - 1) * (q - 1)) == 1:
            return p, q, n


def digest(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()


def external(case: dict) -> dict:
    """Recursively serialise large Python integers as JSON hexadecimal strings."""
    def encode(value):
        if isinstance(value, int) and not isinstance(value, bool):
            return hex(value)
        if isinstance(value, dict):
            return {k: encode(v) for k,v in value.items()}
        if isinstance(value, list):
            return [encode(v) for v in value]
        return value
    return encode(case)


def asint(v: int | str) -> int:
    return v if isinstance(v, int) else int(v, 0)


def emsa_pkcs1_v1_5_sha256(message: bytes, size: int = 256) -> int:
    """Standard PKCS#1 v1.5 SHA-256 encoded message REPRESENTATIVE.

    Encoding only, not a recommended way to implement production signing.
    """
    sha256_digest_info_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
    t = sha256_digest_info_prefix + hashlib.sha256(message).digest()
    if size < len(t) + 11:
        raise ValueError('intended encoded message length too short')
    padding = b'\xff' * (size - len(t) - 3)
    em = b'\x00\x01' + padding + b'\x00' + t
    return bytes_to_int(em)


def generate_cases() -> dict:
    cases = {}
    # I-A: n is truly 2048 bits; q near p by roughly 2^518.
    while True:
        p = lab_prime()
        q = int(nextprime(p + (1 << 518)))
        n = p*q
        if q.bit_length() == PRIME_BITS and n.bit_length() == BITS and gcd(E, (p-1)*(q-1)) == 1:
            break
    msg = b'LAB-ONLY: archived contract amount=100; verified by factor recovery'
    cases['fermat'] = dict(n=n,e=E,c=rsa_ciphertext(msg,n,E),
                           message_bytes=len(msg),expected_sha256=digest(msg),
                           prime_gap_bits=(q-p).bit_length(),
                           notes='two intentionally close 1024-bit primes')

    # I-B: four public keys, exactly one deliberately reused prime.
    while True:
        shared, q1, q2 = lab_prime(), lab_prime(), lab_prime()
        n1, n2 = shared*q1, shared*q2
        if len({shared,q1,q2}) == 3 and n1.bit_length()==n2.bit_length()==BITS and gcd(E,(shared-1)*(q1-1)*(q2-1))==1:
            break
    cp, cq, cn = rsa_primes()
    dp, dq, dn = rsa_primes()
    keys = [dict(id='sensor-A',n=n1,e=E),dict(id='sensor-B',n=n2,e=E),
            dict(id='office-C',n=cn,e=E),dict(id='gateway-D',n=dn,e=E)]
    msg = b'LAB-ONLY: device sensor-A confidential calibration data'
    cases['shared_prime'] = dict(public_keys=keys,target_id='sensor-A',
                                 ciphertext=rsa_ciphertext(msg,n1,E),
                                 message_bytes=len(msg),expected_sha256=digest(msg),
                                 notes='sensor-A and sensor-B share a factor; unrelated keys remain')

    # II: deliberately tiny private exponent, p/q otherwise independent.
    p, q, n = rsa_primes()
    phi = (p-1)*(q-1)
    while True:
        d = secrets.randbits(256) | 1 | (1 << 255)
        if gcd(d,phi) == 1:
            break
    e = modinv(d,phi)
    msg = b'LAB-ONLY: private exponent deliberately too short'
    cases['wiener'] = dict(n=n,e=e,c=rsa_ciphertext(msg,n,e),
                          message_bytes=len(msg),expected_sha256=digest(msg),
                          notes='256-bit private d for a 2048-bit modulus')

    # III-A: same n, different coprime public exponents, same plaintext.
    p, q, n = rsa_primes(e=E*17)
    msg = b'LAB-ONLY: textbook RSA reusing one modulus and plaintext'
    m = bytes_to_int(msg)
    assert gcd(m,n) == 1
    cases['common_modulus'] = dict(n=n,e1=E,e2=17,
                                    c1=pow(m,E,n),c2=pow(m,17,n),
                                    message_bytes=len(msg),expected_sha256=digest(msg),
                                    notes='same plaintext encrypted twice without OAEP')

    # III-B: e=3 broadcast to three independent 2048-bit recipients.
    triples=[]
    for _ in range(3):
        p, q, n = rsa_primes(e=3)
        triples.append(n)
    assert len(set(triples))==3
    assert all(gcd(triples[i], triples[j]) == 1 for i in range(3) for j in range(i+1,3))
    msg = (b'LAB-ONLY BROADCAST: transfer=50000; same unpadded content sent to 3 recipients; '
           + b'unique-case-id=' + secrets.token_hex(38).encode())
    m = bytes_to_int(msg)
    assert all(m < n < m**3 for n in triples), 'avoid the trivial single-ciphertext cube-root case'
    # Companion introductory example: a 128-bit unpadded message has m^3 < n.
    # One ciphertext then equals the integer cube m^3, unlike the broadcast case.
    small_msg = secrets.token_bytes(16)
    small_m = bytes_to_int(small_msg)
    assert 0 < small_m and small_m**3 < triples[0]
    small_case = dict(n=triples[0], c=pow(small_m,3,triples[0]),
                      message_bytes=len(small_msg), expected_sha256=digest(small_msg),
                      notes='one 128-bit demo secret, one 2048-bit modulus, e=3, no padding')
    cases['hastad'] = dict(e=3,single_ciphertext=small_case,
                           recipients=[dict(id=f'recipient-{i+1}',n=n,c=pow(m,3,n))
                                          for i,n in enumerate(triples)],
                           message_bytes=len(msg),expected_sha256=digest(msg),
                           individual_cube_root_possible=False,
                           notes='three pairwise-coprime 2048-bit moduli and SAME long unpadded message')

    # IV: fully-sized RSA with proper random key parameters; simulate a
    # single fault in the CRT signing calculation; store NO private factors.
    p, q, n = rsa_primes()
    d = modinv(E, (p-1)*(q-1))
    msg = b'LAB-ONLY: authorised firmware update manifest v1'
    representative = emsa_pkcs1_v1_5_sha256(msg)
    good, bad = simulate_fault(representative,p,q,d)
    assert pow(good,E,n) == representative
    assert pow(bad,E,n) != representative
    cases['crt_fault'] = dict(n=n,e=E,encoded_message=representative,
                              good_signature=good,faulty_signature=bad,
                              expected_message_sha256=digest(msg),
                              notes='one CRT residue corrupted in a simulated signer; private p/q NOT exported')

    data = dict(metadata=dict(bits=BITS,created_utc=datetime.now(timezone.utc).isoformat(),
                               source='synthetic, deliberately vulnerable lab keys, not real credentials',
                               test_vectors_only=True), cases=cases)
    return external(data)


def create(path: Path = DEFAULT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cases = generate_cases()
    path.write_text(json.dumps(cases,indent=2)+'\n',encoding='utf-8')
    return path


def load(path: Path = DEFAULT) -> dict:
    if not path.exists():
        raise FileNotFoundError(f'fixtures missing: {path}\nRun: python -m rsa_lab.fixtures')
    return json.loads(path.read_text(encoding='utf-8'))


def generate_audit_cases(base: dict, count: int = 100, extra_shared_pairs: int = 2) -> dict:
    """Construct a PUBLIC-ONLY batch-GCD audit with exactly `count` 2048-bit keys.

    Includes the four baseline devices plus synthetic keys with deliberately
    planted shared-prime pairs. Private primes are never written to disk.
    Keys are generated with a cryptographic library (may take time); ship
    the generated JSON for a fast and reproducible presentation.
    """
    if count < 4 + 2 * extra_shared_pairs or extra_shared_pairs < 0:
        raise ValueError('count must allow four baseline devices and all planted pairs')
    public = [dict(k) for k in base['cases']['shared_prime']['public_keys']]
    if len(public) != 4:
        raise ValueError('expected the four baseline device public keys')
    for pair in range(1, extra_shared_pairs + 1):
        while True:
            shared, q1, q2 = lab_prime(), lab_prime(), lab_prime()
            n1, n2 = shared * q1, shared * q2
            if len({shared, q1, q2}) == 3 and n1.bit_length() == n2.bit_length() == BITS:
                break
        public.extend([
            dict(id=f'audit-pair-{pair}-A', n=n1, e=E),
            dict(id=f'audit-pair-{pair}-B', n=n2, e=E),
        ])
    for offset in range(count - len(public)):
        _, _, n = rsa_primes()
        public.append(dict(id=f'independent-{offset + 1:03d}', n=n, e=E))
    assert len(public) == count
    assert all(asint(k['n']).bit_length() == BITS for k in public)
    return external(dict(metadata=dict(bits=BITS, key_count=count,
                                       source='synthetic 2048-bit public keys only; deliberate shared primes',
                                       extra_shared_pairs=extra_shared_pairs,
                                       test_vectors_only=True), public_keys=public))


def create_audit(path: Path = AUDIT_DEFAULT, base_path: Path = DEFAULT,
                 count: int = 100, extra_shared_pairs: int = 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = generate_audit_cases(load(base_path), count, extra_shared_pairs)
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    return path


def load_audit(path: Path = AUDIT_DEFAULT) -> dict:
    if not path.exists():
        raise FileNotFoundError(f'public key audit file missing: {path}\nRun: python -m scripts.generate_audit')
    return json.loads(path.read_text(encoding='utf-8'))


if __name__ == '__main__':
    print(f'Created synthetic 2048-bit public fixture set: {create()}')
