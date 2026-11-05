# Act I — Too-Close Primes

**RSA modulus size:** Exactly **2048 bits** for every supplied case.

## Goal

Given only public modulus `n` and ciphertext `c`, recover both 1024-bit prime factors of a 2048-bit RSA modulus using `n = a² − b²`, derive private exponent `d` and decrypt.

## Preconditions / threat model

The prime factors were chosen unusually close; no efficient factorization of ordinary random RSA moduli is implied.

## Core mathematics

`p = a − b`, `q = a + b` once `a² − n` is a square.

## Run live

From the **repository root**:

```bash
python -m rsa_lab --attack fermat --no-pause --verbose
```

**Implementation:** [`../../rsa_lab/attacks/fermat.py`](../../rsa_lab/attacks/fermat.py)  
**Synthetic inputs:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json)  
**Explanation and mitigation:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)

## Reading / cross-check reference

https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Fermat

The source file in this package is independently written for the lab; this is a learning reference, not a verbatim code copy. Do not present this synthetic weak-key exploit as a successful break of correctly deployed RSA-2048.
