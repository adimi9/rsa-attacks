# Act III — Short Private Exponent

**RSA modulus size:** Exactly **2048 bits** for every supplied case.

## Goal

Recover a deliberately 256-bit RSA private exponent from a 2048-bit public modulus using exact continued fractions, then decrypt a message.

## Preconditions / threat model

Private exponent was intentionally chosen far below the classical Wiener bound; ordinary RSA keys are not vulnerable.

## Core mathematics

For convergent `k/d` of `e/n`, candidate `φ(n) = (ed − 1)/k`; validate by factoring quadratic.

## Run live

From the **repository root**:

```bash
python -m rsa_lab --attack wiener --no-pause --verbose
```

**Implementation:** [`../../rsa_lab/attacks/wiener.py`](../../rsa_lab/attacks/wiener.py)  
**Synthetic inputs:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json)  
**Explanation and mitigation:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)

## Reading / cross-check reference

https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener

The source file in this package is independently written for the lab; this is a learning reference, not a verbatim code copy. Do not present this synthetic weak-key exploit as a successful break of correctly deployed RSA-2048.
