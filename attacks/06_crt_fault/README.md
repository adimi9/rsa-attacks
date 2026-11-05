# Act IVII — Bellcore RSA-CRT Fault

**RSA modulus size:** Exactly **2048 bits** for every supplied case.

## Goal

Take one corrupted RSA-CRT signature on a correctly sized 2048-bit public key; recover its factors and demonstrate signing with the reconstructed private exponent.

## Preconditions / threat model

The synthetic signer injected a single bad residue in one CRT branch and released the faulty signature. No physical fault was created.

## Core mathematics

`gcd(s_fault^e − EM, n)` isolates the unaffected prime factor.

## Run live

From the **repository root**:

```bash
python -m rsa_lab --attack crt_fault --no-pause --verbose
```

**Implementation:** [`../../rsa_lab/attacks/crt_fault.py`](../../rsa_lab/attacks/crt_fault.py)  
**Synthetic inputs:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json)  
**Explanation and mitigation:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)

## Reading / cross-check reference

https://github.com/janmasarik/RSA-CRT-fault-attack

The source file in this package is independently written for the lab; this is a learning reference, not a verbatim code copy. Do not present this synthetic weak-key exploit as a successful break of correctly deployed RSA-2048.
