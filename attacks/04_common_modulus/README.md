# Act IIIII — Common Modulus Misuse

**RSA modulus size:** Exactly **2048 bits** for every supplied case.

## Goal

Recover an unpadded message from two RSA ciphertexts using same 2048-bit modulus and two coprime exponents, never recovering the private key.

## Preconditions / threat model

The exact same integer plaintext is encrypted twice without randomized padding and with shared modulus.

## Core mathematics

Find `a e₁ + b e₂ = 1`, then `m ≡ c₁ᵃ c₂ᵇ (mod n)`.

## Run live

From the **repository root**:

```bash
python -m rsa_lab --attack common_modulus --no-pause --verbose
```

**Implementation:** [`../../rsa_lab/attacks/common_modulus.py`](../../rsa_lab/attacks/common_modulus.py)  
**Synthetic inputs:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json)  
**Explanation and mitigation:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)

## Reading / cross-check reference

https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Common-Modulus

The source file in this package is independently written for the lab; this is a learning reference, not a verbatim code copy. Do not present this synthetic weak-key exploit as a successful break of correctly deployed RSA-2048.
