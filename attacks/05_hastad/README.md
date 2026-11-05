# Act III — Low public exponent: Basic cube root → Håstad broadcast

**Six-attack lifecycle project, investigation 05.** Both examples have `e=3`, no padding, and exact **2048-bit RSA moduli**. A small exponent **alone** does not make properly padded RSA insecure.

## Basic attack: one ciphertext

For textbook RSA, `c = m³ mod n`. When `m³<n`, the modular reduction does nothing, so `c=m³`. Calculate the **exact integer cube root** to recover `m`. The included fixture encrypts **one 128-bit test secret with one 2048-bit modulus** and successfully recovers it.

Implemented as [`hastad.cube_root_attack()`](../../rsa_lab/attacks/hastad.py).

## Advanced attack: three recipients

Use a **longer identical plaintext**, `e=3`, and **three distinct pairwise-coprime 2048-bit moduli**. For this fixture the ciphertexts have undergone modular reduction and **none can be recovered by the simple individual cube-root approach**.

CRT combines the three congruences `c_i = m³ mod n_i`. Because `m<n_i` for each recipient, `m³ < n_1 n_2 n_3`; CRT therefore produces the actual integer `m³`. Its exact cube root reveals the message. Our code verifies both that individual roots fail and that the combined root succeeds.

Implemented as [`hastad.attack()`](../../rsa_lab/attacks/hastad.py).

## Mitigation

Use approved randomised RSA encryption padding such as **RSA-OAEP**, rather than unpadded textbook RSA. The repository explains this mitigation but does not include a separate OAEP comparison experiment.

## Run

```bash
python -m rsa_lab --attack hastad --no-pause --verbose
```

**Public fixture:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json) contains both `single_ciphertext` and `recipients` cases, without the secret plaintext.  
**Mathematics:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)  
**Learning reference:** https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Hastad-Broadcast
