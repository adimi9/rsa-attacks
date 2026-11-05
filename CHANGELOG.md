# Changelog

## v1.1.0 — Four acts, two algorithm extensions

- Reorganised the six existing RSA vulnerabilities into **four acts**: key generation, key parameters, protocol design, and implementation security. Bellcore is now explicitly Act IV.
- Added `rsa_lab/attacks/batch_gcd.py`: a **real product/remainder-tree batch GCD algorithm**, with an explicit ambiguity report when the batch result equals the full modulus.
- Added `fixtures/public_key_audit_100.json`: **100 public 2048-bit moduli**, three planted shared-prime pairs (six compromised keys), 94 without planted shared factors; no private factors saved.
- Updated the GCD demo to first explain the **four-device pairwise** recovery, then compare pairwise vs batch factors on the **same 100-key audit**, printing observed timings without promising batch wins at small sizes.
- Added `hastad.cube_root_attack()` and a **128-bit single-ciphertext test case**; the Håstad demonstration now clearly progresses from basic cube root to CRT broadcast on a longer message that individual roots cannot recover.
- Updated lecture connections, attack READMEs, four-act README, mathematical guide, eight-minute speaking plan, scope limitations, fixtures, and sample result JSON.
- Added regression tests for **exact 2048-bit moduli**, batch/pairwise factor equivalence, odd-size product trees, ambiguous factor cases, and both low-public-exponent scenarios. Test suite now includes **19 passing tests**.
- Verified both the included fixtures and a completely freshly generated set.

## v1.0.0 — Initial six-attack educational lab

- Fermat, shared-prime pairwise GCD, Wiener, common modulus, Håstad broadcast and Bellcore CRT fault demos with synthetic 2048-bit moduli.
