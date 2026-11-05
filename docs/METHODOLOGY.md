# Experimental methodology and limitations

## Objective and boundary

This is a controlled, offline SC4010 lab investigating six *independent RSA weaknesses* across **four security acts**. Every public modulus is **exactly 2048 bits**. Success is possible because the fixture generator intentionally creates **insecure parameters or faulty operations**, not because RSA-2048 with sound keys and approved padding is generally broken.

The main methodology is **six verified recoveries**, with exactly **two short algorithm comparisons**:

- **Shared primes:** Pairwise GCD compared to an independently implemented **product/remainder-tree batch GCD**.
- **Low exponent:** One-ciphertext integer cube-root attack on a small message, followed by **three-recipient CRT broadcast** on a longer message that the simple attack cannot recover.

No additional compare-and-contrast experiments are claimed for Fermat, Wiener, common modulus or Bellcore. Their core demonstrations and relevant negative controls are sufficient for this scope.

## Inputs and fixture generation

`rsa_lab/fixtures.py` uses OpenSSL-backed `cryptography` RSA prime generation, plus `sympy.nextprime` when constructing intentionally close primes. Private factors exist only temporarily during fixture creation and are **never saved**. Public test inputs are stored in JSON as hexadecimal strings. SHA-256 digests let the runner verify recovered synthetic messages without putting their plaintext into the fixture.

- `fixtures/demo_cases.json`: six attack cases, including a 4-device shared-prime example and **both** small-exponent scenarios.
- `fixtures/public_key_audit_100.json`: **100 synthetic 2048-bit public RSA moduli**, including the original four devices, **two extra planted shared-prime pairs**, and **92 additional independently generated keys**. The three planted pairs produce exactly **six factorable keys**; the other 94 keys have no planted shared factor.
- `scripts/generate_audit.py`: prepares a fresh audit file **offline**, with configurable collection size and number of extra pairs. The included dataset is pre-generated for fast live presentation.

Generated moduli are checked for exactly 2048 bits; that does not mean *all other parameters are secure*. The key audit is **synthetic** and does not inspect third-party certificates, real Internet traffic, devices or credentials.

## The two algorithm comparisons

### GCD: same vulnerability, different algorithms

1. **Four-key illustration**: pairwise `gcd(n_A,n_B)` recovers the shared prime, which recovers both key factors and decrypts Sensor A's message.
2. **100-key illustration**: pairwise GCD makes `100*99/2 = 4,950` comparisons; batch GCD builds a product tree, then a remainder tree modulo each leaf squared and computes `g_i = gcd(n_i, (P mod n_i²) / n_i)`. Both runs receive the **same public moduli**.
3. **Correctness criterion**: compare the returned factors by key ID, not only the counts of compromised keys. Require six factors, exactly matched, and **no ambiguous** result for the supplied dataset.
4. **Timing**: print observed timings, but do **not** claim batch is always faster. For 100 keys in pure Python, tree creation and large-integer operations can cost more than the 4,950 native-integer GCD calls. The conceptual algorithm is relevant to *large-scale* research; this is **not a full scalability benchmark**.
5. **Batch edge case**: if both prime factors of a modulus appear in other moduli, the formula can yield `g_i=n_i`, which does not directly reveal a factor; duplicates are likewise ambiguous. Code flags these instead of reporting a false recovery. Unit tests include this case.

### Low `e`: one-ciphertext cube root, then Håstad

1. **Basic case**: `e=3`, one 2048-bit modulus, one 128-bit synthetic unpadded secret, chosen so that `m³<n`; recover `m` as the **exact integer** cube root of the ciphertext.
2. **Extended case**: three pairwise-coprime 2048-bit moduli, `e=3`, the **same longer unpadded plaintext**. Each individual ciphertext is non-cube after modular reduction, so the basic method fails. CRT combines all three to reconstruct the actual `m³`, which can then be cube-rooted exactly.
3. **Correctness criterion**: both success cases must match the expected SHA-256 digests. Verify single-message failure for *each* of the long-message ciphertexts and verify the CRT-recovered message against all three public encryptions. The separate changed-message negative control should fail.
4. **Protocol caveat**: this is textbook unpadded RSA. `e=3` by itself does *not* imply practical insecurity with standard randomised padding.

## Core demonstrations and controls

| Investigation | Deliberately vulnerable input | Existing control / verification |
|---|---|---|
| 01 Fermat | Close prime pair | Independent key resists **bounded** Fermat iterations; factors multiply to 2048-bit `n` |
| 02 Shared prime | One shared pair in four keys; three pairs in audit | Independent devices not flagged; **pairwise = batch exact factors** |
| 03 Wiener | Short private `d` | Normal `e=65537` example not recovered by Wiener; factorisation checked |
| 04 Common modulus | Two coprime public exponents, same `n`, same unpadded `m` | Recovered `m` re-encrypts to both ciphertexts |
| 05 Håstad | Small single-message case and long three-recipient case | Individual exact cube roots fail for the long case; changed-message broadcast fails |
| 06 Bellcore | Simulated bad CRT residue | Correct signature produces no nontrivial factor; recovered key creates valid signature |

A failed control establishes only that **this attack did not succeed with those inputs**, not that the RSA system has been formally proven secure.

## Running experiments and reporting

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m rsa_lab --no-pause --verbose --json-out results/my_run.json
python -m scripts.benchmarks       # optional, existing Fermat prime-gap data
python -m scripts.generate_audit   # optional: regenerate 100-key audit OFFLINE
```

`results/example_results.json` is one observed run of the new four-act lab, **not** a statistical performance claim. Times depend on hardware and interpreter, and no universal batch-GCD speedup is asserted. Avoid showing misleading ratios from a single small dataset.

## Scope choices and security limits

- **No Pollard's rho or trial division**: useful for small factors, but not necessary to demonstrate the chosen close-prime and shared-factor weaknesses with two large factors. Neither was benchmarked.
- **No low-entropy RNG enumeration or duplicate-prime construction**: these are valid full-sized RSA weaknesses, but would add another key-generation scenario rather than another lifecycle failure mode.
- **No separate batch-GCD scalability study**: the algorithm and its correctness on 100 keys are shown; a series of dataset sizes is **not** required for this project.
- **No separate OAEP/PSS experiment**: use vetted cryptography libraries for real-world encryption and signing; the lab only explains padding and fault verification as countermeasures.
- **No physical fault injection**: Bellcore uses a software-simulated incorrect CRT branch, not a device-level fault.
- **No classical Wiener extension** beyond the implemented lecture-level continued-fraction attack.

The work is an educational implementation of established cryptanalytic methods. Cite the scholarly foundations and code-learning references in `docs/REFERENCES.md`. Contributors should understand the attack preconditions and verification steps rather than claiming to have discovered the algorithms.
