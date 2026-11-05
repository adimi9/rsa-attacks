# Attack guide — four acts, six weaknesses, two algorithmic extensions

**Research question:** Why is a 2048-bit modulus insufficient by itself to guarantee RSA security?

All demonstrations use **synthetic, exact 2048-bit moduli**, intentionally insecure settings and public attack inputs. The fixture generator knows private factors temporarily, but those factors are **not included** in the saved JSON files. A recovered factor or plaintext is checked against mathematical equations or a SHA-256 test digest.

The presentation follows **Vulnerability → Mathematical exploit → Verified outcome → Mitigation**. Only Attack 02 and Attack 05 contain a **basic → advanced** algorithm demonstration.

## ACT I — Key generation

### 01. Fermat factorisation — close primes

- **Vulnerability:** `n=pq` where the two 1024-bit primes are unusually close.
- **Exploit:** `n = a² − b² = (a-b)(a+b)`. Starting at `a = ceil(sqrt(n))`, look for the first `a²−n` that is a square; then `p=a-b` and `q=a+b`. Close primes bring the correct `a` close to `sqrt(n)`.
- **Demonstration:** `rsa_lab/attacks/fermat.py` factors the 2048-bit weak modulus, reconstructs `d` and decrypts a test ciphertext. `python -m scripts.benchmarks` separately varies prime distance, preserving 2048-bit moduli.
- **Boundary:** Balanced random RSA primes typically do not have the required extreme closeness. Failing within a chosen iteration limit is not proof of safety.
- **Mitigation:** Independently generate RSA primes through vetted cryptographic libraries. Do not deliberately choose adjacent primes.
- **Lecture link:** Week 7: dependent primes. **New implementation content:** Fermat's difference-of-squares search against a full-sized modulus.

### 02. Shared-prime GCD — two algorithms, one vulnerability

- **Vulnerability:** Distinct public moduli reuse a prime: `n_A=p q_A` and `n_B=p q_B`.
- **Pairwise algorithm:** `gcd(n_A,n_B)=p`. This factors both keys and allows reconstruction of their private exponents. The four-key introductory fixture contains Sensor A / Sensor B sharing one factor, plus Office C / Gateway D with independent primes.
- **Batch algorithm:** For a collection of public moduli `n_1,...,n_k`, build a **product tree** to obtain `P = ∏n_i`. Use a **remainder tree** to obtain `r_i = P mod n_i²`, then compute:

  `g_i = gcd(n_i, r_i / n_i)`

  The division is exact because `P` includes `n_i`. A nontrivial `1 < g_i < n_i` factors key `i`. `rsa_lab/attacks/batch_gcd.py` implements the full product/remainder-tree method; it does **not** call pairwise GCD to get its factors.
- **Demonstration:** Scan **100 synthetic 2048-bit public moduli** in `fixtures/public_key_audit_100.json`, including **three planted shared-prime pairs (six factorable keys)**. Compare the batch result to an independent pairwise scan (4,950 GCD comparisons) and verify exact factor agreement. This is an *algorithm demonstration*, not an extensive scalability experiment.
- **Important edge case:** If a modulus shares **both** its prime factors with different other moduli, `g_i` may equal `n_i`; identical public moduli can also produce this. The code reports these cases as **ambiguous**, rather than falsely claiming a factor. Pairwise follow-up or additional analysis may resolve some of them. Our supplied 100-key fixture has no such ambiguity.
- **Runtime caveat:** Batch GCD's tree arithmetic has overhead; our small, pure-Python run may be **slower** than pairwise. The motivation is a superior approach to large-scale public-key audits, not a promised speedup on 100 keys.
- **Mitigation:** Cryptographically secure prime generation, independent randomness per device, vetted key provisioning, and authorised audits of public keys.
- **Lecture link:** Week 8: *Mining Your Ps and Qs* and shared-prime recovery. **New implementation content:** an explicit product/remainder-tree batch algorithm, paired with an exact-factor comparison on 100 2048-bit keys.

## ACT II — Key parameters

### 03. Wiener — short private exponent

- **Vulnerability:** An excessively short private exponent `d` is chosen to speed up private operations. The classical Wiener theorem provides a sufficient vulnerable range, under standard prime-balance assumptions: `d < (1/3)n^(1/4)`.
- **Exploit:** Generate continued-fraction convergents `k/d` of `e/n`. For a candidate, `phi(n)=(ed−1)/k`; check whether the resulting quadratic yields integer primes whose product is `n`.
- **Demonstration:** `rsa_lab/attacks/wiener.py` recovers a deliberately ~256-bit `d` from public `(n,e)` with a 2048-bit modulus, then decrypts a message. A regular `e=65537` fixture is a negative control.
- **Mitigation:** Vetted RSA key generation; do not intentionally select tiny private exponents.
- **Lecture link:** Week 8 covers the complete classical Wiener attack. **Implementation contribution:** test against an actual 2048-bit weak modulus; **no extended Wiener variant** is implemented.

## ACT III — Insecure protocol design

### 04. Common-modulus attack — Bézout recovery

- **Vulnerability:** Two users share the same modulus `n` with coprime public exponents `e_1,e_2`, and the **same unpadded integer plaintext** `m` is encrypted under both public keys.
- **Exploit:** Extended Euclid yields `a e_1 + b e_2 = 1`. From `c_1 = m^e_1 mod n` and `c_2 = m^e_2 mod n`, recover `m = c_1^a c_2^b mod n`, using a modular inverse for any negative exponent (the chosen `m` is coprime to `n`).
- **Demonstration:** `rsa_lab/attacks/common_modulus.py` uses one 2048-bit modulus with exponents 65537 and 17; recovers the plaintext *without* recovering a private key.
- **Mitigation:** Independent RSA moduli and standard randomised encryption padding (RSA-OAEP), rather than textbook RSA.
- **Lecture link:** Week 7 introduces the shared-modulus setup; the exact Bézout recovery is implemented here.

### 05. Low public exponent — basic cube root → Håstad broadcast

Both demonstrations have `e=3` and *unpadded textbook RSA*, but the messages differ in size.

**Basic attack: one ciphertext.** Encryption gives `c = m³ mod n`. If `m³ < n`, no reduction occurs and `c=m³`. Therefore `m=∛c` using the **exact integer cube root** (no floating point). The fixture includes **one 128-bit test secret under one 2048-bit modulus**, and `hastad.cube_root_attack()` recovers it.

**Advanced attack: three ciphertexts.** Use a **longer, identical** unpadded message sent to three independent recipients with pairwise-coprime 2048-bit moduli `n_1,n_2,n_3` and `e=3`. Each individual ciphertext has been reduced modulo its `n_i`; taking its integer cube root no longer recovers the message in this fixture. Use CRT to combine `c_i=m³ mod n_i` into the integer `m³` modulo `n_1 n_2 n_3`. Since `m<n_i` for every recipient, `m³<n_1 n_2 n_3`; the CRT result is the *actual* `m³`. Taking the integer cube root recovers `m`.

- **Demonstration:** Both steps execute in Attack 05 (`rsa_lab/attacks/hastad.py`) and must verify successfully; a changed-message negative control fails the broadcast recovery.
- **Mitigation:** Randomised RSA-OAEP encryption. `e=3` alone is **not** sufficient to make RSA insecure.
- **Lecture link:** Week 8 introduces the three-recipient, `e=3` scenario. **Implementation contribution:** contrast single-ciphertext success on a small message with single-ciphertext failure and multi-recipient CRT success on a longer message, all at 2048 bits.

## ACT IV — Faulty implementation

### 06. Bellcore RSA-CRT signature fault

- **Vulnerability:** An RSA-CRT signer computes signature residues separately modulo `p` and `q`. A fault changes **one** residue, but the signer mistakenly releases the resulting signature.
- **Exploit:** With encoded message representative `m`, public exponent `e`, public modulus `n` and faulty signature `s_bad`, calculate `g = gcd((s_bad^e − m) mod n, n)`. If the faulty result is valid modulo one prime and invalid modulo the other, `1<g<n` reveals the unaffected factor. Derive the other factor and reconstruct `d`.
- **Demonstration:** `rsa_lab/attacks/crt_fault.py` uses a securely generated 2048-bit key and **simulates** one corrupted CRT residue. The normal signature does not reveal a factor; the faulty one does. The recovered private exponent generates a valid signature.
- **Mitigation:** Verify the completed signature before releasing it; reject faults and use vetted fault-resistant signing implementations.
- **Lecture link:** Week 8 covers implementation / side-channel risks, but **this CRT fault technique is additional material**. A simulated fault is **not** a claim of physical fault injection or remote compromise.

## What the presentation should establish

Across the six cases, the attacker sometimes recovers **private-key factors** (Acts I, II and IV) and sometimes **only plaintext** (Act III). Key size does not compensate for bad prime generation, bad parameters, textbook RSA protocols, or faulty implementations. Each attack has an explicit prerequisite, so **none of the demos is evidence that correctly deployed RSA-2048 is generally broken**.
