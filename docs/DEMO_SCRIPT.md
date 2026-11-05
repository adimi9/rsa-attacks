# Eight-minute presentation & live-demo script

**Topic:** The Life and Death of a 2048-Bit RSA Key  
**Research question:** What can fail despite a 2048-bit RSA modulus?  
**Format:** Two presenters × four minutes; 20-second introduction, ~7m10s of attacks, 30-second conclusion. Six attack investigations across **four acts**. Only GCD and Håstad have **basic → advanced** algorithm comparisons.

## Exact time allocation

| Time | Speaker | Section | What to show / explain |
|---|---|---|---|
| **0:00–0:20** (20s) | **1** | Introduction | Research question, four-act map, all `n` are 2048 bits and cases are intentionally weak. |
| **0:20–1:12** (52s) | **1** | **Act I · Fermat** | Difference-of-squares equation; close primes; show recovered factors and decrypted plaintext. |
| **1:12–2:42** (90s) | **1** | **Act I · Shared prime** | Four-device example and `gcd(n_A,n_B)=p`; then introduce **product/remainder-tree batch GCD** and show 100 public keys, 6 compromised, algorithms match. |
| **2:42–4:00** (78s) | **1** | **Act II · Wiener** | Short `d` vulnerability and continued-fraction idea; show recovered private exponent. Transition from weak keys to weak protocols. |
| **4:00–4:50** (50s) | **2** | **Act III · Common modulus** | Same `n`, different coprime `e`; Bézout equation; recovered message without `d`. |
| **4:50–6:15** (85s) | **2** | **Act III · Cube root → Håstad** | **One ciphertext** with a small unpadded message: exact cube root. **Long message**: one ciphertext insufficient; **three moduli** + CRT + exact cube root succeeds. |
| **6:15–7:30** (75s) | **2** | **Act IV · Bellcore** | Correct RSA-CRT signing versus one simulated corrupted residue; `gcd(s_bad^e−m,n)` reveals factor; show valid signature from recovered key. |
| **7:30–8:00** (30s) | **2** | Conclusion | RSA-2048 size alone is insufficient; avoid weak keys, unsafe protocols, faulty execution. State the assumptions and mitigations. |

**Speaker 1 totals 4:00; speaker 2 totals 4:00.** Rehearse with a stopwatch; switching screens and terminal scrolling consume time. The extension demonstrations are deliberately short, not separate full presentations.

## Suggested slides

1. **Research question and four-act security lifecycle** (20s).
2. **Fermat** — difference-of-squares equation + real-size factor recovery.
3. **Shared-prime GCD** — four-device diagram on the left; pairwise vs product/remainder-tree batch on the right. Highlight **100 public keys / 6 factorable / results agree**. Explain that 100-key timing is not guaranteed to favor batch.
4. **Wiener** — continued-fraction concept + recovered `d` (the lecture already provides the proof background).
5. **Common modulus** — Bézout coefficients combine two ciphertexts.
6. **Small public exponent → Håstad** — one-modulus cube-root success for the small message vs CRT recovery for the longer message sent to three recipients.
7. **Bellcore** — correct vs faulty CRT signing; one faulty result gives a prime factor.
8. **Summary** — what the attacker recovered, failure assumption, mitigation.

Each attack slide should show **(1) vulnerability, (2) core mathematical relation, (3) observed recovery, (4) mitigation**. Do *not* present a giant 2048-bit integer as evidence; show `bit_length = 2048`, key IDs, checked equations and recovered output.

## Commands to rehearse

From the repository root, after installing dependencies:

```bash
# Normal non-interactive run: all six investigations and two extensions
python -m rsa_lab --no-pause --verbose

# If you want to advance manually between attacks
python -m rsa_lab

# Presenter 1's notable extension: four keys then the 100-key audit
python -m rsa_lab --attack shared_prime --no-pause --verbose

# Presenter 2's notable extension: one cube root then broadcast
python -m rsa_lab --attack hastad --no-pause --verbose

# Verify correctness before going to class
python -m unittest discover -s tests -v
```

**Use the shipped fixture files.** Do not run `--fresh` during the timed demo. The combined runner will display six blocks; per-attack commands are convenient for rehearsal or Q&A.

## Teammate briefing: key facts to know

| Attack | Lecture connection | Unfamiliar part / worthwhile Q&A |
|---|---|---|
| Fermat | Dependent/close primes (Week 7) | Difference of squares and why closeness matters at 2048 bits. |
| Shared-prime GCD | Shared factors and *Mining Your Ps and Qs* (Week 8) | **Batch GCD** uses product/remainder trees; possible `g_i=n_i` ambiguity. |
| Wiener | Continued fractions and Wiener (Week 8) | Full-size implementation and sufficient short-`d` bound. |
| Common modulus | Reusing `n` with different `e` (Week 7) | Extended Euclid / negative modular exponents. |
| Håstad | Three recipients with `e=3` (Week 8) | Small-message cube root contrasted with **CRT broadcast of a longer message**. |
| Bellcore | Implementation risks / side-channels (Week 8) | **New:** simulated CRT fault, GCD factor recovery and signature check. |

**Five likely questions:** (1) Are these genuinely 2048-bit? Yes, the *moduli*, not messages. (2) Why is batch GCD useful if it was slower on 100 keys? Better algorithmic approach at very large scale; small-case overhead matters. (3) Is `e=3` itself insecure? No; the vulnerable demos also require unpadded textbook RSA and their specific message conditions. (4) Why no OAEP test? OAEP is recommended as mitigation, not implemented as a separate experiment here. (5) Is Bellcore a real injected fault? No; it's a software simulation showing the mathematics of faulty signature release.

## Conclusion message

**A 2048-bit modulus is not a complete security guarantee.** Our results show that key generation, key parameters, encryption protocols and signature implementations all have independent conditions that can compromise secrets. These are synthetic vulnerability demonstrations, **not** general breaks of correctly deployed RSA-2048.
