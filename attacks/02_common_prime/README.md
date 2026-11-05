# Act I — Shared-prime attack: Pairwise GCD → Batch GCD

**Six-attack lifecycle project, investigation 02.** All public RSA moduli are **exactly 2048 bits**.

## Vulnerability

Two distinct public keys may inadvertently share one prime: `n_A=pq_A`, `n_B=pq_B`. Knowing only public moduli gives `gcd(n_A,n_B)=p`; both keys can be factored and their private exponents reconstructed.

## Demonstration A: the four-device example

The initial fixture contains:

| Public key | Status |
|---|---|
| `sensor-A` | Shares one prime with Sensor B |
| `sensor-B` | Shares one prime with Sensor A |
| `office-C` | Independent |
| `gateway-D` | Independent |

`rsa_lab/attacks/common_prime.py` uses **pairwise** GCD (six comparisons), discovers the two compromised devices and decrypts Sensor A's synthetic message.

## Demonstration B: batch GCD on 100 public keys

`fixtures/public_key_audit_100.json` contains **100 × 2048-bit public keys**, including the original four. Exactly **three pairs (six keys)** were constructed with shared primes. The other 94 have no deliberately shared factors.

`rsa_lab/attacks/batch_gcd.py` independently implements the **product tree → remainder tree → GCD** algorithm:

1. Multiply all moduli in a **product tree**: `P = ∏n_i`.
2. Efficiently find each `r_i = P mod n_i²` using a **remainder tree**.
3. Recover `g_i = gcd(n_i, r_i / n_i)`; if `1 < g_i < n_i`, it is a factor.

The runner performs **both algorithms on the same 100 keys**, checks **factor-for-factor agreement**, and prints both measured times. Pairwise makes `100*99/2 = 4950` comparisons. Do **not** promise batch is faster at this small size: the extra large-integer tree arithmetic may outweigh the benefit in Python. Batch GCD matters particularly for **large-scale audits**, as in *Mining Your Ps and Qs*.

**Edge case:** If `g_i=n_i` (e.g. a key shares both factors separately), batch alone has not found a nontrivial factor. The code explicitly marks it *ambiguous*, and unit tests check this scenario.

## Mitigation

Use independent, cryptographically strong RSA key generation and authorised public-key audits when relevant.

## Run

```bash
python -m rsa_lab --attack shared_prime --no-pause --verbose
python -m unittest discover -s tests -v
# Optional: generate another PUBLIC-only audit fixture before presenting:
python -m scripts.generate_audit --keys 100 --extra-pairs 2
```

**Code:** [`../../rsa_lab/attacks/common_prime.py`](../../rsa_lab/attacks/common_prime.py), [`../../rsa_lab/attacks/batch_gcd.py`](../../rsa_lab/attacks/batch_gcd.py)  
**Public fixtures:** [`../../fixtures/demo_cases.json`](../../fixtures/demo_cases.json), [`../../fixtures/public_key_audit_100.json`](../../fixtures/public_key_audit_100.json)  
**Full explanation:** [`../../docs/ATTACK_GUIDE.md`](../../docs/ATTACK_GUIDE.md)  
**Research:** [Mining Your Ps and Qs](https://factorable.net/paper.html)
