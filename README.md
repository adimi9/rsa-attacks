# The Life and Death of a 2048-Bit RSA Key

**Six vulnerabilities · Four acts · Two algorithmic extensions**

> **Research question:** How can an RSA system fail even when every public modulus is exactly **2048 bits**?

This is a self-contained educational cryptanalysis lab, not an attack on correctly deployed RSA-2048. All test keys are **synthetic and deliberately vulnerable**. Attack implementations are given only public parameters, textbook ciphertexts, or a simulated faulty signature. The prime factors and private exponents used to create the test fixtures **are never stored**.

## The four-act security story

| Act | Question | Attack | Recovery / demonstration |
|---|---|---|---|
| **I · Key generation** | What if the primes are badly generated? | **01 Fermat** — excessively close primes | Factor a 2048-bit modulus and decrypt |
| | | **02 Shared-prime GCD** — prime reused across public keys | Recover compromised keys; **pairwise → batch GCD** |
| **II · Key parameters** | What if the primes are fine, but `d` is too short? | **03 Wiener** — continued fractions | Recover private exponent and decrypt |
| **III · Protocol design** | What if the keys are sound, but textbook RSA is misused? | **04 Common modulus** — Bézout's identity | Recover plaintext without the private key |
| | | **05 Håstad** — unpadded `e=3` encryption | **Single-ciphertext cube root → three-recipient CRT broadcast** |
| **IV · Implementation** | What if an otherwise sound key leaks through computation? | **06 Bellcore** — faulty RSA-CRT signature | Recover a prime factor and forge a valid signature |

**The only two deliberately added progressions** are (a) pairwise to batch GCD, and (b) the basic single-ciphertext cube-root attack to Håstad's broadcast attack. The other four attacks are kept as independent demonstrations, without artificial extra transitions.

## Run the demo

Requires **Python 3.10+**. From the repository root:

```bash
python -m pip install -r requirements.txt
python -m rsa_lab --no-pause --verbose
python -m unittest discover -s tests -v
```

The combined runner reports all six attacks and the two extensions. Run interactively by omitting `--no-pause`, or select a particular investigation:

```bash
python -m rsa_lab                          # step-by-step, press Enter between attacks
python -m rsa_lab --attack shared_prime --no-pause --verbose
python -m rsa_lab --attack hastad --no-pause --verbose
python -m rsa_lab --attack crt_fault --no-pause
python -m rsa_lab --no-pause --json-out results/my_run.json
```

**Live presentation:** Use the **pre-generated fixture files** included in this repo. No prime generation or web access is needed while presenting.

To generate new synthetic 2048-bit cases (slower, do this *before* the demo):

```bash
python -m rsa_lab --fresh --no-pause
# Or, regenerate only the public-key audit dataset:
python -m scripts.generate_audit --keys 100 --extra-pairs 2
```

### The two short extensions

**02 · Pairwise GCD → Batch GCD.** First, the code shows **four public keys**: Sensor A and Sensor B share a prime, while Office C and Gateway D are independent. It factors the vulnerable moduli and decrypts an example message. Then a separate public-only fixture contains **100 × 2048-bit moduli**, including **three deliberately shared-prime pairs (six compromised public keys)**. Pairwise GCD checks all **4,950** combinations. Batch GCD implements a **product tree and remainder tree** and recovers the same factors. The program checks agreement and prints both observed runtimes. **Batch GCD need not be faster for just 100 keys in pure Python**; its purpose here is to demonstrate a different, large-collection algorithm, not to claim a universal speedup.

**05 · Single cube root → Håstad.** With **one** 2048-bit modulus, `e=3` and a 128-bit unpadded test secret, `m³ < n`, so the ciphertext is the exact integer cube: `m = ∛c`. For the **long** unpadded message in the next test, each individual ciphertext has undergone modular reduction, so the basic cube-root attack does not recover it. With **three different 2048-bit moduli**, however, CRT reconstructs `m³` and an exact cube root reveals the message. Secure randomized padding (e.g. RSA-OAEP) prevents these textbook attacks.

## Source structure

```text
rsa-lifecycle-2048/
├── README.md
├── requirements.txt
├── rsa_lab/
│   ├── __main__.py               # python -m rsa_lab entry point
│   ├── demo.py                   # one runner, FOUR acts, SIX investigations
│   ├── fixtures.py               # synthetic key and public-only audit generation
│   ├── mathutils.py              # precise integer arithmetic
│   └── attacks/
│       ├── fermat.py
│       ├── common_prime.py       # pairwise GCD (four-key example and audit)
│       ├── batch_gcd.py         # product/remainder-tree batch GCD
│       ├── wiener.py
│       ├── common_modulus.py
│       ├── hastad.py            # single cube root + CRT broadcast
│       └── crt_fault.py
├── attacks/                     # one readable README for each of the SIX attacks
│   ├── 01_fermat/README.md
│   ├── 02_common_prime/README.md
│   ├── 03_wiener/README.md
│   ├── 04_common_modulus/README.md
│   ├── 05_hastad/README.md
│   └── 06_crt_fault/README.md
├── fixtures/
│   ├── demo_cases.json          # six synthetic attack cases, public inputs only
│   └── public_key_audit_100.json # 100 public moduli, no private factors
├── scripts/
│   ├── benchmarks.py            # optional Fermat prime-gap experiment
│   └── generate_audit.py        # offline audit fixture generator
├── docs/
│   ├── ATTACK_GUIDE.md          # vulnerabilities, maths, controls, mitigation
│   ├── DEMO_SCRIPT.md          # 8-min presentation split, 4 min each
│   ├── METHODOLOGY.md          # fixture design and limitations
│   └── REFERENCES.md           # papers, course coverage, code references
├── tests/test_attacks.py        # real-sized, small-unit and negative-control tests
└── results/
    ├── example_results.json     # observed outputs from an example local run
    └── fermat_gap_experiment.csv
```

## What each layer does

1. **`fixtures.py`** creates vulnerable keys in memory but exports only attack inputs; `public_key_audit_100.json` is a separate pre-generated collection for the batch example.
2. **`rsa_lab/attacks/`** implements each recovery operation independently. `batch_gcd.py` really builds product/remainder trees, rather than calling the pairwise routine internally.
3. **`demo.py`** executes and verifies each recovery. For Attack 02 it compares both algorithms on the *same 100 public moduli*. For Attack 05 it verifies both the basic and advanced demonstrations.
4. **`tests/`** checks correctness, exact 2048-bit modulus sizes, algorithm agreement, special cases (including an ambiguous batch-GCD result), and selected failures under changed conditions.
5. **`docs/`** explains the mathematics, threat models, lecture overlap, and how to present the four acts.

## Mathematical and academic boundaries

- **Exactly 2048 bits** refers to the RSA modulus `n`, not to the size of a factor, message, or private exponent. Håstad uses three separate 2048-bit moduli; the key audit uses 100 such moduli.
- **Weak conditions are deliberate.** Close primes, repeated primes, small `d`, reused modulus, unpadded textbook encryption, and injected CRT faults are *not* normal secure RSA usage.
- **Batch GCD detects the same shared-factor weakness as pairwise GCD**, using a different algorithm. When both factors of a modulus occur elsewhere, naive batch GCD can return the whole modulus: our code flags such cases as *ambiguous* instead of pretending to have recovered a factor. In the provided 100-key audit there are no ambiguous results.
- **A negative-control failure does not prove general security.** The Fermat control is iteration-bounded; the others exercise specific attack assumptions.
- **Bellcore faults are simulated** in software, not physically injected into a smart card. The test demonstrates the mathematical consequence of releasing a faulty RSA-CRT signature.
- The repo deliberately **does not include** Pollard's rho, RNG enumeration, extended Wiener, or OAEP comparison implementations. Read `docs/METHODOLOGY.md` for scope decisions; never claim those were tested.
- External repositories and scholarly papers informed the mathematical design; see `docs/REFERENCES.md`. Do not present any known attacks as original inventions. This is a reproducible educational implementation, not a proof of security or a guarantee of a grade.

## Presentation prep

Start with [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md), then read [`docs/ATTACK_GUIDE.md`](docs/ATTACK_GUIDE.md) together. Plan for **20 seconds of introduction, ~7 minutes 10 seconds on the attacks, and 30 seconds of conclusion** within the eight-minute limit. Each teammate should be ready to explain the assumptions and countermeasures for all six attacks during Q&A.
