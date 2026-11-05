# The Life and Death of a 2048-Bit RSA Key

## Presenter 1 — Key Construction (4 minutes)

### Slide 1 — Introduction (~15 seconds)

Our project investigates how RSA security can fail despite using 2048-bit moduli.

We demonstrate six attacks across four stages of RSA's lifecycle: prime generation, exponent selection, encryption design and implementation.

All our demonstrations use deliberately vulnerable, real-sized RSA systems.

---

### ACT I — Prime Generation

*Are the primes underlying RSA generated securely?*

### Slide 2 — Fermat Factorisation (~40 seconds)

Our first attack investigates RSA primes that are unusually close together, even though both are 1024 bits long.

Fermat exploits the difference-of-squares identity:

\[
N=a^2-b^2=(a-b)(a+b)
\]

Starting from the ceiling of the square root of \(N\), we increment \(a\) until \(a^2-N\) is a perfect square. We then recover the factors as \(p=a-b\) and \(q=a+b\).

Although Fermat can factor any odd composite number, it is only computationally efficient under favourable conditions, particularly when the factors are close.

**[Show demo result]**

In our implementation, we factored a 2048-bit RSA modulus in just **519 increments**, recovered both 1024-bit primes, reconstructed the private key and decrypted the test message.

This demonstrates how poor prime selection can compromise RSA despite a large modulus.

**Transition:** But primes don't necessarily have to be close for RSA to be vulnerable. What if different RSA keys accidentally reuse the same prime?

### Slide 3 — Pairwise GCD → Batch GCD (~2 minutes 10 seconds)

Our next investigation examines how shared primes can compromise RSA keys across an entire collection.

Suppose two public moduli are \(N_1=pq_1\) and \(N_2=pq_2\). Since both share the prime \(p\), computing their greatest common divisor reveals \(p\), allowing us to factor both moduli and reconstruct their private keys.

This is **pairwise GCD**.

However, for 100 public keys, we need 4,950 pairwise comparisons. As the dataset grows, this becomes computationally expensive.

So we also implemented **Batch GCD**, using product and remainder trees.

Although multiplication is associative, its computational cost depends on the order of operations.

A **product tree** multiplies moduli in pairs, then recursively combines those products until we obtain:

\[
P=\prod_{i=1}^{n}N_i
\]

This keeps operand sizes relatively balanced, improving the efficiency of large-integer multiplication.

Next, the **remainder tree** computes:

\[
r_i=P\bmod N_i^2
\]

Rather than independently dividing the enormous product by every \(N_i^2\), it propagates intermediate remainders down the tree, reusing previous computations.

Finally, for each modulus, we calculate:

\[
g_i=\gcd(N_i,r_i/N_i)
\]

If \(1<g_i<N_i\), we've recovered a nontrivial factor.

**[Show pairwise and batch GCD demo results]**

In our implementation, we used **100 synthetic 2048-bit RSA public moduli**, deliberately introducing shared primes into six keys.

Pairwise GCD performed 4,950 comparisons, while Batch GCD used its product/remainder-tree approach.

Both algorithms successfully identified the same six compromised keys and recovered their factors.

Batch GCD was slower in this small experiment because of its additional overhead, but its algorithmic advantage becomes relevant for much larger collections.

Together, Fermat and shared-prime GCD demonstrate two prime-generation failures: **primes chosen too close together, and primes unintentionally reused across keys.**

---

### ACT II — Exponent Selection

*What if the primes are secure, but the private exponent is weak?*

### Slide 4 — Wiener's Attack (~55 seconds)

Our next attack moves from prime generation to **exponent selection**.

Even with appropriately generated primes, choosing an unusually small private exponent \(d\) can compromise RSA.

Recall that RSA satisfies:

\[
ed-k\phi(N)=1
\]

Since \(\phi(N)\) is close to \(N\) for balanced large primes, we obtain:

\[
\frac eN\approx\frac kd
\]

Wiener's insight is that continued fractions generate exceptionally accurate rational approximations, called convergents.

The algorithm expands the public fraction \(e/N\) into convergents. Under Wiener's small-\(d\) condition, one of these contains the private exponent \(d\) as its denominator.

For each candidate, we calculate:

\[
\phi(N)=\frac{ed-1}{k}
\]

We then verify whether it produces valid prime factors of \(N\).

**[Show demo result]**

Our implementation examined **162 convergents**, recovered a 256-bit private exponent from a 2048-bit modulus, and successfully decrypted the test message.

So far, we've compromised RSA through weaknesses introduced while constructing its keys.

**But even when the keys themselves are secure, can the way RSA is used still expose plaintext?**

---

## Presenter 2 — RSA Usage and Implementation (4 minutes)

### ACT III — Encryption Design

*Can insecure encryption expose plaintext without compromising the private key?*

### Slide 5 — Common-Modulus Attack (~35 seconds)

Our fourth attack investigates insecure modulus reuse.

Suppose the same plaintext is encrypted under one RSA modulus but two different, coprime public exponents.

Using Bézout's identity, we find integers \(a,b\) such that:

\[
ae_1+be_2=1
\]

We can combine the ciphertexts:

\[
c_1^ac_2^b\equiv m^{ae_1+be_2}=m\pmod N
\]

Negative exponents are handled using modular inverses.

**[Show demo result]**

Our implementation uses a 2048-bit modulus with exponents 65537 and 17, and successfully recovers the plaintext without knowing the private key.

**Transition:** But what if every recipient has a different modulus? Can encrypting the same message still be insecure?

### Slide 6 — Cube Root → Håstad's Broadcast Attack (~50 seconds)

Our next attack exploits textbook RSA encryption with a small public exponent, \(e=3\).

If \(m^3<N\), no modular reduction occurs, so taking the integer cube root directly recovers the plaintext.

But when \(m^3>N\), this simple attack no longer works.

Håstad's broadcast attack extends this idea to three recipients encrypting the same unpadded message under different, pairwise-coprime moduli.

Using the Chinese Remainder Theorem, we combine:

\[
c_i=m^3\bmod N_i
\]

to reconstruct \(m^3\) modulo \(N_1N_2N_3\).

Since \(m^3<N_1N_2N_3\), we obtain the exact integer cube and recover the message.

**[Show demo result]**

Our implementation first recovers a short message through a direct cube root. For a longer message, individual recovery fails, but combining three 2048-bit ciphertexts succeeds.

Both attacks demonstrate how **insecure textbook encryption can expose plaintext without recovering the private key**. Secure randomised padding such as RSA-OAEP prevents these straightforward attacks.

---

### ACT IV — Implementation Security

*What if the key and cryptographic design are secure, but the computation itself is faulty?*

### Slide 7 — Bellcore RSA-CRT Fault Attack (~2 minutes 15 seconds)

Our final attack demonstrates a different vulnerability: **even a securely generated RSA key can be compromised through a single faulty signature.**

Normally, RSA signing computes:

\[
s=m^d\bmod N
\]

where \(m\) is the encoded message representative.

However, this computation is expensive, so many implementations use the **Chinese Remainder Theorem** to accelerate signing.

Instead of one large exponentiation, the signer calculates:

\[
s_p=m^{d_p}\bmod p
\]

\[
s_q=m^{d_q}\bmod q
\]

where \(d_p=d\bmod(p-1)\) and \(d_q=d\bmod(q-1)\).

CRT recombines these into the final signature.

**Now, what happens if one computation is faulty?**

In our implementation, we simulate a fault by corrupting the \(p\)-side residue while leaving the \(q\)-side result unchanged.

The resulting signature, \(\tilde{s}\), is incorrect overall.

But crucially, it still satisfies the verification equation modulo \(q\), while failing modulo \(p\).

Therefore:

\[
\tilde{s}^{\,e}-m\equiv0\pmod q
\]

but not modulo \(p\).

Since \(N=pq\), the attacker can calculate:

\[
\boxed{\gcd(\tilde{s}^{\,e}-m,N)=q}
\]

This reveals one secret prime factor. We can divide \(N\) by \(q\) to recover \(p\), allowing reconstruction of the private key.

**[Show demo results]**

In our demonstration, we used a properly generated **2048-bit RSA key** and produced both a correct signature and a simulated faulty signature.

The correct signature passes verification, whereas the faulty signature fails.

Using the faulty signature and publicly known values, we recover both 1024-bit prime factors.

We then reconstruct the private exponent and demonstrate that the recovered key can produce a valid signature.

Importantly, **the key itself was not weak. The vulnerability arose during cryptographic execution.**

One mitigation is to verify the completed signature before releasing it, rejecting any faulty result.

### Slide 8 — Conclusion (~20 seconds)

Across the RSA lifecycle, we've demonstrated four distinct sources of vulnerability:

- Poor prime generation.
- Insecure exponent selection.
- Unsafe encryption design.
- Faulty cryptographic implementation.

Despite using 2048-bit moduli throughout, these weaknesses enabled private-key or plaintext recovery.

**Our conclusion is that RSA security depends not only on key size, but on the entire process of constructing, using and implementing RSA securely.**