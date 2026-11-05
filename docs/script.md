### 1. Fermat Factorisation — ~40 seconds

Our first attack investigates RSA primes that are unusually close together, even though both are 1024 bits long.

Fermat exploits the difference-of-squares identity:

\[
N=a^2-b^2=(a-b)(a+b)
\]

Starting from the ceiling of the square root of N, we increment a until \(a^2-N\) is a perfect square. We then recover the factors as \(p=a-b\) and \(q=a+b\).

Although Fermat can factor any odd composite number, it is only computationally efficient under favourable conditions, particularly when the factors are close.

**[Show demo result]**

In our implementation, we successfully factored a 2048-bit RSA modulus in just **519 increments**, recovered both 1024-bit primes, reconstructed the private key and decrypted the test message.

This demonstrates how poor prime selection can compromise RSA despite a large modulus.

### 2. Wiener's Attack — ~55 seconds

Our next attack targets an unusually small private exponent, d.

Recall that RSA satisfies:

\[
ed-k\phi(N)=1
\]

Since \(\phi(N)\) is close to N for balanced large primes, we obtain the approximation:

\[
\frac eN\approx\frac kd
\]

Wiener's insight is that continued fractions generate exceptionally accurate rational approximations, called convergents.

The algorithm expands the public fraction \(e/N\) into convergents. Under Wiener's small-d condition, one of them contains the private exponent d as its denominator.

For each candidate, we calculate \(\phi(N)=(ed-1)/k\) and check whether it produces valid prime factors of N.

**[Show demo result]**

In our implementation, the algorithm examined **162 convergents**, successfully recovered a 256-bit private exponent from a 2048-bit RSA modulus, and decrypted the test message.

So even properly generated large primes cannot compensate for an insecurely chosen private exponent.

### 3. Pairwise GCD → Batch GCD — ~2–2.5 minutes

Our next investigation examines how shared primes can compromise RSA keys across an entire collection.

Suppose two public moduli are \(N_1=pq_1\) and \(N_2=pq_2\). Since both share the prime \(p\), computing their greatest common divisor reveals \(p\), allowing us to factor both moduli and reconstruct their private keys.

This is **pairwise GCD**.

However, for 100 public keys, we need 4,950 pairwise comparisons. As the dataset grows, this becomes computationally expensive.

So we also implemented **Batch GCD**, using product and remainder trees.

Although multiplication is associative, its computational cost depends on the order of operations.

A **product tree** multiplies the moduli in pairs, then combines these products recursively until we obtain the total product:

\[
P=\prod_{i=1}^{n}N_i
\]

This keeps operand sizes relatively balanced, making large-integer multiplication more efficient.

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

**[Demo: Show pairwise and batch GCD results.]**

In our implementation, we generated a dataset of **100 synthetic 2048-bit RSA public moduli**, deliberately introducing shared primes into six keys.

We ran both algorithms on the same dataset.

Pairwise GCD performed 4,950 comparisons, while Batch GCD used its product/remainder-tree approach.

**Both algorithms successfully identified the same six compromised keys and recovered their factors.**

Interestingly, Batch GCD was slower in our 100-key experiment because of its additional overhead. However, its algorithmic advantage becomes relevant when analysing much larger collections.

Our demonstration therefore shows both **how shared-prime vulnerabilities compromise real-sized RSA keys and how different algorithms detect them at scale**.

### 4. Common-Modulus Attack — ~35 seconds

Our fourth attack exploits reusing the same RSA modulus to encrypt an identical plaintext under two different, coprime public exponents.

Using Bézout's identity, we find integers \(a,b\) such that:

\[
ae_1+be_2=1
\]

We can then combine the ciphertexts:

\[
c_1^ac_2^b\equiv m^{ae_1+be_2}=m\pmod N
\]

Negative exponents are handled using modular inverses.

**[Show demo result]**

In our implementation, we used a 2048-bit modulus with exponents 65537 and 17, and successfully recovered the plaintext without knowing the private key.

### 5. Cube Root → Håstad's Broadcast Attack — ~50 seconds

Our next attack exploits textbook RSA encryption with a small public exponent, \(e=3\).

If \(m^3<N\), no modular reduction occurs, so taking the integer cube root directly recovers the plaintext.

However, when \(m^3>N\), this simple attack no longer works.

Håstad's broadcast attack extends this idea to three recipients encrypting the same unpadded message under different, pairwise-coprime moduli.

Using the Chinese Remainder Theorem, we combine:

\[
c_i=m^3\bmod N_i
\]

to reconstruct \(m^3\) modulo \(N_1N_2N_3\).

Since \(m^3<N_1N_2N_3\), this gives us the exact integer cube, allowing plaintext recovery.

**[Show demo result]**

Our implementation first recovers a short message through a direct cube root. For a longer message, individual recovery fails, but combining three 2048-bit ciphertexts successfully recovers it.

Both attacks demonstrate why secure randomised padding, such as RSA-OAEP, is essential.

### 6. Bellcore RSA-CRT Fault Attack — ~2–2.5 minutes

Our final attack demonstrates an implementation-level vulnerability: **even a securely generated RSA key can be compromised through a single faulty signature.**

Normally, RSA signing computes \(s=m^d\bmod N\), where \(m\) is the encoded message representative.

However, this computation is expensive. RSA implementations often use the **Chinese Remainder Theorem (CRT)** to accelerate signing.

Instead of one large exponentiation, the signer computes two partial signatures:

\[
s_p=m^{d_p}\bmod p
\]

\[
s_q=m^{d_q}\bmod q
\]

where \(d_p=d\bmod(p-1)\) and \(d_q=d\bmod(q-1)\).

CRT then recombines these residues into the final signature \(s\).

**Now, what happens if one computation is faulty?**

In our implementation, we simulate a fault by corrupting the \(p\)-side residue while leaving the \(q\)-side residue unchanged.

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

This reveals one secret prime factor. We can then divide \(N\) by \(q\) to recover \(p\), allowing reconstruction of the entire private key.

**[Show demo results]**

In our demonstration, we generated a properly configured **2048-bit RSA key** and produced both a correct signature and a simulated faulty signature.

The correct signature passes verification, whereas the faulty signature fails.

Using the faulty signature and publicly known values, our attack successfully recovers both 1024-bit prime factors.

We then reconstruct the private exponent and demonstrate that the recovered key can generate a valid signature.

Importantly, **the key itself was not weak. The vulnerability arose from the faulty computation.**

One mitigation is to verify the completed signature before releasing it, rejecting any result that fails verification.