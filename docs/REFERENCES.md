# References and attribution

## Scholarly foundations

1. Heninger, Durumeric, Wustrow, Halderman (2012), **Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices**: https://factorable.net/paper.html — key-generation randomness failures, shared-prime recovery and large-scale GCD research.
2. Boneh (1999), **Twenty Years of Attacks on the RSA Cryptosystem**: https://crypto.stanford.edu/~dabo/pubs/abstracts/RSAattack-survey.html — taxonomy of elementary, small-exponent and implementation attacks.
3. Course lectures: SC4010 Applied Cryptography, Weeks 7–8: dependent/independent primes, *Mining Your Ps and Qs* and shared-prime GCD, Wiener, common modulus, low public exponents, side channels. Batch GCD's tree algorithm and the Bellcore fault demonstration extend those concepts.
4. Heninger et al. (2012) slides on product/remainder-tree GCD: https://www.usenix.org/sites/default/files/conference/protected-files/durumeric_usenixsecurity12_slides.pdf — algorithm overview and original research-scale setting.

## Repositories used as learning/checking references

These references help with mathematical sanity checks and further study. **No upstream source files have been copied** into this repo. Written code is an independent educational implementation.

| Attack | Reference |
|---|---|
| Fermat | https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Fermat |
| Shared prime (pairwise) | https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Common-Prime |
| Batch GCD product/remainder tree | https://github.com/therealmik/batchgcd ; https://factorable.net/resources.html |
| Wiener | https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Wiener |
| Optional Wiener variant reading only | https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Wiener-variant/README.md |
| Common modulus | https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Common-Modulus |
| Small public exponent, basic cube root | Standard textbook RSA relation `c=m³` whenever `m³<n`; see Boneh (1999) above |
| Håstad broadcast | https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-Hastad-Broadcast/README.md |
| RSA-CRT fault | https://github.com/janmasarik/RSA-CRT-fault-attack |
| CRT fault walkthrough | https://www.cryptologie.net/article/371/fault-attacks-on-rsas-signatures/ |

## Coursework inspiration

- https://github.com/Augeliua/SC4010-Hash-Based-Cryptographic-Attacks — inspiration for a readable, multi-attack educational repo with demos; **this project is on RSA and has independent code and a different narrative**.
- https://github.com/tamans13/RSA-Implementation-and-Vulnerabilities — comparator for attack organisation; **not copied**, and this repo emphasises verified exact 2048-bit moduli across every attack.
- https://github.com/vanhuynh-iu/SC4010-WeakRSA — a comparison point for the idea of pairing pairwise and batch GCD. Our code is independently written; we use the product/remainder-tree mathematics described by the research sources above.

## Licensing note

These files are original sample code written for this educational package. Third-party papers and reference repository contents are **not included**. Preserve original author attribution if you later copy or adapt external code, and check each source's license before redistribution.
