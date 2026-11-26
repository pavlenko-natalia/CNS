# RSA — Exam Quick Reference

## 1. Core notation and formulas

| Symbol | Meaning |
|---|---|
| p, q | Distinct secret primes |
| n = pq | Public modulus |
| e | Public exponent (often 65537) |
| d | Private exponent |
| m | Plaintext integer, 0 <= m < n |
| c | Ciphertext integer |

- Public key: (n, e). Private key: (n, d).
- Euler totient: phi = (p - 1)(q - 1) = n - p - q + 1.
- Carmichael function: lambda = lcm(p - 1, q - 1).
- Choose e with gcd(e, phi) = 1.
- Private exponent: d = e^(-1) mod phi (or mod lambda).
- Encryption: c = m^e mod n.
- Decryption: m = c^d mod n.
- Correctness: ed = 1 + k*phi; Euler's theorem gives m^phi = 1 mod n for coprime m. CRT establishes correctness for all residues with distinct primes.

## 2. Essential mathematics

| Concept | Meaning |
|---|---|
| Modulo | Remainder after division |
| GCD | Greatest common divisor; gcd(a,b)=1 means coprime |
| EEA | Finds x,y such that ax + by = gcd(a,b) |
| Modular inverse | a*x = 1 mod n; exists iff gcd(a,n)=1 |
| CRT | Combines residues into a unique residue modulo the product of pairwise coprime moduli |
| Integer root | Exact integer root, not floating-point approximation |
| Continued fractions | Rational approximations with small denominators |
| Smooth number | All prime factors are below a specified bound |

## 3. Relationships between key parameters

For standard two-prime RSA:

- Knowing one prime determines the other: q = n/p.
- Knowing phi and e is sufficient to calculate d.
- Knowing d and n is sufficient for the private RSA operation.
- Let S = p + q and D = p - q. Then S = n - phi + 1.
- S^2 - D^2 = 4n.
- p and q are the roots of x^2 - Sx + n = 0.
- For distinct primes in multi-prime RSA, phi(n) = product of (p_i - 1).

## 4. Recognizing RSA weaknesses

| Method | Relevant clue / condition | Mathematical idea |
|---|---|---|
| Small-e | Small public exponent, short unpadded message | Exact integer powers |
| Common Modulus | Same n, same message, different coprime exponents | Bezout identity |
| Hastad Broadcast | Same unpadded message and small e, different coprime moduli | CRT and integer roots |
| Common Factor | Reused prime across distinct moduli | GCD |
| Fermat | Primes unusually close together | Difference of squares |
| Wiener | Unusually small private exponent d | Continued fractions |
| Pollard p-1 | A prime factor has smooth p-1 | Fermat's little theorem |
| Pollard Rho | Relatively small prime factor | Modular cycles and collisions |
| Dictionary | Predictable plaintext, deterministic encryption | Comparing candidate encryptions |

Important distinctions:
- Small e is not the same as small d.
- Common modulus means identical n; common factor means distinct n sharing a factor.
- Broadcast and common modulus require the same numerical plaintext, not merely the same human-readable message with different randomized padding.
- A small public exponent alone does not imply insecurity.
- Failure of a factorization method does not prove that a key is secure.

## 5. Python arithmetic reference

```python
from math import gcd, isqrt, lcm

pow(a, b, n)                 # modular exponentiation
pow(a, -1, n)                # modular inverse (Python 3.8+)
gcd(a, b)                    # greatest common divisor
isqrt(n)                     # exact floor square root
int.from_bytes(data, 'big')  # bytes -> integer
m.to_bytes(max(1, (m.bit_length()+7)//8), 'big')  # integer -> bytes
```

Use integer arithmetic, not floating-point roots, for large RSA numbers. Preserve fixed block widths when decoding block-based exercises; leading zero bytes may matter.

## 6. Textbook RSA vs real-world RSA

- Textbook RSA is deterministic and multiplicatively malleable.
- RSA-OAEP is a randomized encryption encoding scheme.
- RSA-PSS is a signature scheme; signing is not simply encryption with a private key.
- RSA encryption provides confidentiality; signatures provide authenticity and integrity when correctly verified.
- Factoring n is sufficient to compromise the private key, but general equivalence between RSA inversion and factoring has not been proved.
- Correctly generated modern RSA keys are not practically factorable using the elementary methods above.

## 7. Exam checklist

1. Identify which quantities are public, private, given, or unknown.
2. Distinguish integers, hex strings, bytes, and text.
3. Identify whether ciphertexts belong to different keys or blocks of one message.
4. Read the assumptions about prime generation, exponents, repeated messages, and padding.
5. Match the mathematical conditions to the relevant method; do not rely on the challenge title alone.
6. Check the validity of any recovered key parameters and verify plaintext candidates by re-encryption where applicable.
7. Remember that readable text is a heuristic, not mathematical proof.

Scope: This quick reference covers standard RSA theory and the method names in the preparation suite. It is not an exhaustive syllabus or a guarantee of exam coverage.
