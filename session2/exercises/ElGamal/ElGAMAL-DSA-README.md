# ElGamal & DSA Cheat Sheet

---

## 1. ElGamal Encryption

### Setup
- `p`  — large prime
- `g`  — generator of `Z_p*`  (order `p-1`)
- `x`  — private key
- `y = g^x mod p`  — public key

### Encrypt `m`
Pick a random nonce `k`, then:
```
c1 = g^k mod p
c2 = m * y^k mod p
```
Ciphertext = `(c1, c2)`.

### Decrypt
```
s = c1^x mod p         # = g^(kx) = y^k
m = c2 * s^{-1} mod p
```

**Key idea:** the "shared secret" is `y^k = c1^x`. To decrypt you need
either `x` (private key) or `k` (nonce). Every attack is a way to get one
of them — or to bypass both.

**Security depends entirely on `k` being:**
1. uniformly random,
2. freshly chosen per message,
3. not predictable from the message.

---

## 2. DSA Signatures

### Setup
- `p` — large prime
- `q` — prime divisor of `p-1`
- `g` — element of order `q` in `Z_p*`  (so `g^q ≡ 1 mod p`)
- `x` — private key
- `y = g^x mod p` — public key
- `H = H(m) mod q` — message hash

### Sign `m`
Pick a random nonce `k`:
```
r = (g^k mod p) mod q
s = k^{-1} * (H + x*r) mod q
```
Signature = `(r, s)`.

### Verify
```
w  = s^{-1} mod q
u1 = H*w mod q
u2 = r*w mod q
check:  (g^u1 * y^u2 mod p) mod q == r
```

**Same weakness as ElGamal:** `k` must be unique and secret per message.
Recovering `k` immediately gives `x`:
```
x = (s*k - H) * r^{-1} mod q
```

---

## 3. The Three Attacks You Must Know

### Attack A — Nonce Reuse (ElGamal)

**Trigger:** `c1_known == c1_flag` (same `g^k`), one known plaintext.

**Why it works:** the same `y^k` appears in both ciphertexts, so it cancels:
```
c2_known = m_known * y^k
c2_flag  = m_flag  * y^k
```
**Formula:**
```python
m_flag = m_known * c2_flag * inverse(c2_known, p) % p
```

- Does **not** need `x`.
- Needs **one** known plaintext.

---

### Attack B — Sequential Nonce (ElGamal)

**Trigger:** `k_flag = k_known + δ` with small `δ` (e.g. `δ = 1`).

**Why it works:**
```
c1_flag = g^(k_known+δ) = c1_known * g^δ  (mod p)
```
So test candidate δ values by checking that identity.
Once δ is found:
```
y^k_flag = y^k_known * y^δ
```
where `y^k_known` comes from a known plaintext.

**Formula (δ = 1):**
```python
yk_known = c2_known * inverse(m_known, p) % p    # = y^k_known
yk_flag  = yk_known * y % p
m_flag   = c2_flag * inverse(yk_flag, p) % p
```

- Requires a known plaintext.
- Requires `δ` in the brute-forced range (default `[-10000, 10000]`).

---

### Attack C — Nonce Reuse (DSA)

**Trigger:** two signatures share the same `r` (hence same `k`).

**Why it works:** subtract the two signature equations:
```
s1 - s2 = k^{-1}(H1 - H2)  mod q
```
**Formulas:**
```python
k = (H1 - H2) * inverse(s1 - s2, q) % q
x = (s1*k - H1) * inverse(r, q) % q
assert pow(g, x, p) == y          # ALWAYS verify
```

- `gcd(s1 - s2, q) > 1` → `gcd` candidate values of `k`; try all.
- `q` is prime in practice, so usually the gcd is 1.

---

## 4. Secondary Attacks (when primary ones fail)

| Attack | Condition | Technique |
|--------|-----------|-----------|
| Small nonce `k` | `k < 2^bits` | BSGS on `c1 = g^k` (ElGamal) or brute force on `r` (DSA) |
| Small private key `x` | `x < 2^bits` | BSGS on `y = g^x` |
| Small subgroup of `y` | `y^q ≡ 1` for small `q \| p-1` | BSGS in the subgroup of order `q` |
| Smooth `p-1` | all prime factors of `p-1` are small | Pohlig–Hellman / `sympy.discrete_log` |

**BSGS (Baby-Step Giant-Step):** solves `g^x ≡ h (mod p)` in `O(√order)`
time and memory. Practical limit ≈ `2^40` (~1M dict entries).
Do **not** run it on full `p-1` if that's 256 bits.

---

## 5. Flags after recovering `x`

If the challenge gives an `encrypted_flag` hex, `x` alone is not enough —
the flag is usually XORed with a keystream derived from `x`. Common patterns:

1. `keystream = sha256(f"{x}:0") || sha256(f"{x}:1") || ...`
2. `keystream = long_to_bytes(x)`, repeated
3. `AES-ECB` with key `sha256(long_to_bytes(x))[:16]`
4. `encrypted_flag` is raw ASCII (just `bytes.fromhex`)
5. `keystream = sha256(str(x))` (single block)

`general.py` tries all five and prints whatever decodes to printable text.

