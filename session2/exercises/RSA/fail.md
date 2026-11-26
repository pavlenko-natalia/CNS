# ALL ATTACKS FAILED


---

## 0. 30-Second Triage

```
For each number in the input, label it:
  [n] [e] [c] [p] [q] [d] [phi] [sum] [diff] [dp] [dq] [a] [b] [bits] [?]

If you cannot label a number → it IS the hint. Find its role algebraically.

Look for keywords in the problem text:
  "short message"          → small-e / Coppersmith
  "leaked", "accidentally" → known φ, p+q, dp, dq, or partial d
  "close primes"           → Fermat
  "small d", "large e"     → Wiener / Boneh–Durfee
  "related", "m2 = a·m1+b" → Franklin–Reiter
  "PIN", "range", "format" → dictionary / brute force
  "signature", "verify"    → RSA signatures
  "same message"           → Håstad / Common Modulus
  "different padding"      → attack does NOT apply, rethink
```

---

## 1. Signature → Attack Lookup Table

| Signature in input | Attack | Tool |
|---|---|---|
| `e = 3`, `c` exact cube, no padding | Small-e | `iroot(c, e)` |
| `e = 3`, `c` NOT cube, "short message" | Coppersmith univariate | Sage `small_roots` |
| `e` small, `c` not cube, unknown *k·n* | `iroot(c + k·n, e)`, k ≤ 10⁶ | `general_plus` |
| Same `n`, two `e`, `gcd(e₁,e₂)=1` | Common Modulus | Bezout |
| Same `n`, two `e`, `gcd(e₁,e₂)=g>1` | `m^g`, then g-root / Coppersmith | Sage |
| ≥ e moduli, same `e`, same `m` | Håstad Broadcast | CRT + `iroot` |
| ≥ e moduli, same `e`, `m^e > N` | Håstad + Coppersmith | Sage |
| Multiple moduli, any pair `gcd > 1` | Batch GCD | `general_plus` |
| `n` small (≤ 128 bits) | Trial factor / Pollard rho | `general_plus` |
| `p ≈ q` ("close primes") | Fermat | `general_plus` |
| `d < n^0.25` (hint "small d") | Wiener | `general_plus` |
| `d < n^0.292`, `e ≈ n` (Wiener failed) | Boneh–Durfee | Sage + LLL |
| `p − 1` smooth | Pollard p−1 | `general_plus` |
| Known `φ(n)` or `λ(n)` | Vieta on `p+q` | `factor_from_phi` |
| Known `p+q`, `p−q`, `p²+q²` | Vieta / discriminant | `factor_from_*` |
| Known `dp` or `dq` | `p = (e·dp − 1)/k + 1`, k ∈ [1, e) | `factor_from_dp` |
| `q = a·p + b` known | Solve `a·p² + b·p − n = 0` | `factor_from_linear` |
| `n = p·q·r·...` (multi-prime) | Factor fully, `φ = ∏(pi−1)` | `factor_multi_prime` |
| Partial plaintext (prefix/suffix/bits) | Coppersmith | Sage |
| `m` in small set (PIN, day, yes/no) | Brute force | `attack_pin`, dict |
| Two ciphertexts, `m₂ = a·m₁ + b` | Franklin–Reiter | Sage GCD |
| Known pair `(m₁, c₁)`, want `m₂` | Multiplicative: `m₂ = m₁·(c₂/c₁)^d` — needs d | Usually no |
| RSA signature verification | Textbook forgery `s = s₁·s₂ mod n` | Manual |
| PKCS#1 v1.5 sig., `e=3`, lax check | Bleichenbacher '06 | Manual `iroot` |

---

## 2. Core Formulas — Write These on Paper

```
n = p·q                          (2-prime)
n = p·q·r·...                    (multi-prime)
φ(n) = (p−1)(q−1)                = n − (p+q) + 1
φ(n) = ∏(pi − 1)                 (multi-prime)
λ(n) = lcm(p−1, q−1)             = φ(n) / gcd(p−1, q−1)
e·d ≡ 1 (mod φ(n))
c = m^e mod n
m = c^d mod n

From φ(n):     s = p+q = n − φ(n) + 1
From s:        p, q = (s ± √(s² − 4n)) / 2
From diff δ:   p, q = (√(δ² + 4n) ± δ) / 2
From p²+q²:    s = √(p²+q² + 2n)

Wiener bound:        d < (1/3)·n^(1/4)
Boneh–Durfee bound:  d < n^0.292
Coppersmith (uni):   |x₀| < n^(1/e),  x₀ root of f mod n
Coppersmith (partial p): |x₀| < n^(β²/δ) for f mod p, p ≥ n^β
```

---

## 3. Algebraic Recovery — No Sage Needed

Work through these **in order** before touching code.

### 3.1 Known `φ(n)` or `p+q`
```
s = n − φ + 1              (or s given)
disc = s² − 4n
if disc is a perfect square:
    p = (s + √disc)/2,  q = (s − √disc)/2
```

### 3.2 Known `p − q = δ`
```
disc = δ² + 4n
p = (√disc + δ)/2,  q = (√disc − δ)/2
```

### 3.3 Known `dp = d mod (p−1)`
```
for k in 1..e−1:
    if (e·dp − 1) % k == 0:
        p_candidate = (e·dp − 1)/k + 1
        if p_candidate divides n: FOUND
```

### 3.4 Known `q = a·p + b`
```
a·p² + b·p − n = 0
p = (−b + √(b² + 4an)) / (2a)
```

### 3.5 Known `n`, `e`, and one plaintext-ciphertext pair `(m₀, c₀)`
- If `m₀` shares factors with `n` → factor `n` immediately.
- If `gcd(c₀, n) > 1` → that gcd **is** a factor of `n`.
- Otherwise: no direct attack, look for structure.

### 3.6 Multi-prime — `n = p·q·r`
Once you factor partially, **do NOT assume two factors**:
```
if remaining cofactor is composite:
    φ(n) = (p−1)(q−1)(r−1)   ← not (p−1)(q−1)
```
Check `isprime(cofactor)` before computing `φ`.

---

## 4. Coppersmith — When and How (Sage)

### 4.1 Small-e + modular reduction
```python
# c = m^e mod n, but m^e > n. Search m^e = c + k·n.
for k in range(10**6):
    r, exact = iroot(c + k*n, e)
    if exact: return r
```

### 4.2 Partial plaintext (prefix known)
```python
# m = prefix · 2^(8·u) + x,  x < 2^(8·u),  u = unknown bytes
R.<x> = PolynomialRing(Zmod(n))
f = (prefix * 2^(8*u) + x)^e - c
roots = f.small_roots(X=2^(8*u), beta=1.0)
```

### 4.3 Partial plaintext (low bits known)
```python
# m = x · 2^(8·u) + low
f = (x * 2^(8*u) + low)^e - c
roots = f.small_roots(X=2^(8*u), beta=1.0)
```

### 4.4 Håstad with Coppersmith
```python
# CRT gives X = m^e mod N. If m^e > N, root of x^e − X mod N is small.
R.<x> = PolynomialRing(Zmod(N))
f = x^e - X
roots = f.small_roots(X=2^m_max_bits, beta=1.0)
```

### 4.5 Common Modulus with `m^g > n`
```python
# After Bezout: mg = m^g mod n
f = x^g - mg
roots = f.small_roots(X=2^m_max_bits, beta=1.0)
```

### 4.6 When Coppersmith Applies
- Unknown part **strictly smaller** than `n^(1/e)`.
- **Rule of thumb:** if unknown ≤ `(n.bit_length() / e) − 16` bits, safe.
- `e = 3` and unknown ≤ 2 bytes → brute force in Python, no Sage.
- `e = 3` and unknown ≤ 4 bytes → 4·10⁹ iterations, too slow in Python. Use Sage or accept ~10 min.

---

## 5. Boneh–Durfee — Debug Checklist

Before running LLL:
- [ ] `e` is close to `n` (small `d` usually means huge `e`)
- [ ] Wiener **failed** (otherwise use Wiener — it's O(log n))
- [ ] `d.bit_length() < 0.292 · n.bit_length()`
- [ ] Lattice params: start `m=3, t=1` → if fail, `m=4, t=2` → `m=6, t=3`
- [ ] `delta = 0.26` (safe) → try `0.28` if fails
- [ ] Verify `d` by checking `pow(pow(2, e, n), d, n) == 2`

**If BD fails after `m=6`:** the bound is likely violated. Re-read the challenge — maybe `d` is not the leak, `dp` or `dq` is.

---

## 6. Franklin–Reiter — Recognize & Solve

**Signature:** `c₁ = m^e`, `c₂ = (a·m + b)^e`, same `n`, same `e`. `a, b` are given or "obvious" (e.g., `m₂ = m₁ + 1` → `a=1, b=1`).

**Sage (works up to `e ≈ 30`):**
```python
R.<x> = PolynomialRing(Zmod(n))
f1 = x^e - c1
f2 = (a*x + b)^e - c2
g = f1.gcd(f2)
if g.degree() == 1:
    m = Integer(-g[0] * inverse_mod(g[1], n) % n)
```

**Python fallback: NO** — for `e ≥ 3` you genuinely need polynomial GCD over `Z/nZ`. Small `e = 2` can be solved via resultant algebra manually, but it's rare.

**Special case `m₂ = m₁ + 1`, `e = 3`** — closed form exists:
```
m = (2·c₂ − c₁ + 2) / (6·m₁ + 3) ... but m₁ is unknown
```
→ Still requires Sage. Don't attempt by hand.

---

## 7. RSA Signatures

### 7.1 Textbook signature forgery
Goal: produce `s` such that `s^e ≡ m_target (mod n)`.

- **Multiplicative:** if `m_target = m₁ · m₂ mod n` and you have valid `s₁, s₂`, then `s = s₁·s₂ mod n`.
- **Chosen message:** get `s₁ = m₁^d` for arbitrary `m₁` from oracle → sign anything `m = m₁ · r^e mod n` with `s = s₁ · r`.
- **`m = 0`, `m = 1`, `m = n−1`:** trivial signatures `s = 0, 1, n−1` for those `m`.

### 7.2 Bleichenbacher '06 (`e = 3`, PKCS#1 v1.5, lax verifier)
If verifier only checks prefix `00 01 FF ... FF 00 <hash>` without checking total length:
```python
# Construct message integer that starts with valid prefix but overflows.
# s = iroot(target_with_trailing_zeros, 3)
target = bytes.fromhex('0001FFFFFFFF00') + hash_bytes + b'\x00' * extra
s = iroot(int.from_bytes(target, 'big'), 3)[0]
# Only works if s³ mod n gives valid prefix when left-padded/truncated
```

---

## 8. Dictionary / Brute Force — When & How

| Search space | Approx. iterations | Feasible in Python? |
|---|---|---|
| 2 (YES/NO) | 2 | Trivial |
| 7 (day of week) | 7 | Trivial |
| 12 (month) | 12 | Trivial |
| 3-digit PIN | 10³ | Trivial |
| 4-digit PIN | 10⁴ | Trivial |
| 6-digit PIN | 10⁶ | ~1 sec |
| 8-digit PIN | 10⁸ | ~2 min |
| 3 lowercase chars | 26³ ≈ 17k | Trivial |
| 4 lowercase chars | 26⁴ ≈ 457k | ~1 sec |
| 5 lowercase chars | 26⁵ ≈ 12M | ~30 sec |
| 6 lowercase chars | 26⁶ ≈ 300M | ~15 min |

**Critical rule:** encrypting candidates with `e = 65537` takes ~1 ms each. With `e = 3` it's much faster. Time your first 1000 iterations and extrapolate **before** launching a long run.

**Encoding matters:** `b'1234'` ≠ `bytes.fromhex('1234')` ≠ integer `1234`. Try **all three** representations.

---

## 9. Common Traps (Check Every Time)

1. **Block cipher truncation** — forgot to strip trailing zero padding → garbage. Use `original_length`.
2. **Multi-prime detection** — `p*q != n` after factoring → there are ≥ 3 factors. Compute `φ = ∏(pi−1)`, not `(p−1)(q−1)`.
3. **Wrong encoding** — bytes vs integer vs hex string. Print `m` in all three forms.
4. **`m^e < n` assumption** — always verify `pow(m, e, n) == c` after finding `m`.
5. **Ciphertext associated with wrong key** — when multiple `(n, e, c)`, verify alignment before combining.
6. **`e` and `d` swapped** — sometimes challenge gives "private exponent" as `e`. If `e > n`, suspect it's actually `d`.
7. **`gcd(e, φ) ≠ 1`** — decryption via `c^d` impossible; but `e`-th root mod n still possible if `m^e < n` or via CRT on prime factors.
8. **Different padding on two "same" messages** — Common Modulus breaks. Check if `c₁, c₂` correspond to identical `m`.
9. **Trailing/leading whitespace in flag** — flag regex like `\w+\{[^}]+\}` should allow it; check stripped and unstripped.
10. **Multi-level challenge** — first result is an intermediate value (e.g., a key), not the final flag. Re-run analysis with it as input.

---

## 10. Escalation Ladder (Try in Order)

```
1. Re-read problem statement (5 sec hint scan)
2. general_plus.py  (automated baseline)
3. sage_attacks.sage  (Coppersmith + BD + FR)
4. Manual algebra: label numbers, write equations, solve
5. Parameter tuning:
      Fermat max_iter:    10^6  → 10^8
      Pollard B:          10^5  → 10^6
      small_e max_k:      10^5  → 10^7
6. Read raw challenge file again — check hidden fields
7. Timebox: 20 min per problem, then MOVE ON. Return with fresh eyes.
```

---

## 11. Before the Exam — Checklist

- [ ] `sage --version` works
- [ ] `sage_attacks.sage` runs on a test Coppersmith input
- [ ] `general_plus.py` runs on a test input
- [ ] Print/save this cheat sheet
- [ ] Have these accessible:
  - Python with `pycryptodome`, `sympy`, `gmpy2`
  - SageMath (local or sagecell.sagemath.org)
  - Calculator with big-int support (or just Python REPL)
- [ ] Memorized:
  - Vieta for `p+q`
  - `d < n^0.25` (Wiener), `d < n^0.292` (BD)
  - Coppersmith bound: `|x₀| < n^(1/e)`
  - `φ(n) = n − (p+q) + 1`
- [ ] Wrote on paper: formula reference from §2 above

---

## 12. The Honest Truth

If you find yourself staring at "ALL ATTACKS FAILED" with no clear path:

1. **You almost certainly missed a hint in the problem statement.** Re-read every sentence. Look for: `leaked`, `hint`, `note`, `assume`, `suppose`, `given that`, `approximately`, `close`, `small`, `partial`, `related`, `same`.

2. **Check the shape of the numbers.** `n.bit_length()` vs `e.bit_length()` vs `c.bit_length()`:
   - `c` much smaller than `n` → small-e, no reduction.
   - `e` ≈ `n` in size → small `d` (Wiener / BD).
   - `n` has odd bit length like 513, 1024, 2048 → textbook. 1023, 1025 → suspicious, check `p`, `q` construction.

3. **If the problem is genuinely unsolvable with your tools:** write down what you *would* do if you had Sage / more time. Partial credit is real. Show your analysis.

4. **One more re-read.** Yes. Again.

