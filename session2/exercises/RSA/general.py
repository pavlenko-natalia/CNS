#!/usr/bin/env python3
"""
RSA Attack Suite for CNS exam preparation
==========================================

USAGE:
    python rsa_suite.py challenge.json
    python rsa_suite.py public_keys.txt ciphertexts.txt

SUPPORTED INPUT FORMATS (auto-detected):
    A) {"n": "...", "e": 65537, "c": "..."}                  -> single-key attacks
    B) {"n": "...", "e1": ..., "e2": ..., "c1": ..., "c2": ...} -> Common Modulus
    C) {"n", "e", "ciphertext": [c1, c2, ...],
        "block_size": 8, "original_length": 112}             -> block cipher
    D) public_keys.txt + ciphertexts.txt (text format)        -> multi-key attacks

ATTACK ORDER (fastest / most-likely first):
    1. Small-e, no padding         (m^e < n, take e-th root)
    2. Common Modulus              (same n, two e's, same m)
    3. Håstad Broadcast            (small e, multiple n's, same m)
    4. Common Factor               (gcd between n's > 1)
    5. Fermat factorization        (p and q close)
    6. Wiener's attack             (small private exponent d)
    7. Pollard p-1                 (smooth p-1)
    8. Small-n factorization       (Pollard rho + sympy)
"""

import json
import sys
import re
from math import isqrt, gcd

# ---- Dependencies with graceful fallback ----
try:
    from Crypto.Util.number import inverse as _inv, long_to_bytes, bytes_to_long
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False

try:
    from sympy import factorint, isprime
    HAS_SYMPY = True
except ImportError:
    HAS_SYMPY = False


# ==========================================================================
# Basic helpers
# ==========================================================================

def egcd(a, b):
    """Extended Euclidean: returns (g, x, y) with a*x + b*y = g = gcd(a,b)."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    """Modular inverse a^{-1} mod m. Raises ValueError if not invertible."""
    if HAS_PYCRYPTODOME:
        return int(_inv(a, m))
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a}, {m}) = {g}")
    return x % m


def iroot(n, k):
    """
    Integer k-th root of n: returns (root, is_exact) with root^k == n if exact.

    IMPORTANT: do NOT use n ** (1/k) — float loses precision for large ints.
    Uses exact binary search (or gmpy2 if available).
    """
    if n < 0:
        return (None, False)
    if n == 0:
        return (0, True)
    if HAS_GMPY2:
        root, exact = gmpy2.iroot(int(n), int(k))
        return (int(root), bool(exact))
    lo, hi = 0, 1
    while hi ** k <= n:
        hi *= 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return (lo, lo ** k == n)


def long_to_bytes_safe(n):
    """Integer -> bytes (big-endian). Handles n == 0 edge case."""
    if n == 0:
        return b'\x00'
    if HAS_PYCRYPTODOME:
        return long_to_bytes(n)
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


def bytes_to_long_safe(b):
    """Bytes -> integer (big-endian)."""
    if HAS_PYCRYPTODOME:
        return bytes_to_long(b)
    return int.from_bytes(b, 'big')


def as_int(v):
    """Coerce JSON value to int (handles int or numeric string)."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v.strip())
    raise TypeError(f"Cannot coerce {type(v)} to int")


def try_decode(m):
    """Try to decode m as UTF-8 text. Returns str or None if not text-like."""
    if m is None or m <= 0:
        return None
    b = long_to_bytes_safe(m)
    try:
        s = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    # Heuristic: mostly printable, reasonable length
    if not s:
        return None
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in '\n\r\t')
    if printable / len(s) < 0.85:
        return None
    return s


def report(attack_name, m):
    """Unified success report. Returns True if output looks like a flag."""
    s = try_decode(m)
    print(f"\n{'='*60}")
    print(f"[+] SUCCESS via {attack_name}")
    print(f"{'='*60}")
    print(f"    m (integer) = {m}")
    if s is not None:
        print(f"    m (text)    = {s!r}")
        if any(t in s.lower() for t in ('flag{', 'ctf{', 'cns{', 'htb{')):
            print(f"\n    ⭐ FLAG DETECTED")
    else:
        print(f"    m (hex)     = {m:x}")
        print(f"    (not valid UTF-8 — inspect manually as bytes)")
        print(f"    m (bytes)   = {long_to_bytes_safe(m)}")
    return True


# ==========================================================================
# Decryption helpers
# ==========================================================================

def decrypt_single(n, e, c, p, q):
    """
    Standard RSA decryption given p, q.

    MATH: phi(n) = (p-1)(q-1). d = e^{-1} mod phi. m = c^d mod n.

    PITFALL: gcd(e, phi) != 1 (rare in well-formed RSA) — inverse fails.
    """
    if p * q != n:
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        return None
    return pow(c, d, n)


def decrypt_blocks(n, e, cs, block_size, original_length, p, q):
    """
    Decrypt a block-cipher RSA challenge (each c_i = one plaintext block).

    MATH: same as single, but for each block:
        m_i = c_i^d mod n, then m_i.to_bytes(block_size, 'big')
    Concatenate all blocks, then truncate to original_length.

    PITFALL: forgetting to truncate leaves trailing zero padding bytes
             (from fixed block_size). Forgetting big-endian -> garbage.
    """
    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        return None
    out = bytearray()
    for c in cs:
        m = pow(c, d, n)
        try:
            out.extend(m.to_bytes(block_size, 'big'))
        except OverflowError:
            return None
    return bytes(out[:original_length])


# ==========================================================================
# ATTACK 1: Small-e, no padding
# ==========================================================================

def attack_small_e(n, e, c):
    """
    Small-exponent attack (m^e < n, no padding)
    ============================================

    CONDITION:
        - e is small (typically 3, 5, or 7)
        - m is short enough that m^e < n (no modular reduction occurred)
        - textbook RSA: no PKCS#1 / OAEP padding

    MATH:
        c = m^e mod n. If m^e < n, then modular reduction is a no-op:
            c = m^e as ordinary integer.
        So m = e-th integer root of c.

    DETECTION:
        Compute exact e-th root. If root^e == c, we have m.

    PITFALLS:
        - WITH padding, m includes random padding bytes and m^e > n
          almost surely. Attack fails. Use Håstad instead.
        - For e >= 11, m would need to be < ~2^10 (tiny) for m^e < n.
          Unrealistic unless the challenge is intentionally trivial.
        - If c happens to be a perfect e-th power but m^e > n (coincidence),
          the root is NOT m — this is astronomically rare.
    """
    if e > 11:
        return None
    root, exact = iroot(c, e)
    if exact:
        return root
    return None


# ==========================================================================
# ATTACK 2: Common Modulus
# ==========================================================================

def attack_common_modulus(n, e1, e2, c1, c2):
    """
    Common Modulus Attack
    =====================

    CONDITION:
        - Same modulus n for two encryptions
        - Different exponents e1, e2 with gcd(e1, e2) = 1
        - Same plaintext m encrypted under both

    MATH:
        c1 = m^{e1} mod n, c2 = m^{e2} mod n.
        Bezout: exist a, b with a*e1 + b*e2 = 1.
        Then:
            c1^a * c2^b = m^{a*e1} * m^{b*e2} = m^{a*e1+b*e2} = m (mod n).
        Negative exponents become modular inverses: c^{-k} = (c^{-1})^k.

    PITFALLS:
        - If gcd(e1, e2) > 1, we get m^g, not m. Then need g-th root
          with g possible sign choices (advanced).
        - If the two encryptions used different padding, m1 != m2, attack
          breaks entirely.
        - If c1 is not invertible mod n (gcd(c1, n) > 1), we've actually
          factored n as a side effect.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        print(f"    [!] gcd(e1, e2) = {g} != 1 — attack requires coprime e's")
        return None
    if a < 0:
        c1 = modinv(c1, n)
        a = -a
    if b < 0:
        c2 = modinv(c2, n)
        b = -b
    return (pow(c1, a, n) * pow(c2, b, n)) % n


# ==========================================================================
# ATTACK 3: Håstad Broadcast
# ==========================================================================

def attack_hastad(ns, e, cs):
    """
    Håstad's Broadcast Attack
    =========================

    CONDITION:
        - Same plaintext m encrypted under e (or more) different moduli n_i
        - Same small exponent e for all (typically e = 3)
        - Moduli pairwise coprime (otherwise use Common Factor instead)

    MATH:
        c_i = m^e mod n_i for i = 1, ..., e.
        CRT gives X ≡ c_i (mod n_i) for all i, with X ∈ [0, N),
            N = n_1 * n_2 * ... * n_e.
        So X ≡ m^e (mod N).
        If m^e < N (typical for small e and moderate m), then X = m^e exactly.
        Then m = e-th integer root of X.

    DETECTION:
        Need at least e ciphertexts. If more than e are available, use any
        e of them (or better: use all — bigger N makes m^e < N more likely).

    PITFALLS:
        - Moduli MUST be pairwise coprime. If any gcd(n_i, n_j) > 1,
          CRT fails; use Common Factor (and possibly recover p, q for
          each and decrypt directly).
        - If m^e > N (rare but possible for large m or small e), CRT
          gives m^e mod N. Taking root gives wrong answer. Would need
          Coppersmith's method (not covered here).
        - Using exactly e ciphertexts is sufficient; using more is better.
    """
    if len(cs) < e:
        print(f"    [!] Need >= {e} ciphertexts, have {len(cs)}")
        return None
    use_ns = ns[:e]
    use_cs = cs[:e]
    # Check pairwise coprimality
    for i in range(len(use_ns)):
        for j in range(i + 1, len(use_ns)):
            if gcd(use_ns[i], use_ns[j]) != 1:
                print(f"    [!] gcd(n_{i}, n_{j}) != 1 — Håstad needs coprime moduli")
                return None
    # CRT
    N = 1
    for n in use_ns:
        N *= n
    X = 0
    for ci, ni in zip(use_cs, use_ns):
        Ni = N // ni
        X += ci * Ni * modinv(Ni, ni)
    X %= N
    # e-th root
    m, exact = iroot(X, e)
    if exact:
        return m
    print(f"    [!] Not an exact {e}-th root (m^e > N?)")
    return None


# ==========================================================================
# ATTACK 4: Common Factor
# ==========================================================================

def attack_common_factor(ns, cs, es):
    """
    Common Factor Attack
    ====================

    CONDITION:
        Two or more moduli n_i, n_j share a prime factor p
        (due to bad RNG, recycled "primes", or intentionally planted).

    MATH:
        gcd(n_i, n_j) = p  <=>  they share prime p.
        n_i = p * q_i, n_j = p * q_j. Recover q_i, q_j by division.
        Now factor both moduli; recover d = e^{-1} mod phi; decrypt.

    DETECTION:
        O(k^2) gcd calls for k moduli — trivial.

    PITFALLS:
        - gcd == 1 means no shared factor; this attack fails for that pair.
        - gcd == n_i (one divides the other): pathological, easy to handle
          separately (n_j // n_i gives another factor).
        - Batch GCD with product tree is faster for huge numbers of keys,
          but O(k^2) is fine for < 100 keys.
    """
    results = {}
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = gcd(ns[i], ns[j])
            if 1 < g < ns[i] and 1 < g < ns[j]:
                results[i] = (g, ns[i] // g)
                results[j] = (g, ns[j] // g)
    if not results:
        print("    [-] No shared factors")
        return None
    print(f"    [+] Shared factors found for indices: {sorted(results.keys())}")
    for idx in sorted(results.keys()):
        p, q = results[idx]
        print(f"        idx {idx}: p = {p}, q = {q}")
        if idx < len(cs) and idx < len(es):
            m = decrypt_single(ns[idx], es[idx], cs[idx], p, q)
            if m is not None:
                report(f"Common Factor (idx={idx})", m)
                return True
    return True  # Found factors even if decryption failed


# ==========================================================================
# ATTACK 5: Fermat factorization
# ==========================================================================

def attack_fermat(n, max_iter=10**6):
    """
    Fermat Factorization
    ====================

    CONDITION:
        p and q are close: |p - q| small relative to n.
        Common in badly-generated keys like
        p = next_prime(random()); q = next_prime(p).

    MATH:
        n = p * q, write p = a - b, q = a + b.
        Then n = a^2 - b^2, so a^2 - n = b^2.
        Iterate a = ceil(sqrt(n)), ceil(sqrt(n))+1, ...
        Check if a^2 - n is a perfect square. If yes, p = a - b, q = a + b.

    COMPLEXITY:
        O(|p - q|) iterations. Fast if p ≈ q, infeasible if far apart.

    PITFALLS:
        - For 2048-bit n with random primes (p, q ~ 2^1024, |p-q| ~ 2^512),
          would need ~2^512 iterations — infeasible. Only works if very close.
        - Iteration limit prevents hanging. Increase if challenge hints at
          "close primes" but attack didn't finish.
        - isqrt on huge numbers is exact (integer), unlike sqrt — no float
          precision loss.
    """
    a = isqrt(n) + 1
    for _ in range(max_iter):
        b2 = a * a - n
        if b2 >= 0:
            b = isqrt(b2)
            if b * b == b2:
                p = a - b
                q = a + b
                if p * q == n and p > 1:
                    return (p, q)
        a += 1
    return None


# ==========================================================================
# ATTACK 6: Wiener's attack
# ==========================================================================

def attack_wiener(n, e):
    """
    Wiener's Attack
    ===============

    CONDITION:
        Private exponent d is small:
            d < (1/3) * n^(1/4).

    MATH:
        RSA: e*d ≡ 1 (mod phi(n)), so e*d - k*phi(n) = 1 for some integer k.
        Rearranging: e/phi(n) = k/d + 1/(d*phi(n)).
        Since phi(n) ≈ n, we have e/n ≈ k/d.
        Continued fraction expansion of e/n: convergents h_i/k_i approximate
        k/d. For each convergent, treat denominator as candidate d.
        Compute phi = (e*d - 1)/k, then p+q = n - phi + 1.
        p, q are roots of x^2 - (n - phi + 1)x + n = 0.
        If discriminant is a perfect square and p*q = n, we win.

    DETECTION:
        Cheap (O(log n) convergents). Try for any (n, e).

    PITFALLS:
        - Fails if d is NOT small. Standard RSA (e=65537, d ~ phi) is safe.
        - Need (e*d - 1) % k == 0 check to prune false candidates.
        - Discriminant must be a perfect square AND (p+q) even (both odd
          primes -> p+q even -> p, q integers).
        - If e is small (e.g. 3), Wiener almost never applies.
    """
    # Continued fraction of e/n
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    # Convergents: p_curr/q_curr approximates e/n; we want p_curr/q_curr ~ k/d
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for ai in cf:
        p_next = ai * p_curr + p_prev
        q_next = ai * q_curr + q_prev
        k_cand = p_next
        d_cand = q_next
        if d_cand != 0 and k_cand != 0:
            if (e * d_cand - 1) % k_cand == 0:
                phi = (e * d_cand - 1) // k_cand
                s = n - phi + 1
                disc = s * s - 4 * n
                if disc >= 0:
                    t = isqrt(disc)
                    if t * t == disc and (s + t) % 2 == 0:
                        p_c = (s + t) // 2
                        q_c = (s - t) // 2
                        if p_c * q_c == n and p_c > 1:
                            return d_cand
        p_prev, p_curr = p_curr, p_next
        q_prev, q_curr = q_curr, q_next
    return None


# ==========================================================================
# ATTACK 7: Pollard p-1
# ==========================================================================

def _sieve_primes(limit):
    """Simple Sieve of Eratosthenes."""
    if limit < 2:
        return []
    s = bytearray([1]) * (limit + 1)
    s[0] = s[1] = 0
    for i in range(2, isqrt(limit) + 1):
        if s[i]:
            s[i*i::i] = bytearray(len(s[i*i::i]))
    return [i for i, v in enumerate(s) if v]


def attack_pollard_p_minus_1(n, B=10**6):
    """
    Pollard's p-1 Algorithm
    =======================

    CONDITION:
        p - 1 is B-smooth: all prime factors of p-1 are <= B.

    MATH:
        If p | n and p-1 | M (M = lcm of 1..B, or product of prime powers),
        then by Fermat's little theorem: a^M ≡ 1 (mod p) for any a coprime to p.
        So p | gcd(a^M - 1, n). Compute gcd — if nontrivial, we found p.

    DETECTION:
        Try any n; succeeds if p-1 happens to be smooth.

    PITFALLS:
        - If p-1 has a large prime factor, fails.
        - If B too large and n's both primes have smooth p-1, gcd = n
          (overshoot). Try smaller B.
        - RSA keys generated for DSA compatibility (p = 2*q*small + 1) are
          vulnerable; uniformly random primes rarely are.
    """
    a = 2
    for prime in _sieve_primes(B):
        pk = prime
        while pk * prime <= B:
            pk *= prime
        a = pow(a, pk, n)
        d = gcd(a - 1, n)
        if 1 < d < n:
            return d
        if d == n:
            return None
    return None


# ==========================================================================
# ATTACK 8: Small-n factorization (Pollard rho + sympy)
# ==========================================================================

def _pollard_rho(n, max_iter=10**7):
    """
    Pollard's rho algorithm for integer factorization.

    MATH:
        Iterate x -> x^2 + c mod n. Floyd cycle-finding detects when the
        sequence cycles modulo a factor p of n, revealing p via gcd(|x-y|, n).

    COMPLEXITY:
        O(sqrt(p)) where p is the smallest factor. For 64-bit n with
        32-bit p, that's ~2^16 = 65k iterations.

    PITFALLS:
        - Needs retries with different c/x if first attempt fails.
        - Slower than Fermat for close primes; faster for random primes.
    """
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    import random as _r
    _r.seed(0)
    for _attempt in range(10):
        c = _r.randrange(1, n)
        x = _r.randrange(2, n)
        y = x
        for _ in range(max_iter):
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
            if 1 < d < n:
                return d
            if d == n:
                break
    return None


def attack_small_n(n):
    """
    Factor a small n (~64 bits via Pollard rho; ~100+ bits via sympy).

    CONDITION:
        n is small enough that its factorization is tractable:
            < 64 bits   -> Pollard rho in seconds
            < 100 bits  -> sympy.factorint in minutes
            > 128 bits  -> generally infeasible with standard methods

    PITFALLS:
        - "Small" is fuzzy. 128-bit n needs ECM or specialized methods.
        - sympy.factorint uses multiple algorithms — usually the best
          single call to make.
    """
    d = _pollard_rho(n)
    if d and d != n:
        return (d, n // d)
    if HAS_SYMPY:
        try:
            f = factorint(n, limit=10**6)
            primes = [p for p, e in f.items() for _ in range(e)]
            if len(primes) == 2 and primes[0] * primes[1] == n:
                return tuple(primes)
        except Exception:
            pass
    return None


# ==========================================================================
# Input parsing
# ==========================================================================

def load_input(argv):
    """Load challenge from command-line arguments."""
    if len(argv) == 1:
        path = argv[0]
        if path.endswith('.json'):
            with open(path) as f:
                return json.load(f)
        # text format
        with open(path) as f:
            text = f.read()
        return {
            'ns': [int(x) for x in re.findall(r'n\s*=\s*(\d+)', text)],
            'es': [int(x) for x in re.findall(r'\be\s*=\s*(\d+)', text)],
            'cs': [int(x) for x in re.findall(r'c\d*\s*=\s*(\d+)', text)],
        }
    if len(argv) == 2:
        with open(argv[0]) as f:
            kt = f.read()
        with open(argv[1]) as f:
            ct = f.read()
        return {
            'ns': [int(x) for x in re.findall(r'n\s*=\s*(\d+)', kt)],
            'es': [int(x) for x in re.findall(r'\be\s*=\s*(\d+)', kt)],
            'cs': [int(x) for x in re.findall(r'c\d*\s*=\s*(\d+)', ct)],
        }
    raise ValueError("Usage: rsa_suite.py <file.json | keys.txt [cs.txt]>")


def normalize(challenge):
    """
    Normalize challenge dict to consistent fields:
      ns : list of moduli
      es : list of exponents
      cs : list of ciphertext blocks
      is_block_cipher : bool (block-cipher mode)
      block_size, original_length : only if block cipher
    """
    out = {}

    # --- Moduli ---
    if 'ns' in challenge:
        out['ns'] = [int(x) for x in challenge['ns']]
    elif 'n' in challenge:
        out['ns'] = [as_int(challenge['n'])]
    else:
        out['ns'] = []

    # --- Exponents (handle e1/e2 case) ---
    if 'e1' in challenge and 'e2' in challenge:
        out['es'] = [as_int(challenge['e1']), as_int(challenge['e2'])]
        out['cs'] = [as_int(challenge['c1']), as_int(challenge['c2'])]
        out['is_block_cipher'] = False
        return out

    if 'es' in challenge:
        out['es'] = [int(x) for x in challenge['es']]
    elif 'e' in challenge:
        out['es'] = [as_int(challenge['e'])]
    else:
        out['es'] = []

    # --- Ciphertext ---
    if 'ciphertext' in challenge:
        ct = challenge['ciphertext']
        if isinstance(ct, list):
            out['cs'] = [as_int(x) for x in ct]
            out['is_block_cipher'] = True
            out['block_size'] = int(challenge.get('block_size', 8))
            out['original_length'] = int(
                challenge.get('original_length',
                              len(out['cs']) * out['block_size']))
        else:
            out['cs'] = [as_int(ct)]
            out['is_block_cipher'] = False
    elif 'cs' in challenge:
        out['cs'] = [int(x) for x in challenge['cs']]
        out['is_block_cipher'] = False
    elif 'c' in challenge:
        out['cs'] = [as_int(challenge['c'])]
        out['is_block_cipher'] = False
    else:
        out['cs'] = []
        out['is_block_cipher'] = False

    return out


# ==========================================================================
# Main dispatch
# ==========================================================================

def solve(challenge):
    info = normalize(challenge)
    ns, es, cs = info['ns'], info['es'], info['cs']
    is_block = info.get('is_block_cipher', False)

    print("=" * 60)
    print("RSA Attack Suite — starting analysis")
    print("=" * 60)
    print(f"  moduli:    {len(ns)}")
    for i, n in enumerate(ns):
        print(f"    n[{i}]: {n.bit_length()} bits")
    print(f"  exponents: {es}")
    print(f"  ciphertexts: {len(cs)}")
    print(f"  block cipher: {is_block}")
    if is_block:
        print(f"    block_size: {info['block_size']}, "
              f"original_length: {info['original_length']}")

    # Quick sanity
    n = ns[0] if ns else None
    e = es[0] if es else None
    c = cs[0] if cs else None

    def try_decrypt_all_blocks(p, q, attack_name):
        """Helper: decrypt all blocks given p, q."""
        pt = decrypt_blocks(n, e, cs,
                            info['block_size'],
                            info['original_length'], p, q)
        if pt is None:
            print(f"    [!] Block decryption failed")
            return False
        print(f"\n{'='*60}")
        print(f"[+] SUCCESS via {attack_name} (block cipher)")
        print(f"{'='*60}")
        print(f"    bytes: {pt}")
        try:
            print(f"    text:  {pt.decode('utf-8')!r}")
        except UnicodeDecodeError:
            print(f"    (not UTF-8)")
        return True

    # ---- Attack 1: small-e, no padding ----
    if n and e and c and e <= 11 and not is_block:
        print("\n[→] Attack 1: small-e, no padding")
        m = attack_small_e(n, e, c)
        if m is not None:
            return report("small-e no padding", m)
        print("    [-] not an exact e-th power")

    # ---- Attack 2: Common Modulus ----
    if len(set(ns)) == 1 and len(es) == 2 and len(cs) == 2:
        print("\n[→] Attack 2: Common Modulus")
        m = attack_common_modulus(ns[0], es[0], es[1], cs[0], cs[1])
        if m is not None:
            return report("Common Modulus", m)
        print("    [-] failed")

    # ---- Attack 3: Håstad Broadcast ----
    if len(ns) >= 3 and len(set(es)) == 1 and es[0] <= 11 and len(cs) >= 3:
        print(f"\n[→] Attack 3: Håstad Broadcast (e={es[0]}, {len(ns)} keys)")
        m = attack_hastad(ns, es[0], cs)
        if m is not None:
            return report("Håstad Broadcast", m)
        print("    [-] failed")

    # ---- Attack 4: Common Factor ----
    if len(ns) >= 2:
        print("\n[→] Attack 4: Common Factor")
        if attack_common_factor(ns, cs, es):
            return True
        print("    [-] no shared factors")

    # ---- Attack 5: Fermat ----
    if n:
        print("\n[→] Attack 5: Fermat (close p, q)")
        pq = attack_fermat(n)
        if pq:
            p, q = pq
            print(f"    [+] Found p, q ({p.bit_length()}, {q.bit_length()} bits)")
            if is_block:
                if try_decrypt_all_blocks(p, q, "Fermat"):
                    return True
            else:
                m = decrypt_single(n, e, c, p, q)
                if m is not None:
                    return report("Fermat", m)
        else:
            print("    [-] p, q not close (or > 10^6 iterations)")

    # ---- Attack 6: Wiener ----
    if n and e:
        print("\n[→] Attack 6: Wiener (small d)")
        d = attack_wiener(n, e)
        if d is not None:
            print(f"    [+] d = {d}")
            if is_block:
                out = bytearray()
                for cc in cs:
                    mm = pow(cc, d, n)
                    try:
                        out.extend(mm.to_bytes(info['block_size'], 'big'))
                    except OverflowError:
                        print("    [!] block too large")
                        return False
                pt = bytes(out[:info['original_length']])
                print(f"\n[+] SUCCESS via Wiener (block cipher)")
                print(f"    bytes: {pt}")
                try:
                    print(f"    text:  {pt.decode('utf-8')!r}")
                except UnicodeDecodeError:
                    pass
                return True
            else:
                m = pow(c, d, n)
                return report("Wiener", m)
        print("    [-] d not small")

    # ---- Attack 7: Pollard p-1 ----
    if n and n.bit_length() < 512:
        print("\n[→] Attack 7: Pollard p-1 (smooth p-1)")
        d = attack_pollard_p_minus_1(n, B=10**5)
        if d:
            p, q = d, n // d
            print(f"    [+] p = {p} ({p.bit_length()} bits), q = {q} ({q.bit_length()} bits)")
            if is_block:
                if try_decrypt_all_blocks(p, q, "Pollard p-1"):
                    return True
            else:
                m = decrypt_single(n, e, c, p, q)
                if m is not None:
                    return report("Pollard p-1", m)
        else:
            print("    [-] p-1 not smooth")

    # ---- Attack 8: small-n factorization ----
    if n and n.bit_length() <= 128:
        print("\n[→] Attack 8: small-n factorization")
        pq = attack_small_n(n)
        if pq:
            p, q = pq
            print(f"    [+] Factored: p ({p.bit_length()} bits), q ({q.bit_length()} bits)")
            if is_block:
                if try_decrypt_all_blocks(p, q, "small-n factor"):
                    return True
            else:
                m = decrypt_single(n, e, c, p, q)
                if m is not None:
                    return report("small-n factor", m)
        else:
            print("    [-] factorization failed")

    # ---- All attacks exhausted ----
    print("\n" + "=" * 60)
    print("[-] ALL ATTACKS FAILED")
    print("=" * 60)
    print("    Suggestions:")
    print("      1. Inspect files manually — maybe extra fields, hints")
    print("      2. If p-1 / q-1 might be smooth, increase Pollard p-1 B")
    print("      3. If p, q close, increase Fermat iterations")
    print("      4. Coppersmith / Boneh-Durfee — out of scope here")
    print("      5. Check padding scheme (may need different attack)")
    return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    challenge = load_input(sys.argv[1:])
    solve(challenge)


if __name__ == '__main__':
    main()