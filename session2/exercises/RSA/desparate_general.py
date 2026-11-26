#!/usr/bin/env python3
"""
USAGE:
    python general_plus.py challenge.json
    python general_plus.py public_keys.txt ciphertexts.txt

"""

import json
import sys
import re
import itertools
from math import isqrt, gcd, comb

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
# Basic helpers (shared with general.py)
# ==========================================================================

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    if HAS_PYCRYPTODOME:
        return int(_inv(a, m))
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a}, {m}) = {g}")
    return x % m


def iroot(n, k):
    """Exact integer k-th root. Returns (root, is_exact)."""
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
    if n == 0:
        return b'\x00'
    if HAS_PYCRYPTODOME:
        return long_to_bytes(n)
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')


def bytes_to_long_safe(b):
    if HAS_PYCRYPTODOME:
        return bytes_to_long(b)
    return int.from_bytes(b, 'big')


def as_int(v):
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v.strip())
    raise TypeError(f"Cannot coerce {type(v)} to int")


# ==========================================================================
# Quality scoring — fixes the false-positive report() problem
# ==========================================================================

FLAG_MARKERS = ('flag{', 'ctf{', 'cns{', 'htb{', 'picoctf{', 'ractf{',
                'uac{', 'asu{', 'ductf{', 'uiuctf{', 'crew{', 'nactf{')

def _quality(m):
    """
    Returns (score, text_or_None) where score ∈ [0, 1].
    Score > 0.7 means it's likely a real plaintext.
    Score near 0.3 means valid bytes but not text (candidate but not answer).
    """
    if m is None or m <= 0:
        return 0.0, None
    b = long_to_bytes_safe(m)
    if not b:
        return 0.0, None
    try:
        s = b.decode('utf-8')
    except UnicodeDecodeError:
        return 0.3, None
    if not s:
        return 0.0, None
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in '\n\r\t')
    ratio = printable / len(s)
    if any(t in s.lower() for t in FLAG_MARKERS):
        return 1.0, s
    if ratio < 0.85:
        return ratio * 0.5, None
    return ratio * 0.7 + 0.2, s


def _print_and_score(attack_name, m, extra=""):
    """Print result and return (score, text). Does NOT return success flag."""
    q, s = _quality(m)
    if m is None:
        return q, s
    print(f"\n{'='*60}")
    tag = "SUCCESS" if q >= 0.7 else ("partial" if q >= 0.3 else "candidate")
    print(f"[{tag}] {attack_name}{(' — ' + extra) if extra else ''}")
    print(f"{'='*60}")
    print(f"    m (int) = {m}")
    if s is not None:
        print(f"    m (txt) = {s!r}")
        if any(t in s.lower() for t in FLAG_MARKERS):
            print(f"    ⭐ FLAG-LIKE PATTERN DETECTED")
    else:
        print(f"    m (hex) = {m:x}")
        b = long_to_bytes_safe(m)
        if len(b) <= 200:
            print(f"    m (byt) = {b!r}")
    return q, s


# ==========================================================================
# Decryption helpers (support multi-prime)
# ==========================================================================

def decrypt_single(n, e, c, p, q):
    """Classic two-prime RSA."""
    if p * q != n:
        return None
    phi = (p - 1) * (q - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        return None
    return pow(c, d, n)


def decrypt_with_factors(n, e, c, factors):
    """General RSA decryption (2+ primes)."""
    if not factors:
        return None
    prod = 1
    for f in factors:
        prod *= f
    if prod != n:
        return None
    phi = 1
    for f in factors:
        phi *= (f - 1)
    try:
        d = modinv(e, phi)
    except ValueError:
        return None
    return pow(c, d, n)


def decrypt_blocks(n, e, cs, block_size, original_length, factors):
    """Block cipher with any number of primes."""
    phi = 1
    for f in factors:
        phi *= (f - 1)
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
    if original_length >= 0:
        return bytes(out[:original_length])
    return bytes(out)


# ==========================================================================
# Polynomial arithmetic mod n (for Franklin–Reiter)
# ==========================================================================

def _poly_trim(p):
    while len(p) > 1 and p[-1] == 0:
        p = p[:-1]
    return p

def _poly_mul(a, b, n):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            r[i+j] = (r[i+j] + ai * bj) % n
    return _poly_trim(r)

def _poly_sub(a, b, n):
    L = max(len(a), len(b))
    a = list(a) + [0] * (L - len(a))
    b = list(b) + [0] * (L - len(b))
    return _poly_trim([(a[i] - b[i]) % n for i in range(L)])

def _poly_mod(a, b, n):
    a = list(a)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        if a[-1] == 0:
            a.pop()
            continue
        lc_inv = modinv(b[-1], n)  # may raise ValueError → n factored!
        coeff = (a[-1] * lc_inv) % n
        shift = len(a) - len(b)
        for i, bi in enumerate(b):
            a[shift + i] = (a[shift + i] - coeff * bi) % n
        a.pop()
    return _poly_trim(a) if a else [0]

def _poly_gcd(a, b, n):
    a, b = list(a), list(b)
    while not (len(b) == 1 and b[0] == 0):
        try:
            r = _poly_mod(a, b, n)
        except ValueError:
            return None  # leading coeff not invertible — n factored, skip
        a, b = b, r
    if len(a) == 0 or a[-1] == 0:
        return None
    lc_inv = modinv(a[-1], n)
    return _poly_trim([(c * lc_inv) % n for c in a])


# ==========================================================================
# NEW ATTACKS
# ==========================================================================

# ---- 1. Small-e with modular reduction ---------------------------------
def attack_small_e_modular(n, e, c, max_k=10**5):
    """
    m^e = c + k*n, k > 0.
    Для e ∈ {3, 5, 7} та короткого повідомлення k зазвичай невелике.
    """
    if e > 11:
        return None
    if c == 0:
        return None
    for k in range(max_k + 1):
        val = c + k * n
        root, exact = iroot(val, e)
        if exact:
            return root
    return None


# ---- 2. Common Modulus with gcd(e1,e2) > 1 -----------------------------
def attack_common_modulus_general(n, e1, e2, c1, c2, max_k=10**5):
    """
    Bezout: a*e1 + b*e2 = g = gcd(e1,e2).
    Отримуємо m^g mod n. Далі — або точний g-й корінь, або перебір c + k*n.
    """
    g, a, b = egcd(e1, e2)
    if a < 0:
        try:
            c1 = modinv(c1, n)
        except ValueError:
            return ('FACTOR', gcd(c1, n))
        a = -a
    if b < 0:
        try:
            c2 = modinv(c2, n)
        except ValueError:
            return ('FACTOR', gcd(c2, n))
        b = -b
    mg = (pow(c1, a, n) * pow(c2, b, n)) % n
    # exact g-th root
    root, exact = iroot(mg, g)
    if exact:
        return ('M', root)
    # try c + k*n
    for k in range(1, max_k + 1):
        root, exact = iroot(mg + k * n, g)
        if exact:
            return ('M', root)
    return None


# ---- 3. Batch GCD (product-tree style; O(k^2) is fine for k < 200) -----
def attack_batch_gcd(ns):
    """
    Знаходить усі пари з gcd(n_i, n_j) > 1.
    Повертає dict: idx -> (p, q) (перший знайдений розклад для цього n).
    """
    found = {}
    k = len(ns)
    for i in range(k):
        for j in range(i + 1, k):
            g = gcd(ns[i], ns[j])
            if 1 < g < ns[i] and 1 < g < ns[j]:
                if i not in found:
                    found[i] = (g, ns[i] // g)
                if j not in found:
                    found[j] = (g, ns[j] // g)
            elif g == ns[i] and g != 1 and ns[j] % ns[i] == 0:
                # pathological: n_i | n_j
                if j not in found:
                    found[j] = (ns[i], ns[j] // ns[i])
    return found


# ---- 4. Known phi(n) ---------------------------------------------------
def factor_from_phi(n, phi):
    """
    phi = n - (p+q) + 1  =>  s = p+q = n - phi + 1.
    p, q = корені x^2 - s x + n = 0.
    """
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    t = isqrt(disc)
    if t * t != disc:
        return None
    p = (s + t) // 2
    q = (s - t) // 2
    if p * q == n and p > 1 and q > 1:
        return (p, q)
    return None


# ---- 5. Known p+q / p-q / p^2+q^2 --------------------------------------
def factor_from_sum(n, s):
    """p + q = s."""
    disc = s * s - 4 * n
    if disc < 0:
        return None
    t = isqrt(disc)
    if t * t != disc:
        return None
    p = (s + t) // 2
    q = (s - t) // 2
    if p * q == n and p > 1:
        return (p, q)
    return None


def factor_from_diff(n, diff):
    """p - q = diff (може бути від'ємним)."""
    d2 = diff * diff
    s2 = d2 + 4 * n
    s = isqrt(s2)
    if s * s != s2:
        return None
    if (s + diff) % 2 != 0:
        return None
    p = (s + diff) // 2
    q = (s - diff) // 2
    if p * q == n and p > 1:
        return (p, q)
    return None


def factor_from_p2q2(n, p2_q2):
    """p^2 + q^2 відоме."""
    s2 = p2_q2 + 2 * n   # (p+q)^2 = p^2+q^2 + 2pq
    s = isqrt(s2)
    if s * s != s2:
        return None
    return factor_from_sum(n, s)


# ---- 6. Known CRT private exponents dp / dq ----------------------------
def factor_from_dp(n, e, dp):
    """
    dp = d mod (p-1).
    e*dp - 1 = k*(p-1) for some 1 <= k < e.
    """
    for k in range(1, e):
        if (e * dp - 1) % k == 0:
            p = (e * dp - 1) // k + 1
            if 1 < p < n and n % p == 0:
                return (p, n // p)
    return None

def factor_from_dq(n, e, dq):
    r = factor_from_dp(n, e, dq)
    if r:
        return (r[1], r[0])
    return None


# ---- 7. Linear relation q = a*p + b -----------------------------------
def factor_from_linear(n, a, b):
    """
    q = a*p + b => a*p^2 + b*p - n = 0.
    p = (-b + sqrt(b^2 + 4*a*n)) / (2a).
    """
    if a == 0:
        return None
    disc = b * b + 4 * a * n
    t = isqrt(disc)
    if t * t != disc:
        return None
    num = -b + t
    if num % (2 * a) != 0:
        return None
    p = num // (2 * a)
    if p > 1 and n % p == 0:
        return (p, n // p)
    return None


# ---- 8. Multi-prime factorization -------------------------------------
def factor_multi_prime(n, max_factors=5):
    """
    Розкладає n на прості множники (2..max_factors).
    Використовує Pollard rho / sympy. Повертає список простих або None.
    """
    factors = []
    remaining = n
    while remaining > 1 and len(factors) < max_factors:
        if HAS_SYMPY:
            try:
                if isprime(remaining):
                    factors.append(int(remaining))
                    remaining = 1
                    break
            except Exception:
                pass
        f = _pollard_rho(remaining)
        if f is None or f == remaining:
            # last resort: sympy
            if HAS_SYMPY:
                try:
                    fac = factorint(remaining, limit=10**6)
                    if len(fac) == 1:
                        factors.append(int(remaining))
                        remaining = 1
                        break
                    for prime, exp in fac.items():
                        for _ in range(exp):
                            factors.append(int(prime))
                    remaining = 1
                    break
                except Exception:
                    return None
            return None
        factors.append(f)
        remaining //= f
    if remaining > 1:
        factors.append(remaining)
    if len(factors) < 2:
        return None
    return factors


# ---- 9. Pollard rho / p-1 (helpers) ------------------------------------
def _pollard_rho(n, max_iter=10**6):
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    import random as _r
    _r.seed(0)
    for _ in range(8):
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


def _sieve_primes(limit):
    if limit < 2:
        return []
    s = bytearray([1]) * (limit + 1)
    s[0] = s[1] = 0
    for i in range(2, isqrt(limit) + 1):
        if s[i]:
            s[i*i::i] = bytearray(len(s[i*i::i]))
    return [i for i, v in enumerate(s) if v]


def attack_pollard_p_minus_1(n, B=10**5):
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


# ---- 10. Fermat (extended limit) --------------------------------------
def attack_fermat(n, max_iter=10**6):
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


# ---- 11. Wiener (unchanged) -------------------------------------------
def attack_wiener(n, e):
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for ai in cf:
        p_next = ai * p_curr + p_prev
        q_next = ai * q_curr + q_prev
        k_cand, d_cand = p_next, q_next
        if d_cand and k_cand:
            if (e * d_cand - 1) % k_cand == 0:
                phi = (e * d_cand - 1) // k_cand
                s = n - phi + 1
                disc = s * s - 4 * n
                if disc >= 0:
                    t = isqrt(disc)
                    if t * t == disc and (s + t) % 2 == 0:
                        p = (s + t) // 2
                        q = (s - t) // 2
                        if p * q == n and p > 1:
                            return d_cand
        p_prev, p_curr = p_curr, p_next
        q_prev, q_curr = q_curr, q_next
    return None


# ---- 12. Håstad with filtering & subsets ------------------------------
def attack_hastad(ns, e, cs, max_subsets=2000):
    if len(cs) < e:
        return None
    from itertools import combinations
    total = comb(len(ns), e)
    if total <= max_subsets:
        combos = list(combinations(range(len(ns)), e))
    else:
        combos = [tuple(range(e))]
        # also try random-ish subsets
        import random as _r
        _r.seed(1)
        seen = set(combos)
        tries = 0
        while len(combos) < max_subsets and tries < max_subsets * 10:
            c = tuple(sorted(_r.sample(range(len(ns)), e)))
            if c not in seen:
                seen.add(c); combos.append(c)
            tries += 1
    for combo in combos:
        sub_ns = [ns[i] for i in combo]
        sub_cs = [cs[i] for i in combo]
        ok = True
        for i in range(len(sub_ns)):
            for j in range(i + 1, len(sub_ns)):
                if gcd(sub_ns[i], sub_ns[j]) != 1:
                    ok = False
                    break
            if not ok:
                break
        if not ok:
            continue
        N = 1
        for nn in sub_ns:
            N *= nn
        X = 0
        for ci, ni in zip(sub_cs, sub_ns):
            Ni = N // ni
            X += ci * Ni * modinv(Ni, ni)
        X %= N
        root, exact = iroot(X, e)
        if exact:
            return root
    return None


# ---- 13. Franklin–Reiter related messages -----------------------------
def attack_franklin_reiter(n, e, c1, c2, a, b):
    """
    c1 = m^e (mod n), c2 = (a*m + b)^e (mod n).
    gcd(x^e - c1, (a*x+b)^e - c2) над Z/nZ дає (x - m).
    """
    if e > 13:  # поліноми високого степеня повільні
        return None
    f = [(-c1) % n] + [0] * (e - 1) + [1]
    g_coeffs = [0] * (e + 1)
    for k in range(e + 1):
        g_coeffs[k] = (comb(e, k) * pow(a, k, n) * pow(b, e - k, n)) % n
    g_coeffs[0] = (g_coeffs[0] - c2) % n
    g = _poly_trim(g_coeffs)
    result = _poly_gcd(f, g, n)
    if result is None or len(result) != 2:
        return None
    # result = x - m (monic)
    m = (-result[0]) % n
    return m


# ---- 14. Dictionary / PIN / known-format ------------------------------
def attack_dictionary(n, e, c, candidates):
    for cand in candidates:
        if isinstance(cand, str):
            cand_b = cand.encode()
        elif isinstance(cand, bytes):
            cand_b = cand
        else:
            cand_b = str(cand).encode()
        m = bytes_to_long_safe(cand_b)
        if pow(m, e, n) == c % n:
            return m
    return None


def attack_pin(n, e, c, pin_length=4):
    for i in range(10 ** pin_length):
        s = str(i).zfill(pin_length).encode()
        m = bytes_to_long_safe(s)
        if pow(m, e, n) == c % n:
            return m
    return None


def attack_known_prefix_suffix(n, e, c, prefix, suffix, charset, unknown_len):
    """
    brute force prefix + <unknown_len chars from charset> + suffix
    """
    if unknown_len > 6:
        print(f"    [!] unknown_len = {unknown_len} too large, skip")
        return None
    for combo in itertools.product(charset, repeat=unknown_len):
        middle = ''.join(combo).encode()
        cand = prefix + middle + suffix
        m = bytes_to_long_safe(cand)
        if pow(m, e, n) == c % n:
            return m
    return None


def attack_known_int_range(n, e, c, lo, hi):
    if hi - lo > 10 ** 7:
        print(f"    [!] range too large ({hi - lo}), skip")
        return None
    for m in range(lo, hi + 1):
        if pow(m, e, n) == c % n:
            return m
    return None


# ---- 15. RSA multiplicative property ----------------------------------
def attack_multiplicative(n, e, c_target, known_m, known_c):
    """
    Якщо c_target = m_target^e, і c_target = known_c * c_extra (mod n),
    де known_c = known_m^e, то m_target = known_m * m_extra (mod n).
    Тут: m_extra = c_target * known_c^{-1} mod n ... недостатньо без c_extra.
    Реально ця атака працює лише якщо є ПАРА (m, c) і структурний зв'язок.

    На практиці: дано (m1, c1). Якщо c_target = c1 * c2 для відомого c2
    з відомим m2, то m_target = m1 * m2. Це рідко.
    """
    return None  # too vague without more structure


# ==========================================================================
# Extended input parsing
# ==========================================================================

EXTRA_KEYS = ['p', 'q', 'phi', 'd', 'dp', 'dq', 'p_plus_q', 'p_minus_q',
              'p2_plus_q2', 'a', 'b', 'lambda_n']


def load_input(argv):
    if len(argv) == 1:
        path = argv[0]
        if path.endswith('.json'):
            with open(path) as f:
                return json.load(f)
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
    raise ValueError("Usage: general_plus.py <file.json | keys.txt [cs.txt]>")


def normalize(challenge):
    """Extended normalize — captures all optional parameters."""
    out = {}

    # Moduli
    if 'ns' in challenge:
        out['ns'] = [int(x) for x in challenge['ns']]
    elif 'n' in challenge:
        out['ns'] = [as_int(challenge['n'])]
    else:
        out['ns'] = []

    # Exponents
    if 'e1' in challenge and 'e2' in challenge:
        out['es'] = [as_int(challenge['e1']), as_int(challenge['e2'])]
        out['c1'] = as_int(challenge['c1'])
        out['c2'] = as_int(challenge['c2'])
        out['cs'] = [out['c1'], out['c2']]
        out['is_block'] = False
        # Still grab extras
        for k in EXTRA_KEYS:
            if k in challenge:
                out[k] = as_int(challenge[k])
        return out

    if 'es' in challenge:
        out['es'] = [int(x) for x in challenge['es']]
    elif 'e' in challenge:
        out['es'] = [as_int(challenge['e'])]
    else:
        out['es'] = []

    # Ciphertext(s)
    if 'ciphertext' in challenge:
        ct = challenge['ciphertext']
        if isinstance(ct, list):
            out['cs'] = [as_int(x) for x in ct]
            out['is_block'] = True
            out['block_size'] = int(challenge.get('block_size', 8))
            out['original_length'] = int(
                challenge.get('original_length',
                              len(out['cs']) * out['block_size']))
        else:
            out['cs'] = [as_int(ct)]
            out['is_block'] = False
    elif 'cs' in challenge:
        out['cs'] = [int(x) for x in challenge['cs']]
        out['is_block'] = False
    elif 'c' in challenge:
        out['cs'] = [as_int(challenge['c'])]
        out['is_block'] = False
    else:
        out['cs'] = []
        out['is_block'] = False

    # Extras
    for k in EXTRA_KEYS:
        if k in challenge:
            out[k] = as_int(challenge[k])

    # Hints
    for k in ['known_prefix', 'known_suffix', 'message_format',
              'unknown_charset', 'wordlist', 'known_int_range']:
        if k in challenge:
            out[k] = challenge[k]
    for k in ['pin_length', 'unknown_length']:
        if k in challenge:
            out[k] = int(challenge[k])

    return out


def _align_triples(ns, es, cs):
    """Best-effort alignment of (n, e, c) triples."""
    if not ns or not es or not cs:
        return []
    if len(ns) == len(es) == len(cs):
        return list(zip(ns, es, cs))
    if len(ns) == 1:
        if len(es) == len(cs):
            return [(ns[0], e, c) for e, c in zip(es, cs)]
        if len(es) == 1:
            return [(ns[0], es[0], c) for c in cs]
        if len(cs) == 1:
            return [(ns[0], e, cs[0]) for e in es]
    if len(ns) == len(es) and len(cs) == 1:
        return [(n, e, cs[0]) for n, e in zip(ns, es)]
    if len(ns) == len(cs) and len(es) == 1:
        return [(n, es[0], c) for n, c in zip(ns, cs)]
    if len(es) == len(cs) and len(ns) == 1:
        return [(ns[0], e, c) for e, c in zip(es, cs)]
    return []


# ==========================================================================
# Main solver
# ==========================================================================

def solve(challenge):
    info = normalize(challenge)
    ns = info['ns']; es = info['es']; cs = info['cs']
    is_block = info.get('is_block', False)
    block_size = info.get('block_size', 8)
    original_length = info.get('original_length', -1)

    print("=" * 60)
    print("RSA Attack Suite — EXTENDED")
    print("=" * 60)
    print(f"  moduli: {len(ns)}")
    for i, n in enumerate(ns[:5]):
        print(f"    n[{i}]: {n.bit_length()} bits")
    if len(ns) > 5:
        print(f"    ... ({len(ns)} total)")
    print(f"  exponents: {es[:10]}{' ...' if len(es) > 10 else ''}")
    print(f"  ciphertexts: {len(cs)}")
    print(f"  block cipher: {is_block}")
    if is_block:
        print(f"    block_size={block_size}, original_length={original_length}")

    # Inventory of extra params
    extras = [k for k in EXTRA_KEYS if k in info]
    if extras:
        print(f"  extra params: {extras}")
    if 'known_prefix' in info:
        print(f"  known_prefix: {info['known_prefix']!r}")
    if 'message_format' in info:
        print(f"  message_format: {info['message_format']}")

    candidates = []  # (quality, attack_name, m)
    triples = _align_triples(ns, es, cs)

    def _record(name, m, extra=""):
        if m is None:
            return False
        q, s = _print_and_score(name, m, extra)
        candidates.append((q, name, m))
        return q >= 0.7

    def _record_blocks(name, pt_bytes, extra=""):
        if pt_bytes is None:
            return False
        m = bytes_to_long_safe(pt_bytes) if pt_bytes else 0
        print(f"\n{'='*60}")
        print(f"[+] {name} (block) {('— ' + extra) if extra else ''}")
        print(f"{'='*60}")
        print(f"    bytes: {pt_bytes[:200]!r}")
        try:
            s = pt_bytes.decode('utf-8')
            print(f"    text:  {s!r}")
            q = 1.0 if any(t in s.lower() for t in FLAG_MARKERS) else 0.8
        except UnicodeDecodeError:
            q = 0.3
        candidates.append((q, name, m))
        return q >= 0.7

    # ------------------------------------------------------------------
    # A. Direct keys (d, p, q) — найшвидше
    # ------------------------------------------------------------------
    if triples:
        n, e, c = triples[0]
        if 'd' in info:
            print("\n[→] Direct d provided")
            d = info['d']
            if is_block:
                out = bytearray()
                ok = True
                for cc in cs:
                    mm = pow(cc, d, n)
                    try:
                        out.extend(mm.to_bytes(block_size, 'big'))
                    except OverflowError:
                        ok = False; break
                if ok:
                    pt = bytes(out[:original_length]) if original_length >= 0 else bytes(out)
                    if _record_blocks("direct d", pt):
                        return _summarize(candidates)
            else:
                m = pow(c, d, n)
                _record("direct d", m)

        if 'p' in info and 'q' in info:
            print("\n[→] Direct p, q provided")
            p, q = info['p'], info['q']
            if p * q == n:
                if is_block:
                    pt = decrypt_blocks(n, e, cs, block_size, original_length, [p, q])
                    _record_blocks("direct p,q", pt)
                else:
                    m = decrypt_single(n, e, c, p, q)
                    _record("direct p,q", m)

    # ------------------------------------------------------------------
    # B. Leaked parameters → factor n
    # ------------------------------------------------------------------
    factors_by_index = {}  # idx -> list of primes

    if triples and 'phi' in info:
        print("\n[→] Known phi(n)")
        r = factor_from_phi(ns[0], info['phi'])
        if r: factors_by_index[0] = list(r)

    if triples and 'lambda_n' in info:
        # λ(n) = lcm(p-1, q-1) = phi / gcd(p-1, q-1)
        # Not directly invertible, but if phi is known skip; try to recover via
        # s = n - phi + 1 only if we have phi. Otherwise ignore.
        pass

    if 'p_plus_q' in info and ns:
        print("\n[→] Known p+q")
        r = factor_from_sum(ns[0], info['p_plus_q'])
        if r: factors_by_index[0] = list(r)

    if 'p_minus_q' in info and ns:
        print("\n[→] Known p-q")
        r = factor_from_diff(ns[0], info['p_minus_q'])
        if r: factors_by_index[0] = list(r)

    if 'p2_plus_q2' in info and ns:
        print("\n[→] Known p²+q²")
        r = factor_from_p2q2(ns[0], info['p2_plus_q2'])
        if r: factors_by_index[0] = list(r)

    if 'dp' in info and triples:
        print("\n[→] Known dp")
        r = factor_from_dp(ns[0], es[0], info['dp'])
        if r: factors_by_index[0] = list(r)

    if 'dq' in info and triples:
        print("\n[→] Known dq")
        r = factor_from_dq(ns[0], es[0], info['dq'])
        if r: factors_by_index[0] = list(r)

    if 'a' in info and 'b' in info and ns:
        print("\n[→] Known q = a*p + b")
        r = factor_from_linear(ns[0], info['a'], info['b'])
        if r: factors_by_index[0] = list(r)

    # Decrypt what we already factored
    for idx, facs in list(factors_by_index.items()):
        if idx < len(ns):
            n = ns[idx]
            if is_block:
                e = es[idx] if idx < len(es) else es[0]
                pt = decrypt_blocks(n, e, cs, block_size, original_length, facs)
                _record_blocks(f"leaked params (idx={idx})", pt)
            elif idx < len(cs) and idx < len(es):
                m = decrypt_with_factors(n, es[idx], cs[idx], facs)
                _record(f"leaked params (idx={idx})", m)

    # ------------------------------------------------------------------
    # C. Batch GCD (multi-key shared factor)
    # ------------------------------------------------------------------
    if len(ns) >= 2:
        print("\n[→] Batch GCD across all moduli")
        found = attack_batch_gcd(ns)
        if found:
            print(f"    [+] Found shared factors for indices: {sorted(found)}")
            for idx, facs in found.items():
                if idx not in factors_by_index:
                    factors_by_index[idx] = list(facs)
                if is_block:
                    e = es[idx] if idx < len(es) else es[0]
                    pt = decrypt_blocks(ns[idx], e, cs, block_size, original_length, list(facs))
                    _record_blocks(f"batch GCD (idx={idx})", pt)
                elif idx < len(cs) and idx < len(es):
                    m = decrypt_with_factors(ns[idx], es[idx], cs[idx], list(facs))
                    _record(f"batch GCD (idx={idx})", m)
        else:
            print("    [-] no shared factors")

    # ------------------------------------------------------------------
    # D. Multi-key per-key factoring attacks
    # ------------------------------------------------------------------
    for idx, (n, e, c) in enumerate(triples):
        if idx in factors_by_index:
            continue  # already factored

        # Fermat
        print(f"\n[→] Key {idx}: Fermat (close p, q)")
        pq = attack_fermat(n)
        if pq:
            factors_by_index[idx] = list(pq)
        else:
            print("    [-] not close")

        # Pollard p-1
        print(f"[→] Key {idx}: Pollard p-1")
        d = attack_pollard_p_minus_1(n, B=10**5)
        if d:
            factors_by_index[idx] = [d, n // d]
        else:
            print("    [-] p-1 not smooth")

        # Multi-prime (also covers small n)
        if n.bit_length() <= 512:
            print(f"[→] Key {idx}: multi-prime factorisation")
            facs = factor_multi_prime(n, max_factors=5)
            if facs and len(facs) >= 2:
                factors_by_index[idx] = facs
            else:
                print("    [-] failed")

    # Decrypt everything we factored
    for idx, facs in factors_by_index.items():
        if idx >= len(triples):
            continue
        n, e, c = triples[idx]
        if is_block:
            pt = decrypt_blocks(n, e, cs, block_size, original_length, list(facs))
            _record_blocks(f"factored key {idx}", pt,
                           extra=f"{len(facs)} factors")
        else:
            m = decrypt_with_factors(n, e, c, list(facs))
            _record(f"factored key {idx}", m,
                    extra=f"{len(facs)} factors")

    # ------------------------------------------------------------------
    # E. Small-e / no padding
    # ------------------------------------------------------------------
    for idx, (n, e, c) in enumerate(triples):
        if e > 11:
            continue
        print(f"\n[→] Key {idx}: small-e exact root")
        root, exact = iroot(c, e)
        if exact:
            _record(f"small-e exact (idx={idx})", root)
        else:
            print("    [-] not exact")

        print(f"[→] Key {idx}: small-e with modular reduction")
        m = attack_small_e_modular(n, e, c, max_k=10**5)
        if m is not None:
            _record(f"small-e modular (idx={idx})", m)
        else:
            print("    [-] no small k")

    # ------------------------------------------------------------------
    # F. Common Modulus (both variants)
    # ------------------------------------------------------------------
    if len(set(ns)) == 1 and len(es) >= 2 and len(cs) >= 2:
        n = ns[0]
        e1, e2 = es[0], es[1]
        c1, c2 = cs[0], cs[1]
        g = gcd(e1, e2)
        if g == 1:
            print("\n[→] Common Modulus (coprime e)")
            try:
                if c1 % n == 0 or c2 % n == 0:
                    print("    [!] ciphertext is 0 mod n, skip")
                else:
                    m = (pow(c1, egcd(e1, e2)[1] if egcd(e1, e2)[1] >= 0 else 0, n)
                         * pow(c2, 1, n)) % n  # placeholder, use proper below
                    # Proper implementation:
                    g2, a, b = egcd(e1, e2)
                    if a < 0:
                        c1 = modinv(c1, n); a = -a
                    if b < 0:
                        c2 = modinv(c2, n); b = -b
                    m = (pow(c1, a, n) * pow(c2, b, n)) % n
                    _record("Common Modulus (coprime)", m)
            except ValueError as ve:
                print(f"    [!] {ve}")
        else:
            print(f"\n[→] Common Modulus (gcd(e1,e2)={g})")
            res = attack_common_modulus_general(n, e1, e2, c1, c2)
            if res:
                tag, val = res
                if tag == 'FACTOR':
                    factors_by_index[0] = [val, n // val]
                    m = decrypt_with_factors(n, e1, c1, [val, n // val])
                    _record("Common Modulus side-effect factor", m)
                else:
                    _record(f"Common Modulus (m^{g})", val)

    # ------------------------------------------------------------------
    # G. Håstad Broadcast (filter by e, then try)
    # ------------------------------------------------------------------
    if len(ns) >= 2:
        print("\n[→] Håstad Broadcast (filter by e)")
        # Group by e
        from collections import defaultdict
        groups = defaultdict(list)
        for i, e in enumerate(es):
            if i < len(ns) and i < len(cs):
                groups[e].append(i)
        for e_val, idxs in groups.items():
            if e_val > 11:
                continue
            if len(idxs) < e_val:
                continue
            print(f"    e={e_val}: {len(idxs)} ciphertexts → trying")
            sub_ns = [ns[i] for i in idxs]
            sub_cs = [cs[i] for i in idxs]
            m = attack_hastad(sub_ns, e_val, sub_cs, max_subsets=2000)
            if m is not None:
                _record(f"Håstad (e={e_val}, {len(idxs)} keys)", m)
            else:
                print(f"    [-] failed for e={e_val}")

    # ------------------------------------------------------------------
    # H. Wiener
    # ------------------------------------------------------------------
    for idx, (n, e, c) in enumerate(triples):
        print(f"\n[→] Key {idx}: Wiener (small d)")
        d = attack_wiener(n, e)
        if d is not None:
            if is_block:
                out = bytearray()
                ok = True
                for cc in cs:
                    mm = pow(cc, d, n)
                    try:
                        out.extend(mm.to_bytes(block_size, 'big'))
                    except OverflowError:
                        ok = False; break
                if ok:
                    pt = bytes(out[:original_length]) if original_length >= 0 else bytes(out)
                    _record_blocks(f"Wiener (idx={idx})", pt)
            else:
                m = pow(c, d, n)
                _record(f"Wiener (idx={idx})", m)
        else:
            print("    [-] d not small")

    # ------------------------------------------------------------------
    # I. Dictionary / PIN / known format
    # ------------------------------------------------------------------
    if triples:
        n, e, c = triples[0]
        if 'message_format' in info and info['message_format'] == 'pin':
            print(f"\n[→] PIN brute-force (length={info.get('pin_length', 4)})")
            m = attack_pin(n, e, c, info.get('pin_length', 4))
            if m is not None:
                _record("PIN brute-force", m)
            else:
                print("    [-] no match")

        if 'known_int_range' in info:
            rng = info['known_int_range']
            lo, hi = rng[0], rng[1]
            print(f"\n[→] Known integer range [{lo}, {hi}]")
            m = attack_known_int_range(n, e, c, lo, hi)
            if m is not None:
                _record("known int range", m)

        if 'known_prefix' in info or 'known_suffix' in info:
            prefix = info.get('known_prefix', '').encode() if isinstance(
                info.get('known_prefix', ''), str) else info['known_prefix']
            suffix = info.get('known_suffix', '').encode() if isinstance(
                info.get('known_suffix', ''), str) else info['known_suffix']
            charset = info.get('unknown_charset', '0123456789abcdefghijklmnopqrstuvwxyz')
            unknown_len = info.get('unknown_length', 3)
            print(f"\n[→] Known prefix/suffix brute-force (unknown_len={unknown_len})")
            m = attack_known_prefix_suffix(n, e, c, prefix, suffix, charset, unknown_len)
            if m is not None:
                _record("prefix/suffix brute", m)
            else:
                print("    [-] no match")

        if 'wordlist' in info and info['wordlist']:
            print(f"\n[→] Dictionary attack ({len(info['wordlist'])} entries)")
            m = attack_dictionary(n, e, c, info['wordlist'])
            if m is not None:
                _record("dictionary", m)
            else:
                print("    [-] no match in wordlist")

    # ------------------------------------------------------------------
    # J. Franklin–Reiter
    # ------------------------------------------------------------------
    if ('a' in info and 'b' in info and 'c1' in info and 'c2' in info
            and es and es[0] <= 13):
        print("\n[→] Franklin–Reiter (related messages)")
        m = attack_franklin_reiter(ns[0], es[0], info['c1'], info['c2'],
                                   info['a'], info['b'])
        if m is not None:
            _record("Franklin–Reiter", m)
        else:
            print("    [-] gcd not linear")

    # ------------------------------------------------------------------
    return _summarize(candidates)


def _summarize(candidates):
    print("\n" + "=" * 60)
    if not candidates:
        print("[-] ALL ATTACKS FAILED")
        print("=" * 60)
        print("    'Failed' means only that the built-in attacks didn't find")
        print("    a meaningful plaintext. Try:")
        print("      1. Increase Fermat max_iter / Pollard B / small-e max_k")
        print("      2. Coppersmith (partial plaintext) — requires LLL")
        print("      3. Boneh–Durfee (d < n^0.292) — requires LLL")
        print("      4. Custom algebra if extra parameters are present")
        print("      5. Re-read the challenge — maybe you need to find d or p,")
        print("         not the plaintext")
        return False

    candidates.sort(reverse=True, key=lambda x: x[0])
    best_q, best_name, best_m = candidates[0]
    print(f"[*] {len(candidates)} candidate(s) collected")
    for q, name, m in candidates[:5]:
        print(f"    q={q:.2f}  {name}")
    print()
    if best_q >= 0.7:
        print(f"[+] Most likely flag: attack='{best_name}'")
        print(f"    m = {best_m}")
        _, s = _quality(best_m)
        if s:
            print(f"    text = {s!r}")
        return True
    else:
        print("[!] No candidate looks like valid plaintext.")
        print("    They are printed above — inspect manually.")
        return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    challenge = load_input(sys.argv[1:])
    solve(challenge)


if __name__ == '__main__':
    main()