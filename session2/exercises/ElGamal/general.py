#!/usr/bin/env python3
"""
ElGamal & DSA Attack Suite for CNS exam preparation
====================================================

USAGE:
    python elgamal_dsa_suite.py challenge.json

SUPPORTED INPUT FORMATS (auto-detected):

    ElGamal encryption:
      A) {"p", "g", "y", "cipher_known": [c1, c2],
          "known_plaintext": "...", "cipher_flag": [c1, c2]}
      B) {"p", "g", "y", "c1": ..., "c2": ...}

    DSA signature:
      C) {"p", "q", "g", "y", "signatures": [{"message", "r", "s"}, ...]}
      D) {"p", "q", "g", "y", "m", "r", "s"}  (single signature)

    Encrypted flag (any of the following fields):
      "encrypted_flag": "hex..."
      "flag_ciphertext": "hex..."
      (a description field may hint at the pattern)

ATTACK ORDER — ElGamal (encryption):
    1. Nonce reuse                 (c1_known == c1_flag)
    2. Sequential nonce            (k_flag = k_known + δ, small δ)
    3. Small nonce                 (BSGS on c1)
    4. Small private key x         (BSGS on y)
    5. Nonce = H(m) / m            (check against known plaintext)
    6. Small-subgroup y            (y lies in small prime-order subgroup)
    7. Pohlig-Hellman              (smooth p-1)
    8. sympy.discrete_log          (small p)

ATTACK ORDER — DSA (signature):
    1. Nonce reuse                 (two signatures with same r)
    2. Small nonce                 (brute-force k for small r search)
    3. Small private key x         (BSGS on y)
    4. Pohlig-Hellman              (smooth p-1)
    5. sympy.discrete_log          (small p)
"""

import json
import sys
import hashlib
from math import isqrt, gcd

try:
    from Crypto.Util.number import inverse as _inv, long_to_bytes, bytes_to_long
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

try:
    from sympy import factorint, isprime
    from sympy.ntheory.residue_ntheory import discrete_log
    from sympy.ntheory.modular import crt as sympy_crt
    HAS_SYMPY = True
except ImportError:
    HAS_SYMPY = False


# ==========================================================================
# Basic helpers
# ==========================================================================

def modinv(a, m):
    """Modular inverse a^{-1} mod m."""
    if HAS_PYCRYPTODOME:
        return int(_inv(a, m))
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd = {g}")
    return x % m


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def long_to_bytes_safe(n):
    if n == 0:
        return b'\x00'
    if HAS_PYCRYPTODOME:
        return long_to_bytes(int(n))
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, 'big')


def bytes_to_long_safe(b):
    if HAS_PYCRYPTODOME:
        return bytes_to_long(b)
    return int.from_bytes(b, 'big')


def as_int(v):
    return v if isinstance(v, int) else int(str(v).strip())


def bsgs(g, h, p, order):
    """
    Baby-step Giant-step for discrete log in group of given order.
    Finds x such that g^x ≡ h (mod p), with 0 <= x < order.

    MATH:
        Let m = ceil(sqrt(order)).
        Baby steps: store g^j for j in [0, m).
        Giant steps: for i in [0, m), check h * (g^{-m})^i is in table.
        Then x = i*m + j.

    COMPLEXITY:
        O(sqrt(order)) time and memory.

    PITFALLS:
        - Returns None if no solution found (order too small or wrong).
        - Memory blows up for order > 2^50 — do not use blindly on huge p.
    """
    m = isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = (e * g) % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = (gamma * factor) % p
    return None


def try_decode(m):
    if m is None or m <= 0:
        return None
    b = long_to_bytes_safe(m)
    try:
        s = b.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in '\n\r\t')
    if printable / len(s) < 0.85:
        return None
    return s


def looks_like_flag(text):
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            return False
    return any(t in text.lower() for t in ('flag{', 'ctf{', 'cns{', 'htb{'))


def report(attack_name, m):
    s = try_decode(m)
    print(f"\n{'='*60}")
    print(f"[+] SUCCESS via {attack_name}")
    print(f"{'='*60}")
    print(f"    m (integer) = {m}")
    if s is not None:
        print(f"    m (text)    = {s!r}")
        if looks_like_flag(s):
            print(f"\n    ⭐ FLAG DETECTED")
    else:
        print(f"    m (hex)     = {m:x}")
        print(f"    m (bytes)   = {long_to_bytes_safe(m)}")
    return True


# ==========================================================================
# Flag decryption patterns (used after recovering x)
# ==========================================================================

def decrypt_flag(encrypted_hex, x, challenge):
    """
    Try common flag-encryption patterns using recovered private key x.

    PATTERNS:
        P1: keystream = sha256(f"{x}:0") || sha256(f"{x}:1") || ...   (from dsa1)
        P2: keystream = long_to_bytes(x) repeated
        P3: AES-ECB with key = sha256(long_to_bytes(x))[:16]
        P4: encrypted_hex is the flag itself (x unused)
        P5: keystream = sha256(str(x))
    """
    try:
        ct = bytes.fromhex(encrypted_hex)
    except ValueError:
        # Maybe it's already a plaintext string
        if looks_like_flag(encrypted_hex):
            print(f"\n[+] FLAG (already plaintext): {encrypted_hex}")
            return True
        return False

    candidates = []

    # P1: sha256(f"{x}:{i}") keystream
    try:
        ks = b""
        i = 0
        while len(ks) < len(ct):
            ks += hashlib.sha256(f"{x}:{i}".encode()).digest()
            i += 1
        candidates.append(("sha256(x:i) keystream",
                           bytes(a ^ b for a, b in zip(ct, ks))))
    except Exception:
        pass

    # P2: keystream = long_to_bytes(x) repeated
    try:
        xb = long_to_bytes_safe(x)
        candidates.append(("x bytes repeated",
                           bytes(c ^ xb[i % len(xb)] for i, c in enumerate(ct))))
    except Exception:
        pass

    # P3: AES-ECB with key = sha256(x)[:16]
    try:
        from Crypto.Cipher import AES
        key = hashlib.sha256(long_to_bytes_safe(x)).digest()[:16]
        length = len(ct) // 16 * 16
        candidates.append(("AES-ECB sha256(x)[:16]",
                           AES.new(key, AES.MODE_ECB).decrypt(ct[:length])))
    except Exception:
        pass

    # P4: encrypted_hex is itself the flag (ASCII)
    try:
        candidates.append(("raw hex", ct))
    except Exception:
        pass

    # P5: keystream = sha256(str(x)) (single block)
    try:
        ks = hashlib.sha256(str(x).encode()).digest()
        candidates.append(("sha256(x) single",
                           bytes(a ^ b for a, b in zip(ct, ks))))
    except Exception:
        pass

    for name, pt in candidates:
        # Try decode
        try:
            text = pt.decode('utf-8')
        except UnicodeDecodeError:
            text = None
        if text and looks_like_flag(text):
            print(f"\n{'='*60}")
            print(f"[+] FLAG DECRYPTED (pattern: {name})")
            print(f"{'='*60}")
            print(f"    {text!r}")
            return True

    # No clean match — show all candidates
    print(f"\n[!] No flag-like text found in standard patterns.")
    print(f"    Showing candidates (inspect manually):")
    for name, pt in candidates:
        try:
            print(f"      {name}: {pt.decode(errors='replace')!r}")
        except Exception:
            print(f"      {name}: {pt!r}")
    return False


def find_encrypted_flag(challenge):
    """Look for common field names in JSON."""
    for key in ("encrypted_flag", "flag_ciphertext", "flag_enc", "flag_ct"):
        if key in challenge:
            return challenge[key]
    return None


# ==========================================================================
# HASH function for DSA
# ==========================================================================

def make_hasher(challenge):
    """
    Returns H(m: str) -> int mod q.
    Default: int(sha256(m)) mod q (as in dsa1_challenge.json).
    If challenge specifies "hash" field, try to match it.
    """
    q = challenge.get("q")
    hash_spec = challenge.get("hash", "").lower()

    def H_sha256(m):
        return int.from_bytes(hashlib.sha256(m.encode()).digest(), 'big') % q
    def H_sha1(m):
        return int.from_bytes(hashlib.sha1(m.encode()).digest(), 'big') % q
    def H_md5(m):
        return int.from_bytes(hashlib.md5(m.encode()).digest(), 'big') % q

    if "sha1" in hash_spec:
        return H_sha1
    if "md5" in hash_spec:
        return H_md5
    return H_sha256  # default


# ==========================================================================
# ELGAMAL ENCRYPTION — attacks
# ==========================================================================

def elgamal_attack_nonce_reuse(p, c1_known, c2_known, m_known,
                                c1_flag, c2_flag):
    """
    Nonce Reuse in ElGamal Encryption
    ==================================

    CONDITION: c1_known == c1_flag (same g^k was used).

    MATH:
        c1 = g^k mod p, c2 = m * y^k mod p.
        Same k => same y^k.
        c2_flag / c2_known = m_flag / m_known (mod p)
        => m_flag = m_known * c2_flag * c2_known^{-1} mod p.

    PITFALL:
        Requires one known plaintext. Without it, we only get the RATIO
        m_flag / m_known, not m_flag itself.
    """
    if c1_known is None or c1_flag is None:
        return None
    if c1_known != c1_flag:
        print("    [-] c1_known != c1_flag — nonce reuse not applicable")
        return None
    if m_known is None:
        print("    [-] No known plaintext — cannot exploit")
        return None
    m_flag = (m_known * c2_flag * modinv(c2_known, p)) % p
    return m_flag


def elgamal_attack_sequential_nonce(p, g, y, c1_known, c2_known, m_known,
                                     c1_flag, c2_flag, max_delta=10000):
    """
    Sequential Nonce in ElGamal
    ============================

    CONDITION: k_flag = k_known + δ for some small integer δ.

    MATH:
        c1_flag = g^{k_known + δ} = c1_known * g^δ mod p.
        So try each δ in [-max_delta, max_delta]:
            if (c1_known * g^δ) mod p == c1_flag, δ is correct.
        Then y^{k_flag} = y^{k_known} * y^δ mod p,
        where y^{k_known} = c2_known * m_known^{-1} mod p.
        => m_flag = c2_flag * (y^{k_flag})^{-1} mod p.

    PITFALL:
        - max_delta too small: miss the answer. Try 10000 or more.
        - Requires known plaintext (to compute y^{k_known}).
    """
    if None in (c1_known, c2_known, c1_flag, c2_flag, m_known):
        return None
    yk_known = (c2_known * modinv(m_known, p)) % p
    for delta in range(-max_delta, max_delta + 1):
        if (c1_known * pow(g, delta, p)) % p == c1_flag:
            print(f"    [+] Found δ = {delta}")
            yk_flag = (yk_known * pow(y, delta, p)) % p
            return (c2_flag * modinv(yk_flag, p)) % p
    print(f"    [-] No δ in [-{max_delta}, {max_delta}]")
    return None


def elgamal_attack_small_nonce(p, g, y, c1_flag, c2_flag,
                                limits=None, name="flag"):
    """
    Small Nonce in ElGamal
    =======================

    CONDITION: k_flag < 2^bits for some modest bits.

    MATH:
        Find k via BSGS: g^k = c1_flag mod p, k < limit.
        Then y^k is directly computable, and m = c2 * (y^k)^{-1} mod p.

    PITFALL:
        - Does NOT require knowing x. Good when only some c1 is small.
        - Memory of BSGS scales as sqrt(limit). For limit = 2^48 it's
          ~2^24 dict entries — many GB. Prefer limit <= 2^40 (2^20 entries).
        - If k is NOT small (e.g. uniform random), this fails silently.
    """
    if c1_flag is None or c2_flag is None:
        return None
    limits = limits or [20, 24, 28, 32, 36, 40]
    for bits in limits:
        k = bsgs(g, c1_flag, p, 1 << bits)
        if k is not None:
            print(f"    [+] k_{name} = {k} (< 2^{bits})")
            s = pow(y, k, p)
            return (c2_flag * modinv(s, p)) % p
    print(f"    [-] k_{name} not small (up to 2^{limits[-1]})")
    return None


def elgamal_attack_small_x(p, g, y):
    """
    Small Private Key in ElGamal
    =============================

    CONDITION: x < 2^bits (e.g. weak PRNG or deliberately small).

    MATH:
        Same as small nonce: BSGS on y = g^x mod p to recover x.
    """
    for bits in [20, 24, 28, 32, 36, 40, 48]:
        x = bsgs(g, y, p, 1 << bits)
        if x is not None:
            print(f"    [+] x = {x} (< 2^{bits})")
            return x
    print(f"    [-] x not small")
    return None


def elgamal_attack_nonce_from_hash(p, g, c1_known, m_known_bytes):
    """
    Nonce derived from message
    ===========================

    CONDITION: k_known is some function of the message.

    COMMON PATTERNS to check:
        k = int(m), k = len(m), k = sha256(m), k = sha1(m), k = md5(m)

    PITFALL:
        Even if we identify the pattern, we cannot decrypt the flag without
        k_flag, because k_flag = f(m_flag) and m_flag is unknown. This check
        only helps understand the scheme.
    """
    if c1_known is None or m_known_bytes is None:
        return None
    cands = {
        "int(m)":     bytes_to_long_safe(m_known_bytes),
        "len(m)":     len(m_known_bytes),
        "sha256(m)":  int.from_bytes(hashlib.sha256(m_known_bytes).digest(), 'big'),
        "sha1(m)":    int.from_bytes(hashlib.sha1(m_known_bytes).digest(), 'big'),
        "md5(m)":     int.from_bytes(hashlib.md5(m_known_bytes).digest(), 'big'),
    }
    for name, k in cands.items():
        if pow(g, k % (p - 1), p) == c1_known:
            print(f"    [+] k_known matches: {name}")
            return k
    return None


def elgamal_attack_small_subgroup(p, g, y):
    """
    Small Subgroup Attack on y
    ===========================

    CONDITION:
        y falls into a small prime-order subgroup of Z_p^*.
        That happens if x was generated as a multiple of q_small
        (e.g. x = q_small * s), or by mistake.

    MATH:
        If y^q == 1 (mod p) for small prime q | p-1, then y has order <= q.
        Let g' = g^{(p-1)/q} (element of order q). Then y = (g')^s.
        Find s by BSGS in subgroup of order q — trivial for small q.
        Full x is then s * (p-1)/q (mod ord(g)).

    PITFALL:
        - We must confirm y^q == 1; otherwise y is NOT in that subgroup.
        - y^(p-1) == 1 always holds (Fermat), so don't confuse the two.
    """
    if not HAS_SYMPY:
        return None
    factors = factorint(p - 1, limit=10**7)
    for q in factors:
        if q > 10**6:
            continue  # skip large primes — infeasible BSGS
        if pow(y, q, p) == 1:
            print(f"    [+] y has order dividing q = {q}")
            g_prime = pow(g, (p - 1) // q, p)
            s = bsgs(g_prime, y, p, q)
            if s is not None:
                # Full x = s * (p-1)/q mod ord(g)
                ord_g = p - 1
                for qq in factors:
                    while ord_g % qq == 0 and pow(g, ord_g // qq, p) == 1:
                        ord_g //= qq
                x = (s * ((p - 1) // q)) % ord_g
                if pow(g, x, p) == y:
                    print(f"    [+] x = {x} (via small subgroup order {q})")
                    return x
    return None


def elgamal_attack_pohlig_hellman(p, g, y):
    """
    Pohlig-Hellman for ElGamal
    ===========================

    CONDITION: p-1 is B-smooth (small prime factors).

    MATH:
        ord(g) | p-1. Write p-1 = ∏ q_i^{e_i}.
        For each prime power q^e:
            - Reduce DLP to subgroup of order q^e.
            - Solve via BSGS in O(sqrt(q^e)) time.
        Combine with CRT.
        If all q_i are small (< 2^40), full x is recovered quickly.

    PITFALL:
        - If p-1 has a large prime factor (~ 2^100+), PH can only recover
          x mod (product of small q^e) — not x itself.
        - sympy's discrete_log internally does PH — often simpler to call it.
    """
    if not HAS_SYMPY:
        return None
    try:
        factors = factorint(p - 1, limit=10**7)
    except Exception:
        return None
    biggest = max(factors.keys())
    if biggest > 10**8:
        print(f"    [!] p-1 has factor {biggest.bit_length()} bits — infeasible")
        return None
    print(f"    p-1 factors: {factors}")
    try:
        x = int(discrete_log(p, y, g))
        if pow(g, x, p) == y:
            print(f"    [+] x = {x}")
            return x
    except Exception as e:
        print(f"    [!] discrete_log failed: {e}")
    return None


def solve_elgamal(ch):
    """
    Dispatcher for ElGamal encryption challenges.
    """
    p = as_int(ch["p"])
    g = as_int(ch["g"])
    y = as_int(ch["y"])

    print(f"[i] p = {p.bit_length()} bits, g = {g}")

    # --- Extract ciphertexts ---
    c1_known = c2_known = None
    c1_flag = c2_flag = None
    m_known_bytes = None
    m_known = None

    if "cipher_known" in ch:
        c1_known, c2_known = map(as_int, ch["cipher_known"])
    if "known_plaintext" in ch:
        kp = ch["known_plaintext"]
        m_known_bytes = kp.encode() if isinstance(kp, str) else bytes(kp)
        m_known = bytes_to_long_safe(m_known_bytes)
    if "cipher_flag" in ch:
        c1_flag, c2_flag = map(as_int, ch["cipher_flag"])
    if "c1" in ch and "c2" in ch:
        c1_flag, c2_flag = as_int(ch["c1"]), as_int(ch["c2"])

    x_recovered = None
    m_recovered = None

    # ---- Attack 1: Nonce reuse ----
    if c1_known is not None and c1_flag is not None:
        print("\n[→] Attack 1: Nonce reuse (c1_known == c1_flag)")
        m = elgamal_attack_nonce_reuse(p, c1_known, c2_known, m_known,
                                        c1_flag, c2_flag)
        if m is not None:
            return report("ElGamal nonce reuse", m)

        # ---- Attack 2: Sequential nonce ----
        print("\n[→] Attack 2: Sequential nonce (k_flag = k_known + δ)")
        m = elgamal_attack_sequential_nonce(p, g, y, c1_known, c2_known,
                                             m_known, c1_flag, c2_flag)
        if m is not None:
            return report("ElGamal sequential nonce", m)

    # ---- Attack 3: Small nonce ----
    if c1_flag is not None:
        print("\n[→] Attack 3: Small nonce (BSGS on c1_flag)")
        m = elgamal_attack_small_nonce(p, g, y, c1_flag, c2_flag)
        if m is not None:
            return report("ElGamal small nonce", m)

    # ---- Attack 5: Nonce = H(m) ----
    if c1_known is not None and m_known_bytes is not None:
        print("\n[→] Attack 5: Nonce derived from message?")
        elgamal_attack_nonce_from_hash(p, g, c1_known, m_known_bytes)

    # ---- Attack 4: Small x ----
    print("\n[→] Attack 4: Small private key x (BSGS on y)")
    x_recovered = elgamal_attack_small_x(p, g, y)

    # ---- Attack 6: Small subgroup ----
    if x_recovered is None:
        print("\n[→] Attack 6: Small subgroup of y")
        x_recovered = elgamal_attack_small_subgroup(p, g, y)

    # ---- Attack 7: Pohlig-Hellman ----
    if x_recovered is None:
        print("\n[→] Attack 7: Pohlig-Hellman")
        x_recovered = elgamal_attack_pohlig_hellman(p, g, y)

    # ---- Decrypt with recovered x ----
    if x_recovered is not None:
        if c1_flag is not None:
            s = pow(c1_flag, x_recovered, p)
            m = (c2_flag * modinv(s, p)) % p
            return report("ElGamal (x recovered)", m)
        # No ciphertext — but x itself might be the flag
        print("\n[→] No ciphertext — trying x as flag")
        return report("x as flag", x_recovered)

    # ---- Nothing worked ----
    print("\n" + "=" * 60)
    print("[-] ALL ELGAMAL ATTACKS FAILED")
    print("=" * 60)
    print("    Suggestions:")
    print("      - Inspect JSON: is there a known_plaintext field?")
    print("      - Try increasing BSGS limits in small_nonce / small_x")
    print("      - If p-1 might be smooth, increase factorint limit")
    print("      - Look at title/hint in challenge description")
    return False


# ==========================================================================
# DSA SIGNATURE — attacks
# ==========================================================================

def dsa_attack_nonce_reuse(p, q, g, y, sigs, H):
    """
    DSA Nonce Reuse
    ================

    CONDITION: two signatures with the same r (=> same k).

    MATH:
        s_i = k^{-1}(H_i + x r) mod q.
        s1 - s2 = k^{-1}(H1 - H2) mod q
        => k = (H1 - H2) * (s1 - s2)^{-1} mod q.
        x = (s1 k - H1) * r^{-1} mod q.

    EDGE CASES:
        - If gcd(s1 - s2, q) > 1: the equation for k has g solutions.
          Iterate through all and verify g^x == y.
        - If H1 == H2 and s1 == s2: trivial signature replay, no info.
    """
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            s1, s2 = sigs[i], sigs[j]
            if s1["r"] != s2["r"]:
                continue
            print(f"    [+] Same r in sigs #{i} and #{j}")
            m1, m2 = s1["message"], s2["message"]
            H1, H2 = H(m1), H(m2)
            r, sa, sb = s1["r"], s1["s"], s2["s"]
            den = (sa - sb) % q
            num = (H1 - H2) % q

            gg = gcd(den, q)
            if gg == 1:
                k = (num * modinv(den, q)) % q
                x = ((sa * k - H1) * modinv(r, q)) % q
                if pow(g, x, p) == y:
                    print(f"    [+] x = {x}")
                    return x
            else:
                # Multiple solutions for k
                den_red = den // gg
                num_red = num // gg
                q_red = q // gg
                try:
                    k0 = (num_red * modinv(den_red, q_red)) % q_red
                except ValueError:
                    continue
                for t in range(gg):
                    k = k0 + t * q_red
                    x = ((sa * k - H1) * modinv(r, q)) % q
                    if pow(g, x, p) == y:
                        print(f"    [+] x = {x} (gcd = {gg}, t = {t})")
                        return x
    print("    [-] No repeated r")
    return None


def dsa_attack_small_nonce(p, q, g, y, sigs, H):
    """
    Small Nonce in DSA
    ===================

    CONDITION: k used in signing is small (e.g. < 2^24).

    MATH:
        r = (g^k mod p) mod q.
        This is not directly BSGS-able because of mod q collapse, so for
        small k we brute-force:
            for k in 0..limit: if pow(g, k, p) % q == r: found.
        Then x = (s*k - H) * r^{-1} mod q.

    PITFALL:
        - Only practical for limit up to ~2^24 (16M iterations in Python = minutes).
        - BSGS does NOT apply directly because of the mod q step.
    """
    for sig in sigs:
        r = sig["r"]
        limit = 1 << 24
        print(f"    [*] Brute-forcing k < 2^24 for sig on '{sig['message'][:30]}...'")
        for k in range(1, limit):
            if pow(g, k, p) % q == r:
                print(f"    [+] k = {k}")
                Hm = H(sig["message"])
                x = ((sig["s"] * k - Hm) * modinv(r, q)) % q
                if pow(g, x, p) == y:
                    print(f"    [+] x = {x}")
                    return x
                break
    print("    [-] No small k found")
    return None


def dsa_attack_small_x(p, q, g, y):
    """
    Small Private Key in DSA
    =========================

    MATH:
        y = g^x mod p. BSGS in Z_p^* for small x.
    """
    for bits in [20, 24, 28, 32, 36, 40, 48]:
        x = bsgs(g, y, p, 1 << bits)
        if x is not None:
            print(f"    [+] x = {x} (< 2^{bits})")
            return x
    print("    [-] x not small")
    return None


def dsa_attack_pohlig_hellman(p, g, y):
    """
    Pohlig-Hellman for DSA (in Z_p^*)
    ==================================

    Same as ElGamal: DLP is in Z_p^*, order q | p-1.
    If p-1 (or q) is smooth, x recovered quickly.
    """
    if not HAS_SYMPY:
        return None
    try:
        factors = factorint(p - 1, limit=10**7)
    except Exception:
        return None
    print(f"    p-1 factors (partial): {list(factors.keys())[:5]}...")
    biggest = max(factors.keys())
    if biggest > 10**8:
        print(f"    [!] Large factor {biggest.bit_length()} bits — infeasible")
        return None
    try:
        x = int(discrete_log(p, y, g))
        if pow(g, x, p) == y:
            print(f"    [+] x = {x}")
            return x
    except Exception as e:
        print(f"    [!] discrete_log failed: {e}")
    return None


def solve_dsa(ch):
    """
    Dispatcher for DSA signature challenges.
    """
    p = as_int(ch["p"])
    q = as_int(ch["q"])
    g = as_int(ch["g"])
    y = as_int(ch["y"])

    print(f"[i] p = {p.bit_length()} bits, q = {q.bit_length()} bits")

    # --- Normalise signatures ---
    if "signatures" in ch:
        sigs = []
        for s in ch["signatures"]:
            sigs.append({
                "message": s.get("message") or s.get("m"),
                "r": as_int(s["r"]),
                "s": as_int(s["s"]),
            })
    elif "r" in ch and "s" in ch:
        sigs = [{
            "message": ch.get("m") or ch.get("message"),
            "r": as_int(ch["r"]),
            "s": as_int(ch["s"]),
        }]
    else:
        print("[-] No signatures in input")
        return False

    H = make_hasher(ch)
    x_recovered = None

    # ---- Attack 1: Nonce reuse ----
    if len(sigs) >= 2:
        print("\n[→] Attack 1: DSA nonce reuse (same r)")
        x_recovered = dsa_attack_nonce_reuse(p, q, g, y, sigs, H)
        if x_recovered is not None:
            return dsa_finalize(ch, x_recovered)

    # ---- Attack 2: Small nonce ----
    print("\n[→] Attack 2: DSA small nonce")
    x_recovered = dsa_attack_small_nonce(p, q, g, y, sigs, H)
    if x_recovered is not None:
        return dsa_finalize(ch, x_recovered)

    # ---- Attack 3: Small x ----
    print("\n[→] Attack 3: Small private key x")
    x_recovered = dsa_attack_small_x(p, q, g, y)
    if x_recovered is not None:
        return dsa_finalize(ch, x_recovered)

    # ---- Attack 4: Pohlig-Hellman ----
    print("\n[→] Attack 4: Pohlig-Hellman on Z_p^*")
    x_recovered = dsa_attack_pohlig_hellman(p, g, y)
    if x_recovered is not None:
        return dsa_finalize(ch, x_recovered)

    print("\n" + "=" * 60)
    print("[-] ALL DSA ATTACKS FAILED")
    print("=" * 60)
    return False


def dsa_finalize(ch, x):
    """After recovering x, decrypt the flag or report x."""
    print(f"\n[+] Recovered private key x = {x}")

    enc_flag = find_encrypted_flag(ch)
    if enc_flag:
        print(f"\n[→] Decrypting flag (pattern: see decrypt_flag)")
        if decrypt_flag(enc_flag, x, ch):
            return True

    # No encrypted flag — x might be the flag
    print("\n[→] No encrypted_flag — trying x as flag")
    return report("x as flag", x)


# ==========================================================================
# Main
# ==========================================================================

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        ch = json.load(f)

    # Auto-detect mode
    is_dsa = "q" in ch and ("signatures" in ch or
                             ("r" in ch and "s" in ch))
    is_elgamal = ("y" in ch and
                  ("c1" in ch or "c2" in ch or "cipher_flag" in ch or
                   "cipher_known" in ch or "ciphertext" in ch))

    if is_dsa:
        print("=" * 60)
        print("DSA Signature Attack Suite")
        print("=" * 60)
        solve_dsa(ch)
    elif is_elgamal:
        print("=" * 60)
        print("ElGamal Encryption Attack Suite")
        print("=" * 60)
        solve_elgamal(ch)
    else:
        print("[-] Cannot auto-detect challenge type.")
        print("    If it's DSA, ensure 'q' and 'signatures' (or 'r','s') present.")
        print("    If it's ElGamal, ensure 'p','g','y' and some ciphertext.")
        sys.exit(1)


if __name__ == "__main__":
    main()