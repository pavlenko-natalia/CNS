#!/usr/bin/env python3
"""
========================================

Modes (auto-detected, override with --mode):
  elgamal_enc   ElGamal encryption (p,g,y + ciphertexts)
  elgamal_sig   Classic ElGamal signature (p,g,y + signatures)
  dsa           DSA signature  (p,q,g,y + signatures)

Usage:
  python general_v2.py challenge.json
  python general_v2.py challenge.json --mode dsa
  python general_v2.py challenge.json --known-x 12345
"""
import json
import sys
import hashlib
from math import isqrt, gcd
from argparse import ArgumentParser

try:
    from Crypto.Util.number import inverse as _inv, long_to_bytes, bytes_to_long
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

try:
    from sympy import factorint, isprime
    from sympy.ntheory.residue_ntheory import discrete_log
    _HAS_SYMPY = True
except ImportError:
    _HAS_SYMPY = False


# ============================================================
# Utilities
# ============================================================

def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    if _HAS_CRYPTO:
        try:
            return int(_inv(a, m))
        except Exception:
            pass
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no inverse, gcd={g}")
    return x % m


def L2B(n):
    if n == 0:
        return b"\x00"
    if _HAS_CRYPTO:
        return long_to_bytes(int(n))
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, "big")


def B2L(b):
    if _HAS_CRYPTO:
        return bytes_to_long(b)
    return int.from_bytes(b, "big")


def as_int(v):
    if isinstance(v, int):
        return v
    s = str(v).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def prod(xs):
    r = 1
    for x in xs:
        r *= x
    return r


class TooBig(Exception):
    """BSGS table exceeds memory budget."""


def factor_checked(n, limit=10**7):
    """Return (factors_dict, is_complete). Complete means all primes + product == n."""
    if not _HAS_SYMPY:
        return {}, False
    try:
        f = factorint(n, limit=limit)
    except Exception:
        return {}, False
    complete = prod(p ** e for p, e in f.items()) == n and all(isprime(p) for p in f)
    return f, complete


def order_of(g, p, factors=None):
    """ord(g) in Z_p^*. factors = factorization of p-1."""
    if p == 2:
        return 1
    if factors is None:
        factors, _ = factor_checked(p - 1)
    n = p - 1
    for q in factors:
        while n % q == 0 and pow(g, n // q, p) == 1:
            n //= q
    return n


def bsgs(g, h, p, order, max_entries=1 << 24):
    """x s.t. g^x ≡ h (mod p), 0 ≤ x < order. Raise TooBig if memory too high."""
    if order <= 0:
        return None
    m = isqrt(order) + 1
    if m > max_entries:
        raise TooBig(f"BSGS needs {m} > {max_entries} entries")
    tbl = {}
    e = 1
    for j in range(m):
        tbl.setdefault(e, j)
        e = e * g % p
    f = pow(g, -m, p)
    gamma = h % p
    for i in range(m):
        if gamma in tbl:
            return i * m + tbl[gamma]
        gamma = gamma * f % p
    return None


def decode_text(m):
    if m is None or m < 0:
        return None
    try:
        s = L2B(m).decode("utf-8")
    except Exception:
        return None
    if not s:
        return None
    ok = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\n\r\t")
    return s if ok / len(s) >= 0.85 else None


def is_flag(t):
    if isinstance(t, bytes):
        try:
            t = t.decode()
        except UnicodeDecodeError:
            return False
    return any(k in t.lower() for k in ("flag{", "ctf{", "cns{", "htb{"))


# ============================================================
# Reporting — distinguishes x / k / plaintext / flag
# ============================================================

def emit(attack, value, kind):
    """Print a result. Returns 'flag' / 'plaintext' / 'x' / 'k' / None."""
    print(f"\n{'='*60}\n[+] {attack}\n{'='*60}")
    print(f"    {kind} = {value}")
    if kind == "plaintext":
        s = decode_text(value)
        if s:
            print(f"    text = {s!r}")
            if is_flag(s):
                print(f"    ⭐ FLAG DETECTED")
                return "flag"
            return "plaintext"
        print(f"    hex = {value:x}")
        return "plaintext"
    return kind


# ============================================================
# Flag decryption — post-x
# ============================================================

def decrypt_flag_patterns(enc, x):
    """Try common flag-encryption patterns using recovered x."""
    if isinstance(enc, str):
        try:
            ct = bytes.fromhex(enc)
        except ValueError:
            if is_flag(enc):
                print(f"\n[+] FLAG already in plaintext: {enc!r}")
                return True
            return False
    else:
        ct = bytes(enc)

    cands = []
    try:
        ks, i = b"", 0
        while len(ks) < len(ct):
            ks += hashlib.sha256(f"{x}:{i}".encode()).digest()
            i += 1
        cands.append(("sha256(f'{x}:{i}') keystream", bytes(a ^ b for a, b in zip(ct, ks))))
    except Exception:
        pass
    try:
        xb = L2B(x)
        cands.append(("x-bytes repeated", bytes(c ^ xb[i % len(xb)] for i, c in enumerate(ct))))
    except Exception:
        pass
    try:
        from Crypto.Cipher import AES
        key = hashlib.sha256(L2B(x)).digest()[:16]
        cands.append(("AES-ECB sha256(x)[:16]", AES.new(key, AES.MODE_ECB).decrypt(ct[:len(ct)//16*16])))
    except Exception:
        pass
    cands.append(("raw hex", ct))
    try:
        ks = hashlib.sha256(str(x).encode()).digest()
        cands.append(("sha256(str(x)) single", bytes(a ^ b for a, b in zip(ct, ks))))
    except Exception:
        pass

    for name, pt in cands:
        try:
            s = pt.decode()
        except UnicodeDecodeError:
            s = None
        if s and is_flag(s):
            print(f"\n{'='*60}\n[+] FLAG DECRYPTED ({name})\n{'='*60}\n    {s!r}")
            return True
    print("\n[!] No flag-pattern matched. Candidates:")
    for name, pt in cands:
        try:
            print(f"    {name}: {pt!r}")
        except Exception:
            pass
    return False


def find_encrypted_flag(ch):
    for k in ("encrypted_flag", "flag_ciphertext", "flag_enc", "flag_ct"):
        if k in ch:
            return ch[k]
    return None


# ============================================================
# Hash function for DSA / ElGamal-sig
# ============================================================

def make_hasher(ch, q):
    """
    H(m) -> int. Supports hash specs: sha256 (default), sha1, sha512, md5,
    int (message parsed as integer), raw/none (bytes as int),
    leftmost-sha256 (truncate leading bits to q's bit-length).
    'message_format': 'ascii' (default) | 'hex' | 'int'.
    """
    hash_spec = str(ch.get("hash", "")).lower()
    msg_fmt = str(ch.get("message_format", "ascii")).lower()

    def to_bytes(m):
        if isinstance(m, bytes):
            return m
        s = str(m)
        if msg_fmt == "hex":
            return bytes.fromhex(s.removeprefix("0x"))
        if msg_fmt == "int":
            return L2B(int(s, 0))
        return s.encode()

    def hasher(m):
        if "int" in hash_spec and not any(x in hash_spec for x in ("sha", "md5")):
            try:
                H = int(str(m), 0)
            except ValueError:
                H = B2L(to_bytes(m))
        elif "raw" in hash_spec or "none" in hash_spec:
            H = B2L(to_bytes(m))
        elif "sha512" in hash_spec:
            H = int.from_bytes(hashlib.sha512(to_bytes(m)).digest(), "big")
        elif "sha1" in hash_spec:
            H = int.from_bytes(hashlib.sha1(to_bytes(m)).digest(), "big")
        elif "md5" in hash_spec:
            H = int.from_bytes(hashlib.md5(to_bytes(m)).digest(), "big")
        else:
            H = int.from_bytes(hashlib.sha256(to_bytes(m)).digest(), "big")
        if q:
            if "leftmost" in hash_spec or "trunc" in hash_spec:
                qbits = q.bit_length()
                if H.bit_length() > qbits:
                    H >>= (H.bit_length() - qbits)
            H %= q
        return H
    return hasher


# ============================================================
# Parameter analysis
# ============================================================

def analyze_params(ch, need_q=False):
    p, g, y = as_int(ch["p"]), as_int(ch["g"]), as_int(ch["y"])
    q = as_int(ch["q"]) if need_q and "q" in ch else None

    print("\n[i] Parameter analysis")
    tag = lambda ok: "PRIME" if ok else "not prime / unknown"
    print(f"    p = {p.bit_length()} bits — {tag(_HAS_SYMPY and isprime(p))}")

    if q is not None:
        print(f"    q = {q.bit_length()} bits — {tag(_HAS_SYMPY and isprime(q))}")
        if (p - 1) % q:
            print(f"    [!] q ∤ (p-1)")
        if pow(g, q, p) != 1:
            print(f"    [!] g^q ≢ 1 (mod p) — g not in the q-subgroup")
        if pow(y, q, p) != 1:
            print(f"    [!] y^q ≢ 1 (mod p) — y not in the q-subgroup")

    factors_p1, complete = factor_checked(p - 1)
    if not complete:
        print(f"    [!] p-1 not fully factored (large cofactor)")
    ord_g = order_of(g, p, factors_p1)
    print(f"    ord(g) = {ord_g} ({ord_g.bit_length()} bits)")
    if ord_g < p - 1:
        print(f"    [!] ord(g) < p-1 → DLP lives in subgroup of size {ord_g.bit_length()} bits")
    if ord_g == 1:
        print(f"    [!] TRIVIAL generator (g == 1)")

    ord_y = ord_g
    for qq in factors_p1:
        while ord_y % qq == 0 and pow(y, ord_y // qq, p) == 1:
            ord_y //= qq
    print(f"    ord(y) = {ord_y}")
    if ord_y < ord_g:
        print(f"    [!] y lies in a proper subgroup")

    return {
        "p": p, "q": q, "g": g, "y": y,
        "factors_p1": factors_p1, "complete": complete,
        "ord_g": ord_g, "ord_y": ord_y,
    }


# ============================================================
# ElGamal ENCRYPTION — attacks
# ============================================================

def elgamal_enc_nonce_reuse_multi(p, pairs, m_known_default=None):
    """
    pairs: list of (c1, c2, m_or_None).
    Find any pair with c1 shared → decode the other via ratio.
    """
    for i in range(len(pairs)):
        c1i, c2i, mi = pairs[i]
        for j in range(i + 1, len(pairs)):
            c1j, c2j, mj = pairs[j]
            if c1i != c1j:
                continue
            if mi is not None and mj is None:
                mj = mi * c2j * modinv(c2i, p) % p
                return mj, f"pair #{j} via #{i} (nonce reuse)"
            if mj is not None and mi is None:
                mi = mj * c2i * modinv(c2j, p) % p
                return mi, f"pair #{i} via #{j} (nonce reuse)"
    return None, None


def elgamal_enc_sequential(p, g, y, pairs, max_delta=10000):
    """
    Find pair where k_j = k_i + δ (small δ).  Requires at least one known m.
    Then recover δ via c1_j = c1_i * g^δ, and recover unknown m.
    """
    for i in range(len(pairs)):
        c1i, c2i, mi = pairs[i]
        if mi is None:
            continue
        yk_i = c2i * modinv(mi, p) % p
        for j in range(len(pairs)):
            if i == j:
                continue
            c1j, c2j, mj = pairs[j]
            if mj is not None:
                continue
            for delta in range(-max_delta, max_delta + 1):
                if c1i * pow(g, delta, p) % p == c1j:
                    yk_j = yk_i * pow(y, delta, p) % p
                    mj = c2j * modinv(yk_j, p) % p
                    return mj, f"pair #{j} via #{i}, δ={delta}"
    return None, None


def elgamal_enc_small_nonce(p, g, y, c1, c2, max_bits=40):
    for bits in [20, 24, 28, 32, 36, 40]:
        if bits > max_bits:
            break
        try:
            k = bsgs(g, c1, p, 1 << bits)
        except TooBig:
            continue
        if k is not None:
            return c2 * modinv(pow(y, k, p), p) % p, k
    return None, None


def elgamal_enc_small_x(p, g, y):
    for bits in [20, 24, 28, 32, 36, 40, 44]:
        try:
            x = bsgs(g, y, p, 1 << bits)
        except TooBig:
            continue
        if x is not None:
            return x
    return None


def elgamal_enc_small_subgroup(p, g, y, factors):
    """y in a small prime-order subgroup ⇒ BSGS in subgroup recovers x mod that order."""
    for q in factors:
        if q > 10**6:
            continue
        if pow(y, q, p) != 1:
            continue
        gq = pow(g, (p - 1) // q, p)
        try:
            s = bsgs(gq, y, p, q)
        except TooBig:
            continue
        if s is None:
            continue
        ord_g = order_of(g, p, factors)
        # x ≡ s * (p-1)/q (mod ord(g)) may need reduction
        # verify directly
        for mult in [1]:
            x = s * ((p - 1) // q) * mult % ord_g
            if pow(g, x, p) == y:
                return x, q
    return None, None


def elgamal_enc_pohlig_hellman(p, g, y, factors, ord_g):
    """Apply Pohlig-Hellman on ord(g). Uses sympy.discrete_log after feasibility check."""
    if not _HAS_SYMPY:
        return None
    biggest = max(factors.keys()) if factors else 2
    if biggest > 10**8:
        print(f"    [!] largest prime factor of p-1: {biggest.bit_length()} bits — PH infeasible")
        return None
    try:
        x = int(discrete_log(p, y, g))
        if pow(g, x, p) == y:
            return x
    except Exception as e:
        print(f"    [!] discrete_log failed: {e}")
    return None


def nonce_prng_patterns(p, g, c1, msg_bytes):
    """
    Test if k = f(message). If yes, return f (callable) + detected name.
    """
    tests = {
        "int(m)": B2L(msg_bytes) if msg_bytes else None,
        "len(m)": len(msg_bytes) if msg_bytes is not None else None,
        "sha256(m)": int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big") if msg_bytes else None,
        "sha1(m)": int.from_bytes(hashlib.sha1(msg_bytes).digest(), "big") if msg_bytes else None,
        "md5(m)": int.from_bytes(hashlib.md5(msg_bytes).digest(), "big") if msg_bytes else None,
        "sha256(m)%(p-1)": int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big") % (p - 1) if msg_bytes else None,
    }
    for name, k in tests.items():
        if k is None:
            continue
        if pow(g, k % (p - 1), p) == c1:
            return name, k
    return None, None


# ============================================================
# ElGamal CLASSIC SIGNATURE — attacks
# ============================================================

def _elgamal_sig_verify(p, g, y, H, r, s):
    """
    Verify:  y^r · r^s ≡ g^H (mod p).
    H must be reduced mod ord(g) (or p-1).
    """
    if not (0 < r < p) or not (0 < s < p - 1):
        return False
    lhs = pow(y, r, p) * pow(r, s, p) % p
    rhs = pow(g, H, p)
    return lhs == rhs


def elgamal_sig_reuse(p, g, y, sigs, H):
    """
    r = g^k mod p, s = (H - x·r)·k^{-1} mod (p-1).
    Same r ⇒ same k.  From two signatures:
      (s₁ - s₂)·k ≡ H₁ - H₂  (mod p-1)
    Solve for k modulo p-1; take all gcd-many solutions; verify each.
    """
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            a, b = sigs[i], sigs[j]
            if a["r"] != b["r"]:
                continue
            H1, H2 = H(a["message"]), H(b["message"])
            s1, s2 = a["s"], b["s"]
            if s1 == s2 and H1 == H2:
                # exact same signature — no new info
                print(f"    [-] sigs #{i},#{j} identical — replay, skipping")
                continue
            den = (s1 - s2) % (p - 1)
            num = (H1 - H2) % (p - 1)
            gg = gcd(den, p - 1)
            if num % gg:
                continue
            den_red, num_red, m_red = den // gg, num // gg, (p - 1) // gg
            try:
                k0 = num_red * modinv(den_red, m_red) % m_red
            except ValueError:
                continue
            for t in range(min(gg, 1000)):  # cap in case gg huge
                k = k0 + t * m_red
                if k == 0:
                    continue
                try:
                    x = (H1 - s1 * k) * modinv(a["r"], p - 1) % (p - 1)
                except ValueError:
                    continue
                if pow(g, x, p) == y:
                    print(f"    [+] same r in #{i},#{j}; gcd={gg}, t={t}")
                    return x
    return None


def elgamal_sig_known_k(p, g, y, sigs, H, known_k, which=0):
    """Given k for signature[which]: x = (H - s·k)·r^{-1} mod (p-1)."""
    sig = sigs[which]
    Hm = H(sig["message"])
    try:
        x = (Hm - sig["s"] * known_k) * modinv(sig["r"], p - 1) % (p - 1)
    except ValueError:
        return None
    return x if pow(g, x, p) == y else None


def elgamal_sig_small_nonce(p, g, y, sigs, H, max_bits=32):
    """
    r = g^k mod p (NOT reduced mod q), so BSGS directly on r!
    For each small-k candidate: x from k, then verify.
    """
    for sig in sigs:
        r = sig["r"]
        for bits in [20, 24, 28, 32]:
            if bits > max_bits:
                break
            try:
                k = bsgs(g, r, p, 1 << bits)
            except TooBig:
                continue
            if k is None:
                continue
            Hm = H(sig["message"])
            try:
                x = (Hm - sig["s"] * k) * modinv(r, p - 1) % (p - 1)
            except ValueError:
                continue
            if pow(g, x, p) == y:
                return x, k
    return None, None


def elgamal_sig_small_x(p, g, y):
    for bits in [20, 24, 28, 32, 36, 40]:
        try:
            x = bsgs(g, y, p, 1 << bits)
        except TooBig:
            continue
        if x is not None:
            return x
    return None


def elgamal_sig_pohlig_hellman(p, g, y, factors_p1):
    return elgamal_enc_pohlig_hellman(p, g, y, factors_p1, order_of(g, p, factors_p1))


# ============================================================
# DSA — attacks
# ============================================================

def _dsa_verify(p, q, g, y, H, r, s):
    if not (0 < r < q) or not (0 < s < q):
        return False
    w = modinv(s, q)
    u1 = H * w % q
    u2 = r * w % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r


def dsa_reuse(p, q, g, y, sigs, H):
    for i in range(len(sigs)):
        for j in range(i + 1, len(sigs)):
            a, b = sigs[i], sigs[j]
            if a["r"] != b["r"]:
                continue
            H1, H2 = H(a["message"]), H(b["message"])
            if a["s"] == b["s"] and H1 == H2:
                print(f"    [-] sigs #{i},#{j} identical — replay, skipping")
                continue
            den = (a["s"] - b["s"]) % q
            num = (H1 - H2) % q
            gg = gcd(den, q)
            if num % gg:
                continue
            if gg == 1:
                k = num * modinv(den, q) % q
                x = (a["s"] * k - H1) * modinv(a["r"], q) % q
                if pow(g, x, p) == y:
                    print(f"    [+] same r in #{i},#{j}")
                    return x
            else:
                den_r, num_r, q_r = den // gg, num // gg, q // gg
                try:
                    k0 = num_r * modinv(den_r, q_r) % q_r
                except ValueError:
                    continue
                for t in range(gg):
                    k = k0 + t * q_r
                    x = (a["s"] * k - H1) * modinv(a["r"], q) % q
                    if pow(g, x, p) == y:
                        print(f"    [+] same r in #{i},#{j}; gcd={gg}, t={t}")
                        return x
    return None


def dsa_known_k(p, q, g, y, sigs, H, k, which=0):
    sig = sigs[which]
    Hm = H(sig["message"])
    try:
        x = (sig["s"] * k - Hm) * modinv(sig["r"], q) % q
    except ValueError:
        return None
    return x if pow(g, x, p) == y else None


def dsa_sequential(p, q, g, y, sigs, H, max_delta=1000):
    """
    k2 = k1 + δ.  From linear system:
      s1·k1 ≡ H1 + x·r1  (mod q)
      s2·k2 ≡ H2 + x·r2  (mod q)
    Eliminating k1 via k2 - k1 = δ gives x; verify g^x == y.
    """
    for i in range(len(sigs)):
        for j in range(len(sigs)):
            if i == j:
                continue
            a, b = sigs[i], sigs[j]
            H1, H2 = H(a["message"]), H(b["message"])
            r1, s1, r2, s2 = a["r"], a["s"], b["r"], b["s"]
            try:
                i1 = modinv(s1, q)
                i2 = modinv(s2, q)
            except ValueError:
                continue
            # x·(r2·s2^{-1} - r1·s1^{-1}) ≡ δ - H2·s2^{-1} + H1·s1^{-1}
            coef = (r2 * i2 - r1 * i1) % q
            for delta in list(range(1, max_delta + 1)) + list(range(-1, -max_delta - 1, -1)):
                rhs = (delta - H2 * i2 + H1 * i1) % q
                try:
                    x = rhs * modinv(coef, q) % q
                except ValueError:
                    continue
                if pow(g, x, p) == y:
                    print(f"    [+] δ={delta}, sigs #{i},{j}")
                    return x
    return None


def dsa_related(p, q, g, y, sigs, H, small_a=5, small_b=5):
    """
    k2 = a·k1 + b.  Solve 2x2 linear system over GF(q):
      s1·k1 - r1·x ≡ H1
      s2·a·k1 - r2·x ≡ H2 - s2·b
    Then verify (also need r1 = g^{k1} mod p mod q).
    """
    for i in range(len(sigs)):
        for j in range(len(sigs)):
            if i == j:
                continue
            a_s, b_s = sigs[i], sigs[j]
            H1, H2 = H(a_s["message"]), H(b_s["message"])
            r1, s1, r2, s2 = a_s["r"], a_s["s"], b_s["r"], b_s["s"]
            for av in range(1, small_a + 1):
                for bv in range(-small_b, small_b + 1):
                    # det = s1·(-r2) - (-r1)·(s2·a) = -s1·r2 + r1·s2·a
                    det = (-s1 * r2 + r1 * s2 * av) % q
                    try:
                        di = modinv(det, q)
                    except ValueError:
                        continue
                    # k1 = (H1·(-r2) - (-r1)·(H2 - s2·b)) / det
                    k1 = (H1 * (-r2) + r1 * (H2 - s2 * bv)) * di % q
                    # x = (s1·(H2 - s2·b) - H1·s2·a) / det
                    x = (s1 * (H2 - s2 * bv) - H1 * s2 * av) * di % q
                    if pow(g, k1, p) % q != r1:
                        continue
                    if pow(g, x, p) == y:
                        print(f"    [+] a={av}, b={bv}, sigs #{i},{j}")
                        return x
    return None


def dsa_small_nonce(p, q, g, y, sigs, H, max_bits=24):
    """
    FIXED vs v1: iterate over ALL matching r, verify each candidate x.
    Also incremental g^k (much faster than pow each step).
    """
    limit = 1 << max_bits
    for sig in sigs:
        r = sig["r"]
        Hm = H(sig["message"])
        gk = g
        for k in range(1, limit):
            if gk % q == r:
                try:
                    x = (sig["s"] * k - Hm) * modinv(r, q) % q
                except ValueError:
                    gk = gk * g % p
                    continue
                if pow(g, x, p) == y:
                    print(f"    [+] k={k}, x verified")
                    return x
                # else: false-positive r, keep searching
            gk = gk * g % p
        print(f"    [*] done sig with r={r[:16]}...")
    return None


def dsa_small_x(p, q, g, y, factors_p1):
    for bits in [20, 24, 28, 32, 36, 40]:
        try:
            x = bsgs(g, y, p, 1 << bits)
        except TooBig:
            continue
        if x is not None:
            return x
    return None


def dsa_pohlig_hellman(p, q, g, y, factors_p1):
    return elgamal_enc_pohlig_hellman(p, g, y, factors_p1, order_of(g, p, factors_p1))


# ============================================================
# Dispatchers
# ============================================================

def _extract_pairs_elgamal(ch):
    """Normalize ElGamal ciphertexts into [(c1, c2, m_or_None), ...]."""
    pairs = []
    kp = ch.get("known_plaintext")
    m_known = None
    if kp is not None:
        if isinstance(kp, str):
            try:
                m_known = int(kp, 16) if kp.lower().startswith("0x") else B2L(kp.encode())
            except Exception:
                m_known = B2L(kp.encode())
        else:
            m_known = as_int(kp)

    # Format A: cipher_known + known_plaintext + cipher_flag
    if "cipher_known" in ch:
        c1, c2 = map(as_int, ch["cipher_known"])
        pairs.append((c1, c2, m_known))
    if "cipher_flag" in ch:
        c1, c2 = map(as_int, ch["cipher_flag"])
        pairs.append((c1, c2, None))
    # Format B: c1 / c2 single ciphertext
    if "c1" in ch and "c2" in ch:
        pairs.append((as_int(ch["c1"]), as_int(ch["c2"]), None))
    # Format C: ciphertexts array
    if "ciphertexts" in ch:
        for entry in ch["ciphertexts"]:
            if isinstance(entry, dict):
                c1, c2 = as_int(entry["c1"]), as_int(entry["c2"])
                m = entry.get("m") or entry.get("message") or entry.get("plaintext")
                if isinstance(m, str):
                    m = B2L(m.encode())
                elif m is not None:
                    m = as_int(m)
                pairs.append((c1, c2, m))
            else:
                c1, c2 = as_int(entry[0]), as_int(entry[1])
                pairs.append((c1, c2, None))
    return pairs


def solve_elgamal_encryption(ch, args):
    info = analyze_params(ch, need_q=False)
    p, g, y = info["p"], info["g"], info["y"]
    pairs = _extract_pairs_elgamal(ch)
    print(f"\n[i] ciphertext pairs: {len(pairs)}")

    # Known-x fast path
    if args.known_x is not None:
        x = args.known_x
        for idx, (c1, c2, m) in enumerate(pairs):
            if m is None:
                s = pow(c1, x, p)
                m = c2 * modinv(s, p) % p
                emit(f"ElGamal decrypt pair #{idx} (known x)", m, "plaintext")
        return True

    # A1: Nonce reuse (any pair)
    if len(pairs) >= 2:
        print("\n[→] A1: nonce reuse across pairs")
        m, how = elgamal_enc_nonce_reuse_multi(p, pairs)
        if m is not None:
            print(f"    {how}")
            if emit("ElGamal nonce reuse", m, "plaintext") == "flag":
                return True

        # A2: Sequential nonce
        print("\n[→] A2: sequential nonce")
        m, how = elgamal_enc_sequential(p, g, y, pairs)
        if m is not None:
            print(f"    {how}")
            if emit("ElGamal sequential nonce", m, "plaintext") == "flag":
                return True

    # A3: Small nonce (per unknown pair)
    for idx, (c1, c2, m) in enumerate(pairs):
        if m is not None:
            continue
        print(f"\n[→] A3: small nonce on pair #{idx}")
        pt, k = elgamal_enc_small_nonce(p, g, y, c1, c2)
        if pt is not None:
            print(f"    k = {k}")
            if emit(f"ElGamal small nonce (pair #{idx})", pt, "plaintext") == "flag":
                return True

    # A4: Message-derived nonce (diagnostic only — needs known plaintext)
    for (c1, c2, m) in pairs:
        if m is None:
            continue
        msg = L2B(m)
        name, _k = nonce_prng_patterns(p, g, c1, msg)
        if name:
            print(f"\n[→] A4: nonce = f(message) detected: {name}  (diagnostic only)")

    # A5: Small private key x
    print("\n[→] A5: small x via BSGS")
    x = elgamal_enc_small_x(p, g, y)
    if x is not None:
        emit("ElGamal small x", x, "x")
        for idx, (c1, c2, m) in enumerate(pairs):
            if m is None:
                s = pow(c1, x, p)
                pt = c2 * modinv(s, p) % p
                if emit(f"ElGamal decrypt pair #{idx}", pt, "plaintext") == "flag":
                    return True
        return True

    # A6: Small subgroup
    print("\n[→] A6: small-subgroup attack on y")
    x, q_small = elgamal_enc_small_subgroup(p, g, y, info["factors_p1"])
    if x is not None:
        print(f"    y in subgroup of order {q_small}")
        emit("ElGamal small subgroup", x, "x")
        for idx, (c1, c2, m) in enumerate(pairs):
            if m is None:
                pt = c2 * modinv(pow(c1, x, p), p) % p
                if emit(f"ElGamal decrypt pair #{idx}", pt, "plaintext") == "flag":
                    return True
        return True

    # A7: Pohlig-Hellman on ord(g)
    print("\n[→] A7: Pohlig-Hellman on ord(g)")
    x = elgamal_enc_pohlig_hellman(p, g, y, info["factors_p1"], info["ord_g"])
    if x is not None:
        emit("ElGamal Pohlig-Hellman", x, "x")
        for idx, (c1, c2, m) in enumerate(pairs):
            if m is None:
                pt = c2 * modinv(pow(c1, x, p), p) % p
                if emit(f"ElGamal decrypt pair #{idx}", pt, "plaintext") == "flag":
                    return True
        return True

    print("\n[-] All ElGamal encryption attacks exhausted.")
    return False


def solve_elgamal_signature(ch, args):
    info = analyze_params(ch, need_q=False)
    p, g, y = info["p"], info["g"], info["y"]
    H = make_hasher(ch, q=p - 1)

    sigs = []
    if "signatures" in ch:
        for s in ch["signatures"]:
            sigs.append({
                "message": s.get("message", s.get("m", "")),
                "r": as_int(s["r"]), "s": as_int(s["s"]),
            })
    elif "r" in ch and "s" in ch:
        sigs.append({
            "message": ch.get("m") or ch.get("message", ""),
            "r": as_int(ch["r"]), "s": as_int(ch["s"]),
        })
    if not sigs:
        print("[-] No signatures in input")
        return False

    # Optional signature verification first
    print("\n[→] Verify signatures")
    for i, sig in enumerate(sigs):
        ok = _elgamal_sig_verify(p, g, y, H(sig["message"]), sig["r"], sig["s"])
        print(f"    sig #{i}: {'VALID' if ok else 'INVALID'}")

    # Known-x fast path
    if args.known_x is not None:
        x = args.known_x
        print(f"\n[i] Using provided x = {x}")
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x)
        return bool(emit("x provided", x, "x"))

    # Known-k fast path
    if args.known_k is not None:
        x = elgamal_sig_known_k(p, g, y, sigs, H, args.known_k, 0)
        if x is not None:
            emit("ElGamal-sig known k", x, "x")
            enc = find_encrypted_flag(ch)
            if enc:
                return decrypt_flag_patterns(enc, x)
            return True

    # A1: nonce reuse
    if len(sigs) >= 2:
        print("\n[→] A1: nonce reuse (same r)")
        x = elgamal_sig_reuse(p, g, y, sigs, H)
        if x is not None:
            emit("ElGamal-sig nonce reuse", x, "x")
            enc = find_encrypted_flag(ch)
            if enc:
                return decrypt_flag_patterns(enc, x)
            return True

    # A2: small nonce (BSGS on r directly — no mod q collapse!)
    print("\n[→] A2: small nonce via BSGS on r")
    x, k = elgamal_sig_small_nonce(p, g, y, sigs, H)
    if x is not None:
        emit("ElGamal-sig small nonce", x, "x")
        print(f"    k = {k}")
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x)
        return True

    # A3: small x
    print("\n[→] A3: small x")
    x = elgamal_sig_small_x(p, g, y)
    if x is not None:
        emit("ElGamal-sig small x", x, "x")
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x)
        return True

    # A4: Pohlig-Hellman
    print("\n[→] A4: Pohlig-Hellman on ord(g)")
    x = elgamal_sig_pohlig_hellman(p, g, y, info["factors_p1"])
    if x is not None:
        emit("ElGamal-sig Pohlig-Hellman", x, "x")
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x)
        return True

    print("\n[-] All ElGamal-signature attacks exhausted.")
    return False


def solve_dsa(ch, args):
    info = analyze_params(ch, need_q=True)
    p, q, g, y = info["p"], info["q"], info["g"], info["y"]
    if q is None:
        print("[-] 'q' missing for DSA")
        return False
    H = make_hasher(ch, q=q)

    sigs = []
    if "signatures" in ch:
        for s in ch["signatures"]:
            sigs.append({
                "message": s.get("message", s.get("m", "")),
                "r": as_int(s["r"]), "s": as_int(s["s"]),
            })
    elif "r" in ch and "s" in ch:
        sigs.append({
            "message": ch.get("m") or ch.get("message", ""),
            "r": as_int(ch["r"]), "s": as_int(ch["s"]),
        })
    if not sigs:
        print("[-] No signatures")
        return False

    # Signature verification first — often the exam question!
    print("\n[→] Verify signatures")
    all_valid = True
    for i, sig in enumerate(sigs):
        ok = _dsa_verify(p, q, g, y, H(sig["message"]), sig["r"], sig["s"])
        print(f"    sig #{i}: {'VALID' if ok else 'INVALID'}")
        all_valid = all_valid and ok
    if not all_valid:
        print("    [!] Some signatures invalid — likely malformed input or forgery question")

    # Known-x fast path
    if args.known_x is not None:
        x = args.known_x
        print(f"\n[i] Using provided x = {x} (verify: g^x==y: {pow(g, x, p) == y})")
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x)
        return bool(emit("x provided", x, "x"))

    # Known-k fast path
    if args.known_k is not None:
        x = dsa_known_k(p, q, g, y, sigs, H, args.known_k, 0)
        if x is not None:
            emit("DSA known k", x, "x")
            enc = find_encrypted_flag(ch)
            if enc:
                return decrypt_flag_patterns(enc, x)
            return True

    x_recovered = None

    # A1: nonce reuse
    if len(sigs) >= 2:
        print("\n[→] A1: nonce reuse")
        x_recovered = dsa_reuse(p, q, g, y, sigs, H)
        if x_recovered is not None:
            emit("DSA nonce reuse", x_recovered, "x")

    # A2: sequential nonce
    if x_recovered is None and len(sigs) >= 2:
        print("\n[→] A2: sequential nonce (k₂ = k₁ + δ)")
        x_recovered = dsa_sequential(p, q, g, y, sigs, H)
        if x_recovered is not None:
            emit("DSA sequential nonce", x_recovered, "x")

    # A3: related nonces
    if x_recovered is None and len(sigs) >= 2:
        print("\n[→] A3: related nonces (k₂ = a·k₁ + b, small a,b)")
        x_recovered = dsa_related(p, q, g, y, sigs, H)
        if x_recovered is not None:
            emit("DSA related nonces", x_recovered, "x")

    # A4: small nonce (with verification)
    if x_recovered is None:
        print("\n[→] A4: small nonce (verify each candidate)")
        x_recovered = dsa_small_nonce(p, q, g, y, sigs, H)
        if x_recovered is not None:
            emit("DSA small nonce", x_recovered, "x")

    # A5: small x
    if x_recovered is None:
        print("\n[→] A5: small x")
        x_recovered = dsa_small_x(p, q, g, y, info["factors_p1"])
        if x_recovered is not None:
            emit("DSA small x", x_recovered, "x")

    # A6: Pohlig-Hellman
    if x_recovered is None:
        print("\n[→] A6: Pohlig-Hellman on ord(g)")
        x_recovered = dsa_pohlig_hellman(p, q, g, y, info["factors_p1"])
        if x_recovered is not None:
            emit("DSA Pohlig-Hellman", x_recovered, "x")

    if x_recovered is not None:
        enc = find_encrypted_flag(ch)
        if enc:
            return decrypt_flag_patterns(enc, x_recovered)
        return True

    print("\n[-] All DSA attacks exhausted.")
    return False


# ============================================================
# Main
# ============================================================

def detect_mode(ch):
    has_q = "q" in ch
    has_sig = "signatures" in ch or ("r" in ch and "s" in ch)
    has_ct = any(k in ch for k in ("c1", "c2", "cipher_known", "cipher_flag", "ciphertexts"))
    if has_q and has_sig:
        return "dsa"
    if has_sig and not has_ct:
        return "elgamal_sig"
    if has_ct:
        return "elgamal_enc"
    return None


def main():
    ap = ArgumentParser()
    ap.add_argument("challenge")
    ap.add_argument("--mode", choices=("dsa", "elgamal_enc", "elgamal_sig"))
    ap.add_argument("--known-x", type=int, default=None,
                    help="Provide private key x directly (fast path)")
    ap.add_argument("--known-k", type=int, default=None,
                    help="Provide nonce k for first signature (fast path)")
    args = ap.parse_args()

    with open(args.challenge) as f:
        ch = json.load(f)

    mode = args.mode or detect_mode(ch)
    if mode is None:
        print("[-] Cannot auto-detect challenge. Use --mode.")
        sys.exit(1)

    print("=" * 60)
    print(f"Mode: {mode}")
    print("=" * 60)

    if mode == "dsa":
        ok = solve_dsa(ch, args)
    elif mode == "elgamal_sig":
        ok = solve_elgamal_signature(ch, args)
    else:
        ok = solve_elgamal_encryption(ch, args)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()