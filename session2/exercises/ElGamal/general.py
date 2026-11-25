#!/usr/bin/env python3
"""
Universal ElGamal attack solver.
Usage: python elgamal_solver.py challenge.json

Підтримує формати:
  - Encryption: {"p", "g", "y", "cipher_known"?, "cipher_flag"?, "known_plaintext"?,
                 "ciphertext"?, "c1"?, "c2"?}
  - Signature:  {"p", "g", "y", "signatures": [{"m","r","s"}, ...]}
                або {"p", "g", "y", "m", "r", "s"}
"""
import json
import sys
import hashlib
from math import isqrt, gcd

from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

try:
    from sympy import factorint
    from sympy.ntheory.residue_ntheory import discrete_log
    from sympy.ntheory.modular import crt as sympy_crt
    HAS_SYMPY = True
except ImportError:
    HAS_SYMPY = False
    print("[!] sympy not installed — some attacks disabled")

# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def bsgs(g, h, p, order):
    """x: g^x = h mod p, x < order. O(sqrt(order)) time & space."""
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


def looks_like_text(b):
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(32 <= ord(c) < 127 or c in "\n\r\t" for c in s)


def try_output(m, label=""):
    """Пробуємо перетворити m на текст і вивести, якщо схоже на флаг."""
    if m is None or m == 0:
        return None
    b = long_to_bytes(int(m))
    if not looks_like_text(b):
        return None
    s = b.decode("utf-8")
    # пріоритет — типовим флагам
    if any(x in s.lower() for x in ("flag{", "ctf{", "htb{", "picoctf{")):
        print(f"\n[✓] FLAG ({label}): {s}\n")
    else:
        print(f"\n[+] Decrypted ({label}): {s}\n")
    return s


def compute_order(g, p, factors):
    """Обчислити ord(g), знаючи часткову факторизацію p-1."""
    order = p - 1
    for q in factors:
        while order % q == 0 and pow(g, order // q, p) == 1:
            order //= q
    return order


def factor_p_minus_1(p, limit=10**7):
    if not HAS_SYMPY:
        return None
    try:
        return factorint(p - 1, limit=limit)
    except Exception:
        return None


def pohlig_hellman_partial(g, y, p, order, factors):
    """Знайти x mod M, де M = добуток малих q^e з factors.
    Повертає (x_partial, M) або None."""
    if not HAS_SYMPY:
        return None
    residues, moduli = [], []
    for q, e in factors.items():
        if q > 10**6:
            continue
        qe = q ** e
        if order % qe != 0:
            continue
        # розв'язуємо x mod q^e
        g_q = pow(g, order // qe, p)
        y_q = pow(y, order // qe, p)
        x_q = 0
        ok = True
        for k in range(e):
            base = pow(g_q, qe // q, p)
            exp = qe // (q ** (k + 1))
            term = (y_q * pow(pow(g_q, x_q, p), -1, p)) % p
            target = pow(term, exp, p)
            d = bsgs(base, target, p, q)
            if d is None:
                ok = False
                break
            x_q += d * (q ** k)
        if ok:
            residues.append(x_q)
            moduli.append(qe)
    if not residues:
        return None
    x_partial, M = sympy_crt(moduli, residues)
    return int(x_partial) % int(M), int(M)


def recover_x_full(g, y, p, order, factors):
    """
    Спробувати знайти повний x:
      1) повний Pohlig-Hellman (якщо order гладкий)
      2) частковий PH + BSGS на залишку
    """
    if not HAS_SYMPY:
        return None

    # (1) чи повністю факторизовано?
    remaining = order
    for q, e in factors.items():
        qe = q ** e
        while remaining % q == 0:
            remaining //= q

    if remaining == 1:
        # повний PH
        res = pohlig_hellman_partial(g, y, p, order, factors)
        if res and pow(g, res[0], p) == y:
            return res[0]

    # (2) частковий PH + BSGS
    res = pohlig_hellman_partial(g, y, p, order, factors)
    if res is None:
        return None
    x_partial, M = res
    if M == order:
        return x_partial if pow(g, x_partial, p) == y else None
    remaining = order // M
    if remaining > 10**10:
        return None
    target = (y * pow(g, -x_partial, p)) % p
    g_M = pow(g, M, p)
    t = bsgs(g_M, target, p, remaining)
    if t is None:
        return None
    x = x_partial + t * M
    return x if pow(g, x, p) == y else None


# ------------------------------------------------------------------
# Attacks — Encryption
# ------------------------------------------------------------------

def attack_nonce_reuse(ch, m_known, c1_known, c2_known, c1_flag, c2_flag):
    """c1_known == c1_flag."""
    if c1_known is None or c1_flag is None or m_known is None:
        return None
    if c1_known != c1_flag:
        return None
    p = ch["p"]
    print("[*] Nonce reuse detected (c1 equal)")
    m_flag = (m_known * c2_flag * inverse(c2_known, p)) % p
    return try_output(m_flag, "nonce reuse")


def attack_sequential_nonce(ch, m_known, c1_known, c2_known, c1_flag, c2_flag,
                            max_delta=10000):
    """c1_flag = c1_known * g^delta для малого delta."""
    if None in (c1_known, c1_flag, m_known, c2_known, c2_flag):
        return None
    p, g, y = ch["p"], ch["g"], ch["y"]
    print(f"[*] Sequential nonce search |δ| ≤ {max_delta}")
    yk_known = (c2_known * inverse(m_known, p)) % p
    for delta in range(-max_delta, max_delta + 1):
        if (c1_known * pow(g, delta, p)) % p == c1_flag:
            print(f"[+] Sequential nonce: δ = {delta}")
            yk_flag = (yk_known * pow(y, delta, p)) % p
            m_flag = (c2_flag * inverse(yk_flag, p)) % p
            return try_output(m_flag, f"sequential nonce δ={delta}")
    return None


def attack_small_nonce(ch, c1_flag, c2_flag, name="flag", limits=None):
    """BSGS на c1_flag: c1 = g^k для малого k. Тоді m = c2 / y^k."""
    if c1_flag is None or c2_flag is None:
        return None
    p, g, y = ch["p"], ch["g"], ch["y"]
    limits = limits or [20, 24, 28, 32, 36, 40, 44, 48]
    for bits in limits:
        k = bsgs(g, c1_flag, p, 1 << bits)
        if k is not None:
            print(f"[+] Small nonce k_{name} = {k} (< 2^{bits})")
            s = pow(y, k, p)
            m = (c2_flag * inverse(s, p)) % p
            return try_output(m, f"small nonce (<2^{bits})")
    return None


def attack_small_x(ch):
    """BSGS на y = g^x для малого x."""
    p, g, y = ch["p"], ch["g"], ch["y"]
    for bits in [20, 24, 28, 32, 36, 40, 44, 48]:
        x = bsgs(g, y, p, 1 << bits)
        if x is not None:
            print(f"[+] Small private key x = {x} (< 2^{bits})")
            return x
    return None


def attack_nonce_from_hash(ch, m_known_bytes, c1_known):
    """Перевірити, чи k = m / H(m) / len(m)."""
    if c1_known is None or m_known_bytes is None:
        return None
    p, g = ch["p"], ch["g"]
    cands = {
        "k = m_int":      bytes_to_long(m_known_bytes),
        "k = len(m)":     len(m_known_bytes),
        "k = sha256(m)":  int(hashlib.sha256(m_known_bytes).hexdigest(), 16),
        "k = sha1(m)":    int(hashlib.sha1(m_known_bytes).hexdigest(), 16),
        "k = md5(m)":     int(hashlib.md5(m_known_bytes).hexdigest(), 16),
    }
    for name, k in cands.items():
        if pow(g, k % (p - 1), p) == c1_known:
            print(f"[+] Nonce matches: {name}")
            return k
    return None


# ------------------------------------------------------------------
# Attacks — Signature
# ------------------------------------------------------------------

def attack_signature_nonce_reuse(ch, signatures):
    """Два підписи з однаковим r -> розкриваємо k і x."""
    p, g, y = ch["p"], ch["g"], ch["y"]
    for i in range(len(signatures)):
        for j in range(i + 1, len(signatures)):
            s1, s2 = signatures[i], signatures[j]
            if s1["r"] != s2["r"]:
                continue
            print(f"[*] Nonce reuse in signatures #{i} and #{j} (r equal)")
            m1, m2 = s1["m"], s2["m"]
            r, sa, sb = s1["r"], s1["s"], s2["s"]
            num = (m1 - m2) % (p - 1)
            den = (sa - sb) % (p - 1)
            gd = gcd(den, p - 1)
            if gd == 0:
                continue
            # (sa - sb) * k = (m1 - m2) mod (p-1)
            # Розв'язуємо: k ≡ num/den mod (p-1)/gd, gd розв'язків
            den_red = den // gd
            if gcd(den_red, (p - 1) // gd) != 1:
                continue
            k0 = (num // gd) * pow(den_red, -1, (p - 1) // gd) % ((p - 1) // gd)
            for t in range(gd):
                k = k0 + t * ((p - 1) // gd)
                if k == 0:
                    continue
                # x = (m1 - k*sa) * r^{-1} mod (p-1)
                try:
                    r_inv = pow(r, -1, p - 1)
                except ValueError:
                    continue
                x = ((m1 - k * sa) * r_inv) % (p - 1)
                if pow(g, x, p) == y:
                    print(f"[+] x recovered = {x}")
                    return x
    return None


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def solve_encryption(ch):
    p, g, y = ch["p"], ch["g"], ch["y"]

    # ---- зчитуємо, що є в JSON ----
    c1_known = c2_known = None
    c1_flag = c2_flag = None
    m_known_bytes = m_known = None

    if "cipher_known" in ch:
        c1_known, c2_known = ch["cipher_known"]
    if "cipher_flag" in ch:
        c1_flag, c2_flag = ch["cipher_flag"]
    if "ciphertext" in ch:
        ct = ch["ciphertext"]
        if isinstance(ct, list) and len(ct) == 2:
            c1_flag, c2_flag = ct
    if "c1" in ch and "c2" in ch:
        c1_flag, c2_flag = ch["c1"], ch["c2"]
    if "known_plaintext" in ch:
        kp = ch["known_plaintext"]
        m_known_bytes = kp.encode() if isinstance(kp, str) else bytes(kp)
        m_known = bytes_to_long(m_known_bytes)

    print(f"[i] p = {p.bit_length()} bits, g = {g}")
    if c1_known is not None:
        print(f"[i] known ciphertext present")
    if c1_flag is None:
        print("[!] No flag ciphertext — nothing to decrypt")
        return

    # ---- швидкі атаки на nonce ----
    r = attack_nonce_reuse(ch, m_known, c1_known, c2_known, c1_flag, c2_flag)
    if r is not None: return

    r = attack_sequential_nonce(ch, m_known, c1_known, c2_known, c1_flag, c2_flag)
    if r is not None: return

    # small nonce на flag
    r = attack_small_nonce(ch, c1_flag, c2_flag, name="flag")
    if r is not None: return

    # nonce = H(m)?
    if c1_known is not None and m_known_bytes is not None:
        attack_nonce_from_hash(ch, m_known_bytes, c1_known)

    # ---- шукаємо x ----
    print("[*] Factoring p-1 (limited)...")
    factors = factor_p_minus_1(p)
    if factors:
        big = [q for q in factors if q > 10**8]
        if big:
            print(f"    p-1 has {len(big)} large factor(s), biggest = "
                  f"{max(big).bit_length()} bits")
        else:
            print(f"    p-1 fully factored into small primes")
    else:
        print("    factoring failed, continuing anyway")

    if factors:
        order_g = compute_order(g, p, factors)
    else:
        order_g = p - 1
    print(f"[i] order(g) = {order_g.bit_length()} bits")

    # small x
    x = attack_small_x(ch)
    if x is not None:
        m = (c2_flag * inverse(pow(c1_flag, x, p), p)) % p
        return try_output(m, "small x")

    # Pohlig-Hellman (повний або частковий + BSGS)
    if HAS_SYMPY and factors:
        print("[*] Pohlig-Hellman...")
        x = recover_x_full(g, y, p, order_g, factors)
        if x is not None:
            print(f"[+] x recovered = {x}")
            m = (c2_flag * inverse(pow(c1_flag, x, p), p)) % p
            return try_output(m, "pohlig-hellman")

    # sympy discrete_log (для малих p)
    if HAS_SYMPY and p.bit_length() < 200:
        try:
            print("[*] sympy.discrete_log...")
            x = int(discrete_log(p, y, g))
            if pow(g, x, p) == y:
                print(f"[+] x recovered = {x}")
                m = (c2_flag * inverse(pow(c1_flag, x, p), p)) % p
                return try_output(m, "discrete_log")
        except Exception as e:
            print(f"    discrete_log failed: {e}")

    print("\n[-] Automatic attacks failed.")
    print("    Suggestions:")
    print("      - Increase BSGS limits in attack_small_nonce/small_x")
    print("      - Try external tools: sage, pari, pyecm")
    print("      - Manually inspect the challenge structure")


def solve_signature(ch, signatures):
    p, g, y = ch["p"], ch["g"], ch["y"]
    print(f"[i] Signature mode, {len(signatures)} signature(s)")
    x = attack_signature_nonce_reuse(ch, signatures)
    if x is not None:
        return x
    print("[-] No signature attack succeeded")


def main():
    if len(sys.argv) < 2:
        print("Usage: python elgamal_solver.py challenge.json")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        ch = json.load(f)

    # автовизначення режиму
    is_sig = "signatures" in ch or ("r" in ch and "s" in ch and "c1" not in ch)

    if is_sig:
        sigs = ch.get("signatures")
        if sigs is None:
            sigs = [{"m": ch.get("m"), "r": ch["r"], "s": ch["s"]}]
        solve_signature(ch, sigs)
    else:
        solve_encryption(ch)


if __name__ == "__main__":
    main()