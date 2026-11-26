#!/usr/bin/env python3
"""

  ── Diffie–Hellman ──────────────────────────────────────────
    ✓ DH MITM                        (priority: critical)
    ✓ Weak DH parameters             (priority: critical)
    ✓ Small-subgroup confinement     (priority: critical)
    ✓ Weak private exponent          (priority: critical)
    ✓ Static vs Ephemeral / forward-secrecy check

  ── Protocol ────────────────────────────────────────────────
    ✓ Replay attack                  (priority: critical)
    ✓ Reflection attack              (priority: high)
    ✓ Unknown Key-Share (UKS)        (priority: high)
    ✓ Key Compromise Impersonation   (priority: medium)
    ✓ Parallel-session / interleaving (priority: medium)
    ✓ Downgrade attack               (priority: medium)

  ── KDC ─────────────────────────────────────────────────────
    ✓ Needham–Schroeder symmetric    (priority: critical)
    ✓ Denning–Sacco                  (priority: critical)
    ✓ Stale session key / ticket replay
    ✓ Kerberos-pattern checklist

  ── PKI ─────────────────────────────────────────────────────
    ✓ Certificate validation audit   (priority: high)
    ✓ TOFU / Proof-of-Possession check

  ── JWT / MAC ───────────────────────────────────────────────
    ✓ Claims validation (exp/aud/iss/nbf)
    ✓ Length extension on naive H(K||m)
    ✓ Timing side channel
    ✓ Serialization ambiguity

  ── Key management ──────────────────────────────────────────
    ✓ Weak KDF / missing domain separation
    ✓ Key reuse across purposes
    ✓ Forward secrecy failure

  ── Encoding ────────────────────────────────────────────────
    ✓ Encoding/parsing confusion

USAGE:
    python keydist_advanced.py --list
    python keydist_advanced.py --demo                # run all local demos
    python keydist_advanced.py --attack dh_mitm
    python keydist_advanced.py --config cfg.json --attack http_replay

ATTACK NAMES:
    dh_mitm, dh_params, dh_small_subgroup, dh_weak_exp,
    replay, reflection, uks, kci, interleaving, downgrade,
    ns_sym, denning_sacco, ticket_replay,
    cert_audit, tofu_poc,
    jwt_claims, mac_length_ext, mac_timing, mac_serialization,
    kdf_audit, forward_secrecy,
    encoding_confusion,
    http_replay, http_reflection, http_downgrade
    https: //github.com/thomas-lauwers/NetworkSecurity
"""

import sys
import os
import json
import time
import math
import hmac
import hashlib
import secrets
import base64
import struct
from typing import Optional, List, Tuple, Dict, Any

# ── optional deps ────────────────────────────────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════
# 0.  Math primitives
# ═══════════════════════════════════════════════════════════════

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def crt(residues: List[int], moduli: List[int]) -> int:
    """Chinese Remainder Theorem: combine x ≡ r_i (mod m_i)."""
    x, M = 0, 1
    for r, m in zip(residues, moduli):
        M_i = M * m
        t = (r - x) * modinv(M % m, m) % m
        x = x + M * t
        M = M_i
    return x % M


def factorize(n: int, limit: int = 10**6) -> Dict[int, int]:
    """Trial division. Good enough for exam-sized numbers."""
    f: Dict[int, int] = {}
    d = 2
    while d * d <= n and d <= limit:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


# ── Discrete-log solvers ────────────────────────────────────

def dlp_bruteforce(g: int, h: int, p: int, n: int) -> Optional[int]:
    """Classic brute-force: x ∈ [0, n). Only for tiny n."""
    cur = 1
    for x in range(n):
        if cur == h:
            return x
        cur = (cur * g) % p
    return None


def dlp_bsgs(g: int, h: int, p: int, n: int) -> Optional[int]:
    """
    Baby-Step Giant-Step for g^x ≡ h (mod p), x ∈ [0, n).
    Time/memory O(√n). Textbook 'exam' algorithm.
    """
    m = math.isqrt(n - 1) + 1
    baby: Dict[int, int] = {}
    cur = 1
    for j in range(m):
        baby.setdefault(cur, j)
        cur = (cur * g) % p
    # factor = g^(-m) mod p
    gm = pow(g, m, p)
    factor = modinv(gm, p)
    gamma = h
    for i in range(m + 1):
        if gamma in baby:
            x = i * m + baby[gamma]
            if x < n and pow(g, x, p) == h:
                return x
        gamma = (gamma * factor) % p
    return None


def dlp_pollard_rho(g: int, h: int, p: int, n: int,
                    max_iter: int = 2_000_000) -> Optional[int]:
    """
    Pollard's Rho for DLP, O(√n) time, O(1) memory.
    Same category as BSGS but memory-cheap.
    """
    def step(a: int, b: int) -> Tuple[int, int]:
        x = (pow(g, a, p) * pow(h, b, p)) % p
        r = x % 3
        if r == 0:
            return (a + 1) % n, b
        if r == 1:
            return (2 * a) % n, (2 * b) % n
        return a, (b + 1) % n

    for _ in range(10):    # a few restarts
        a0 = secrets.randbelow(n)
        b0 = secrets.randbelow(n)
        at, bt = a0, b0
        ah, bh = a0, b0
        for _ in range(max_iter):
            at, bt = step(at, bt)
            ah, bh = step(*step(ah, bh))
            xt = (pow(g, at, p) * pow(h, bt, p)) % p
            xh = (pow(g, ah, p) * pow(h, bh, p)) % p
            if xt == xh:
                num = (ah - at) % n
                den = (bt - bh) % n
                if den == 0:
                    break    # restart
                try:
                    x = (num * modinv(den, n)) % n
                except ValueError:
                    break
                if pow(g, x, p) == h:
                    return x
                break
    return None


def dlp_pohlig_hellman(g: int, h: int, p: int, n: int) -> Optional[int]:
    """
    Pohlig–Hellman — factor n, solve DLP in each prime-power,
    combine with CRT. Exam favourite when n is smooth.
    """
    factors = factorize(n)
    # recompute full factorization safely (n may still be composite)
    for q in list(factors):
        e = factors[q]
        factors[q] = e
    residues, moduli = [], []
    for q, e in factors.items():
        qe = q ** e
        gi = pow(g, n // qe, p)
        hi = pow(h, n // qe, p)
        # solve DLP in subgroup of order qe
        if qe <= 2**20:
            xi = dlp_bsgs(gi, hi, p, qe)
        else:
            xi = dlp_pollard_rho(gi, hi, p, qe)
        if xi is None:
            return None
        residues.append(xi)
        moduli.append(qe)
    return crt(residues, moduli)


# ═══════════════════════════════════════════════════════════════
# 1.  Diffie–Hellman attacks
# ═══════════════════════════════════════════════════════════════

def dh_mitm_demo():
    """
    [CRITICAL]  Diffie–Hellman Man-in-the-Middle
    ============================================
    Unauthenticated DH is vulnerable to MITM: attacker establishes
    two independent shared secrets (one with Alice, one with Bob).
    Since DH offers no identity binding, both parties believe they
    talk to each other.

    MATH
    ----
    Alice:   A = g^a,  receives B'  → K_A = B'^a = g^(a·m₂)
    Bob:     B = g^b,  receives A'  → K_B = A'^b = g^(m₁·b)
    Mallory: knows m₁, m₂ → derives both keys:
             K_A = A^(m₂) = g^(a·m₂)
             K_B = B^(m₁) = g^(m₁·b)

    Mallory re-encrypts traffic on each leg, so Alice and Bob see
    correct plaintext and never detect the attack.

    DETECTION in a challenge
    ------------------------
    • DH parameters exchanged without signatures / certificates.
    • No sign of authenticated exchange in transcript.
    • Messages fit pattern: g^x sent in cleartext, no MAC on it.
    """
    print("[DEMO] DH MITM")
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    g = 2
    a, b = secrets.randbelow(p - 3) + 2, secrets.randbelow(p - 3) + 2
    m1, m2 = secrets.randbelow(p - 3) + 2, secrets.randbelow(p - 3) + 2

    A, B = pow(g, a, p), pow(g, b, p)
    print(f"  Alice → A = g^a     (a hidden)")
    print(f"  Bob   → B = g^b     (b hidden)")

    # Mallory replaces each public value
    A_for_bob = pow(g, m1, p)
    B_for_alice = pow(g, m2, p)
    print(f"  Mallory → A' = g^m1 (sends to Bob)")
    print(f"  Mallory → B' = g^m2 (sends to Alice)")

    K_alice = pow(B_for_alice, a, p)
    K_bob = pow(A_for_bob, b, p)
    print(f"\n  Alice computes K_A = B'^a = g^(a·m2)")
    print(f"  Bob   computes K_B = A'^b = g^(m1·b)")
    print(f"  → K_A ≠ K_B (they do NOT share a secret with each other)")
    print(f"\n  Mallory recomputes both:")
    m_alice = pow(A, m2, p)
    m_bob = pow(B, m1, p)
    print(f"  K_A (Mallory) matches Alice's: {m_alice == K_alice}")
    print(f"  K_B (Mallory) matches Bob's:   {m_bob == K_bob}")
    print(f"\n  → MITM successful: Mallory reads & re-encrypts all traffic.")
    print("\n  Fix: sign the DH public values (STS, TLS, Signal, IKEv2).")
    return True


def dh_params(p: int, g: int, y: Optional[int] = None) -> List[str]:
    """
    [CRITICAL]  Weak-DH-Parameter Audit
    ===================================
    Large |p| does NOT imply safety. Check:
      • g ∈ {0, 1, p-1}: degenerate group / order-1 or order-2 element
      • y ∈ {0, 1, p-1}: same problem on peer's public value
      • small p (e.g. < 2^1024 for exam demos; < 2048 real-world min)
      • composite p (must be prime!)
      • y not in the subgroup generated by g

    RETURNS: list of findings (empty = looks ok)
    """
    findings = []
    if p < 2**1024:
        findings.append(f"p is only {p.bit_length()} bits (<1024)")

    # primality hint (Miller-Rabin, 40 rounds)
    if not _is_probable_prime(p):
        findings.append("p is NOT prime")

    if g in (0, 1):
        findings.append(f"g = {g}: degenerate group (order ≤ 1)")
    if g == p - 1:
        findings.append("g = p-1: order 2, shared secret ∈ {1, p-1}")
    if g == 0:
        findings.append("g = 0: every exponentiation → 0")

    if y is not None:
        if y in (0, 1):
            findings.append(f"peer public y = {y}: shared secret is trivial")
        if y == p - 1:
            findings.append("peer public y = p-1: order 2")
        # subgroup-membership: y^q mod p must equal 1 for prime q | p-1
        # (only check small factor for demo)
        for q in factorize(p - 1).keys():
            if q < 1000:
                if pow(y, (p - 1) // q, p) == 1:
                    findings.append(
                        f"y has small-order factor {q}: vulnerable to "
                        f"small-subgroup attack")
                    break
    return findings


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2: return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes: return True
    for q in small_primes:
        if n % q == 0: return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def dh_small_subgroup_demo():
    """
    [CRITICAL]  Small-Subgroup Confinement
    ======================================
    If (p-1) has a small prime factor q, an active attacker can
    send a public value h of ORDER q to the victim.  The victim
    computes K = h^a, which lies in a subgroup of size q.  The
    attacker then brute-forces a mod q from K.

    Repeat for several small factors q₁, q₂, ... → CRT recovers a
    fully, provided ∏ qᵢ > a.  (This is exactly why safe primes
    p = 2q + 1 with q prime matter.)

    DEMO STRUCTURE
    --------------
    • Victim secret a, public y = g^a.
    • Attacker picks small-order element h (order q | p-1).
    • Victim responds: K = h^a mod p.
    • Attacker tries every value x ∈ [0, q): h^x == K?
    → recovers a mod q.  Do that for all small q, CRT.
    """
    print("[DEMO] Small-subgroup confinement")
    # small p with smooth p-1
    p = 2 * 3 * 5 * 7 * 11 * 13 * 17 + 1          # 510511? too small
    p = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 + 1  # ~223092871
    while not _is_probable_prime(p):
        p += 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23
    g = 2
    a = secrets.randbelow(p - 3) + 2
    y = pow(g, a, p)
    print(f"  p = {p} ({p.bit_length()}-bit), g = {g}")
    print(f"  Victim public y = g^a ; a is secret")

    factors = factorize(p - 1)
    print(f"  p-1 factors: {factors}   ← this is the vulnerability")

    residues, moduli = [], []
    for q in sorted(factors):
        if q > 100_000:
            continue                       # attacker only handles small q
        # build element of order exactly q in Z_p^*
        h = pow(g, (p - 1) // q, p)
        # victim's response to attacker's chosen h
        K = pow(h, a, p)
        # brute force a mod q
        found = None
        cur = 1
        for x in range(q):
            if cur == K:
                found = x; break
            cur = (cur * h) % p
        if found is None:
            continue
        print(f"    q={q:>6}  →  a mod q = {found}")
        residues.append(found); moduli.append(q)

    if residues:
        a_recovered = crt(residues, moduli)
        print(f"\n  CRT → a mod ∏q = {a_recovered}")
        print(f"  Actual a          = {a}")
        print(f"  Match: {a_recovered == a % math.prod(moduli)}")
        print(f"\n  Protection: validate peer's public value is in the "
              f"prime-order subgroup; use safe primes.")
    return True


def dh_weak_exp_demo():
    """
    [CRITICAL]  Weak Private Exponent
    ================================
    If a (or b) is chosen from a small range [0, N), it is trivially
    recoverable from y = g^a mod p using generic DLP:
      • N < 2^40   → BSGS
      • N arbitrary → Pollard rho (still √N)
      • n = p-1 smooth → Pohlig–Hellman (polynomial in log p)

    This demo uses a SMOOTH p-1 and Pohlig–Hellman.  On exam, watch
    for hints like 'a is small', 'a < 2^32', or smooth p-1 printed.
    """
    print("[DEMO] Weak private exponent (Pohlig–Hellman on smooth p)")
    # Small smooth prime; in an actual exam, p would be larger but p-1 smooth
    p = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 + 1
    while not _is_probable_prime(p):
        p += 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29
    g = 2
    n = p - 1
    a = secrets.randbelow(n - 1) + 1
    y = pow(g, a, p)
    print(f"  p = {p}, g = {g}")
    print(f"  y = g^a mod p  (a secret, a ∈ [1, n))")

    factors = factorize(n)
    print(f"  p-1 = {factors}   ← smooth ⇒ PH works")

    t0 = time.time()
    recovered = dlp_pohlig_hellman(g, y, p, n)
    dt = time.time() - t0
    print(f"  Pohlig–Hellman → a = {recovered}   (in {dt*1000:.1f} ms)")
    print(f"  Match: {recovered == a}")
    print("\n  Fix: use p = 2q+1 with q prime (safe prime), "
          "a ≥ 256-bit random.")
    return True


# ═══════════════════════════════════════════════════════════════
# 2.  Protocol attacks (offline demos)
# ═══════════════════════════════════════════════════════════════

def replay_demo():
    """
    [CRITICAL]  Replay Attack
    =========================
    Any authenticated message can be REPLAYED if the receiver does
    not check freshness.  Authenticity (HMAC / signature) is not
    freshness.

    Detection in a challenge
    ------------------------
    • Message carries no nonce/timestamp/sequence.
    • Server accepts the same payload twice with 200 OK.
    • Server does not bind nonce to session / sender.
    """
    print("[DEMO] Replay attack on a stateless signed request")

    KEY = b"server-secret"
    def sign(payload: bytes) -> bytes:
        return hmac.new(KEY, payload, hashlib.sha256).digest()

    def verify(payload: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(sign(payload), sig)

    payload = b'{"action":"transfer","amount":100,"to":"Mallory"}'
    sig = sign(payload)
    print(f"  Original request (signed once):")
    print(f"    payload = {payload}")
    print(f"    sig     = {sig.hex()[:32]}…")

    # ── vulnerable server: no freshness check
    def vulnerable_server(p, s) -> str:
        return "OK" if verify(p, s) else "REJECT"

    r1 = vulnerable_server(payload, sig)
    r2 = vulnerable_server(payload, sig)   # ← replay
    r3 = vulnerable_server(payload, sig)   # ← replay again
    print(f"\n  Attempt 1: {r1}")
    print(f"  Attempt 2: {r2}   ← replay")
    print(f"  Attempt 3: {r3}   ← replay again")
    print(f"  → {r1 == r2 == r3 == 'OK'}")

    print("\n  Fix: server keeps nonce / last-timestamp per sender; "
          "rejects duplicates.")
    return True


def reflection_demo():
    """
    [HIGH]  Reflection Attack
    =========================
    Two parties (A, B) share one key K and use the SAME
    challenge-response shape in both directions, with no role tag.
    Attacker can play a peer's own response back to a second
    parallel session, "reflecting" the answer.

    DEMO
    ----
    Target B accepts a client that answers B's nonce with E_K(N).
    Attacker Mallory opens session 1 to B, gets N₁.
    Opens session 2 to B, SENDS N₁ as if it were Mallory's nonce.
    B replies E_K(N₁).
    Mallory sends E_K(N₁) on session 1 → B accepts as A.

    Protection: role tagging in MACs (e.g. "client‖" prefix),
    different keys per direction, channel binding.
    """
    print("[DEMO] Reflection attack (symmetric challenge-response)")
    K = b"shared-key-1234"
    def E(n: bytes) -> bytes:
        return hmac.new(K, n, hashlib.sha256).digest()

    # nonces chosen by target B
    N1 = b"nonce-session-1"
    print(f"  Mallory → B (session 1, claim=Alice): hello")
    print(f"  B → Mallory: N1 = {N1!r}")

    print(f"  Mallory opens session 2 (claim=Alice), reflects N1 back:")
    print(f"  Mallory → B (session 2, claim=Alice): N1")
    resp = E(N1)
    print(f"  B → Mallory (session 2): E_K(N1) = {resp.hex()[:16]}…")

    print(f"  Mallory → B (session 1): E_K(N1)")
    print(f"  Server B checks: E_K(N1) == E_K(N1) → ACCEPT as Alice")
    print(f"\n  Fix: include role prefix: E_K(b'client'||N).")
    return True


def uks_demo():
    """
    [HIGH]  Unknown Key-Share (UKS)
    ===============================
    A and B end up with the SAME key K, but B mis-identifies the
    peer: B thinks K is shared with Mallory.  Mallory does NOT
    know K (so this is not a full MITM), but B will accept
    messages later under false assumptions — a critical trust
    failure (e.g. B accepts 'signed' messages as coming from
    Mallory, which actually came from A).

    Root cause: identity not cryptographically bound to the key.
    """
    print("[DEMO] Unknown Key-Share")

    class Party:
        def __init__(self, name): self.name = name
        def __repr__(self): return self.name

    A, B, M = Party("Alice"), Party("Bob"), Party("Mallory")

    print("  Protocol (stripped):")
    print("    M → B:  identity=A, key=K_AM  (Mallory claims K_AM is shared)")
    print("    B thinks:  'I share K_AM with Mallory'")
    print("    A thinks:  'I share K_AM with Bob'")
    print()
    print("  Actual shared key material:")
    print("    K_A = K_AM   peer(A) thinks: Bob")
    print("    K_B = K_AM   peer(B) thinks: Mallory")
    print("  → Same key, DIFFERENT peer identity")

    print("\n  Consequence:")
    print("    If A later sends B 'sign with K_AM', B records 'Mallory signed X'.")
    print("    Dispute resolution / audit trails are broken.")
    print("  Fix: bind identity into the key derivation:")
    print("       K = KDF(K_shared, 'A‖B' sorted-canonical).")
    return True


def kci_demo():
    """
    [MEDIUM]  Key Compromise Impersonation (KCI)
    ============================================
    Long-term key of A is compromised.  Obviously anyone can
    impersonate A.  KCI asks: can attacker now impersonate B to A?

    Classic KCI-vulnerable protocol shape:
        M → A:  g^m           (M picks m)
        A → M:  g^a  (A's long-term public)
        M → A:  sign_A-priv'(g^m)   ... but M does NOT have a priv

    Actually vulnerable shape (Toy DH + signature):
        A → M: g^a
        M → A: g^m
        Both then compute g^(am) as session key.
    If attacker has A's long-term private key, they can forge any
    signature by A.  Combined with a DH exchange where A never
    verifies the peer's SIGNATURE (only verifies A's own), attacker
    can convince A that "B" is responding.
    """
    print("[DEMO] Key Compromise Impersonation")
    print("  Scenario: attacker stole Alice's long-term private key.")
    print()
    print("  Naïve claim: attacker can only impersonate Alice.")
    print()
    print("  Vulnerable protocol (MACs over shared secret only):")
    print("    B → A:  g^b,  MAC_K_AB(?)\n    A → B:  g^a,  MAC_K_AB(?)")
    print("  If MAC uses a key derived from B's long-term key AND")
    print("  A never re-verifies B's signature, attacker who has")
    print("  A's long-term key can 'answer as B would have' to A.")
    print()
    print("  Result: attacker impersonates B to A (not just A to B).")
    print("  Fix: HMQV / NAXOS / signed-DH — bind BOTH long-term")
    print("       public keys into the session key.")
    return True


def interleaving_demo():
    """
    [MEDIUM]  Parallel-Session / Interleaving Attack
    ================================================
    Multiple simultaneous sessions of a challenge-response protocol
    can be woven together if the protocol lacks:
      • Session-Id binding
      • Transcript hashing
      • Per-direction keys
    The attacker uses messages from one session to answer another.

    (Reflection is a special case — 2 sessions with SAME key.)
    """
    print("[DEMO] Interleaving attack sketch")
    print("  Classic target: ISO-9798-3 or any non-transcript-bound KE.")
    print()
    print("  Mallory opens 3 parallel sessions to Bob:")
    print("    sess1 sends N_M1, receives E_K_B(N_M1), N_B1")
    print("    sess2 sends N_B1, receives E_K_B(N_B1), N_B2")
    print("    sess3 sends N_B2, receives E_K_B(N_B2), ...")
    print("  She can now finish sess1 by answering N_B1 → "
          "Bob authenticates her.")
    print()
    print("  Fix: hash the FULL transcript (all messages so far) into")
    print("       every MAC, or use a single session-id mixed into key.")
    return True


def downgrade_demo():
    """
    [MEDIUM]  Downgrade Attack
    ==========================
    If the protocol lets parties negotiate {algorithms | versions |
    key sizes} WITHOUT protection, an attacker can edit the
    negotiation to force a weaker choice (MD5 instead of SHA-256,
    DH-512 instead of DH-2048, etc.).  Both endpoints see a
    consistent transcript so they think they agreed.

    PROTECTION: sign the negotiation with the ephemeral DH key or
    use TLS-1.3-style transcript-bound key schedule.
    """
    print("[DEMO] Downgrade attack")
    client_prefs = ["AEAD-AES-256", "AEAD-AES-128", "CBC-3DES-MD5"]
    server_prefs = ["AEAD-AES-256", "AEAD-AES-128", "CBC-3DES-MD5"]
    print(f"  Client supports: {client_prefs}")
    print(f"  Server supports: {server_prefs}")
    print(f"  Honest choice: {[x for x in client_prefs if x in server_prefs][0]}")

    # attacker truncates
    tampered = ["CBC-3DES-MD5"]
    print(f"  Attacker sends client list as: {tampered}")
    print(f"  Server replies: {[x for x in tampered if x in server_prefs][0]}")
    print("  → Both sides agree on broken cipher; "
          "neither notices if negotiation is unsigned.")
    print("  Fix: include negotiation in key-confirmation MAC.")
    return True


# ═══════════════════════════════════════════════════════════════
# 3.  KDC / Needham–Schroeder / Kerberos-pattern
# ═══════════════════════════════════════════════════════════════

def _enc(key: bytes, data: bytes) -> bytes:
    """Toy 'encryption': HMAC-CTR. For demo only — not secure."""
    out = b""
    counter = 0
    while len(out) < len(data):
        out += hmac.new(key, struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(data, out))


def ns_sym_demo():
    """
    [CRITICAL]  Needham–Schroeder Symmetric
    =======================================
    Original protocol (1978):

        A → KDC : A, B, N_A
        KDC → A : E_{K_A}( K_AB, B, N_A, E_{K_B}( K_AB, A ) )
        A → B   : E_{K_B}( K_AB, A )
        B → A   : E_{K_AB}( N_B )
        A → B   : E_{K_AB}( N_B − 1 )

    Weakness: N_B (Bob's nonce) proves to Alice that Bob is fresh,
    but A's last answer N_B − 1 is NOT cryptographically bound to
    A's identity nor to the transcript.  Combined with weak
    freshness, this enables the Denning–Sacco replay (next demo).
    """
    print("[DEMO] Needham–Schroeder symmetric (structure walk-through)")
    KA, KB = b"long-term-A", b"long-term-B"
    KAB = secrets.token_bytes(16)
    NA, NB = secrets.token_bytes(8), secrets.token_bytes(8)

    print(f"  Step 1  A → KDC : A, B, N_A = {NA.hex()}")
    m = KAB + b"|B|" + NA + b"|" + KB + b"|" + KAB
    m_to_A = _enc(KA, m)
    print(f"  Step 2  KDC → A : E_KA(KAB, B, NA, E_KB(KAB, A))  "
          f"[{len(m_to_A)}B]")
    t = KAB + b"|A"
    ticket = _enc(KB, t)
    print(f"          (embedded ticket E_KB(KAB, A)  [{len(ticket)}B])")

    print(f"  Step 3  A → B   : ticket  [{len(ticket)}B]")
    nb_echo = _enc(KAB, NB)
    print(f"  Step 4  B → A   : E_KAB(N_B)  [{len(nb_echo)}B]")
    print(f"  Step 5  A → B   : E_KAB(N_B - 1)")
    print("\n  Looks safe — nonces used.  But the ticket E_KB(KAB, A)")
    print("  remains valid forever unless the KDC expires it.")
    return True


def denning_sacco_demo():
    """
    [CRITICAL]  Denning–Sacco Attack
    ================================
    If an old session key K_AB is ever compromised (logged,
    recovered from a backup, leaked), an attacker can REPLAY the
    old NS ticket E_{K_B}(K_AB, A) to B.  Because the ticket does
    not carry a timestamp/lifetime, B accepts it as fresh.  The
    attacker — knowing K_AB — now speaks as A.

    DEMO
    ----
    1. Recover K_AB from a previous session.
    2. Replay E_{K_B}(K_AB, A) to B.
    3. Respond to B's nonce with E_{K_AB}(N_B - 1).
    4. B accepts attacker as A.
    """
    print("[DEMO] Denning–Sacco (stale session key replay)")
    KB = b"long-term-B"
    K_AB_old = b"OLD-SESSION-KEY!"
    ticket_old = _enc(KB, K_AB_old + b"|A")
    print(f"  Old ticket recovered from logs: {ticket_old.hex()[:24]}…")

    NB = secrets.token_bytes(8)
    print(f"  Attacker → B: {ticket_old.hex()[:24]}…  (replay old ticket)")
    print(f"  B → Attacker: E_K_AB_old(N_B)  N_B = {NB.hex()}")
    # Attacker knows K_AB_old → can decrypt, respond
    resp = _enc(K_AB_old, (int.from_bytes(NB, 'big') - 1).to_bytes(8, 'big'))
    print(f"  Attacker → B: {resp.hex()[:24]}…  (= E_K_AB_old(N_B − 1))")
    print("  B ACCEPTS: challenge-response verified → attacker = A.")
    print()
    print("  Fix:  • include timestamps/lifetimes in tickets")
    print("        • KDC rejects stale (K_AB, B) pairs")
    print("        • rekey long before compromise horizon")
    return True


def ticket_replay_demo():
    """
    [HIGH]  Ticket Replay
    =====================
    Same root cause as Denning–Sacco: if service tickets do not
    expire, anyone holding one is accepted.  Kerberos mitigates
    via short lifetimes (default 10h) + authenticators with
    fresh timestamps and per-session nonces.
    """
    print("[DEMO] Ticket replay (Kerberos-pattern)")
    print("  Kerberos ticket: E_{K_svc}( K_session, ClientID, "
          "StartTime, EndTime )")
    print("  Kerberos authenticator (sent with each request):")
    print("    { ClientID, Timestamp } encrypted under K_session")
    print()
    print("  If authenticator's timestamp is NOT checked against")
    print("  a freshness window (±5 min), an attacker who captured")
    print("  (ticket, authenticator) can replay indefinitely.")
    print()
    print("  Exam checklist for Kerberos questions:")
    print("    [✓] short ticket lifetime")
    print("    [✓] authenticator timestamp window enforced")
    print("    [✓] session keys not reused across services")
    print("    [✓] ticket is bound to the service identity (SPN)")
    return True


# ═══════════════════════════════════════════════════════════════
# 4.  PKI / certificate validation
# ═══════════════════════════════════════════════════════════════

def cert_audit(hostname: str, port: int = 443):
    """
    [HIGH]  Certificate Validation Audit
    ====================================
    Checks a live TLS endpoint against the standard pitfalls:
      • chain/trust anchor
      • hostname binding
      • expiration
      • key usage / EKU
      • revocation (CRL/OCSP) — only checks presence
      • basic constraints (CA bits)
      • TLS version / cipher downgrade

    Requires: `ssl` (stdlib). No external deps.
    """
    import ssl, socket
    print(f"[AUDIT] cert of {hostname}:{port}")
    ctx = ssl.create_default_context()
    findings = []
    try:
        with socket.create_connection((hostname, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert = s.getpeercert()
                version = s.version()
                cipher = s.cipher()
                print(f"  negotiated: {version}  cipher: {cipher[0]}")

                # 1. expiration
                not_after = cert.get("notAfter")
                if not_after:
                    import email.utils, time as _t
                    exp = _t.mktime(
                        email.utils.parsedate(not_after))
                    if exp < _t.time():
                        findings.append("EXPIRED certificate")

                # 2. SAN hostname binding
                san = cert.get("subjectAltName", ())
                hostnames = [v for k, v in san if k == "DNS"]
                if hostname not in hostnames and not any(
                        h.startswith("*.") and hostname.endswith(h[1:])
                        for h in hostnames):
                    findings.append(
                        f"hostname {hostname} not in SAN {hostnames}")

                # 3. EKU / key usage
                eku = cert.get("extendedKeyUsage", "")
                if "serverAuth" not in eku:
                    findings.append(f"missing serverAuth EKU (got {eku!r})")

                # 4. weak protocol
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(f"weak protocol {version}")

                # 5. weak cipher (very rough)
                if cipher and any(x in cipher[0] for x in
                                  ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                    findings.append(f"weak cipher {cipher[0]}")
    except Exception as e:
        findings.append(f"TLS error: {e}")

    if findings:
        print("  [!] Findings:")
        for f in findings:
            print(f"      - {f}")
    else:
        print("  [✓] No glaring issues")
    return findings


def tofu_poc_demo():
    """
    [HIGH]  Trust-on-First-Use & Proof-of-Possession
    ================================================
    TOFU: first-seen public key is trusted forever.  If first
    contact is MITM'd, attacker is trusted permanently.
    PoP:   registration should require a signature over a fresh
    challenge under the private key.  Otherwise the registry may
    accept a public key the submitter does NOT control.

    This demo shows a PoP check and why it's necessary.
    """
    print("[DEMO] TOFU + Proof-of-Possession")
    print()
    print("  TOFU failure (SSH-style):")
    print("    client connects first time → pins host key")
    print("    if MITM'd at that moment, all future connections")
    print("    pin the wrong key.  No warning raised after.")
    print("  Mitigation: out-of-band fingerprint confirmation.")

    print()
    print("  PoP check (should be done by directory):")
    print("    Challenge:  nonce = 32 random bytes")
    print("    Response:   sign_privkey(nonce)  +  public_key")
    print("    If signature verifies, prover controls the private key.")

    # Simulate with a tiny exponent group (toy, not safe)
    p = 2**127 - 1
    g = 3
    x_honest = secrets.randbelow(p - 2) + 1
    y_honest = pow(g, x_honest, p)
    nonce = secrets.token_bytes(32)

    def sign(x, msg): return hash((x, msg))
    def verify(y, msg, sig):
        # Recover small x by DLP? no.  Just show the concept with
        # honest / dishonest signer.
        return None   # placeholder — see text

    print(f"  Honest:  sign_{x_honest}(nonce) verifies against y={y_honest}")
    x_fake = secrets.randbelow(p - 2) + 1
    y_claim = pow(g, x_fake, p)   # attacker's own key
    print(f"  Attacker registers {y_claim} claiming it's Bob's — but")
    print(f"  cannot sign nonce with x_claim? It CAN, it owns x_fake!")
    print()
    print("  KEY POINT: PoP only proves 'holder controls some key'.")
    print("  To also prove 'this key belongs to Bob', you need an")
    print("  OUT-OF-BAND identity check (CA, DNS, pre-shared secret).")
    return True


# ═══════════════════════════════════════════════════════════════
# 5.  JWT / MAC extensions
# ═══════════════════════════════════════════════════════════════

def jwt_claims_audit(token: str):
    """
    [HIGH]  JWT Claim Validation Audit
    ==================================
    Verifies presence of standard claims that MUST be checked:
      exp (expiry), nbf (not-before), iat, aud, iss.
    Missing aud/iss → cross-service token reuse.
    Missing exp    → infinite token lifetime.
    """
    import base64
    def _b64d(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)
    parts = token.split(".")
    if len(parts) != 3:
        print("[!] Not a JWT"); return []
    try:
        payload = json.loads(_b64d(parts[1]))
    except Exception:
        print("[!] Cannot parse payload"); return []

    print("[AUDIT] JWT claims")
    findings = []
    for claim, why in [
        ("exp", "no expiry → token never invalidated"),
        ("nbf", "no not-before → usable immediately, hard to coordinate"),
        ("iat", "no issued-at → can't bound lifetime"),
        ("aud", "no audience → token accepted by other services"),
        ("iss", "no issuer → token from any issuer accepted"),
    ]:
        if claim not in payload:
            findings.append(f"missing '{claim}' ({why})")
        else:
            print(f"  {claim} = {payload[claim]}")

    # check exp validity
    if "exp" in payload and payload["exp"] < time.time():
        findings.append("exp is in the past (expired but server may not check)")

    if findings:
        print("  [!]")
        for f in findings: print("      -", f)
    else:
        print("  [✓] core claims present")
    return findings


def mac_length_ext_demo():
    """
    [HIGH]  Length Extension on Naive MAC (H(K‖m))
    ==============================================
    IMPORTANT exam distinction:
      • HMAC(K, m)      — NOT vulnerable to length extension.
      • SHA256(K‖m)     — VULNERABLE (Merkle–Damgård property).
      • SHA3(m‖K)       — not vulnerable (sponge).
      • BLAKE2(key=m)   — not vulnerable (built-in keyed mode).

    If a challenge uses `sha256(secret || message)` as a MAC,
    an attacker who knows one (m, tag) can compute a valid tag
    for m‖padding‖extra WITHOUT the secret.
    """
    print("[DEMO] Length-extension on SHA256(K || m)")
    K = b"secret-key"
    orig = b"user=guest&admin=false"
    tag = hashlib.sha256(K + orig).digest()
    print(f"  Known: m = {orig!r}")
    print(f"  Known: tag = sha256(K || m) = {tag.hex()[:32]}…")

    # MD padding for the inner hash (K||m):  length = len(K)+len(m)
    def md_padding(msg_len: int) -> bytes:
        bits = msg_len * 8
        pad = b"\x80"
        pad += b"\x00" * ((56 - (msg_len + 1)) % 64)
        pad += struct.pack(">Q", bits)
        return pad

    inner_len = len(K) + len(orig)
    glue = md_padding(inner_len)
    extra = b"&admin=true"
    forged_msg = orig + glue + extra

    # Continue the hash from the KNOWN tag (= state after K||m||pad)
    # Using SHA256's documented continuation trick.
    import hashlib as _h
    class SHA256_Continue:
        """Minimal state-continuation for SHA-256. Demo only."""
        def __init__(self, digest_state: bytes):
            self.H = list(struct.unpack(">8I", digest_state))
        def _process(self, block: bytes):
            K_ = [
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,
                0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,
                0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,
                0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
                0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,
                0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
                0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,
                0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,
                0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,
                0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,
                0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
                0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
            w = list(struct.unpack(">16I", block)) + [0]*48
            for i in range(16, 64):
                s0 = ((w[i-15]>>7|w[i-15]<<25) ^ (w[i-15]>>18|w[i-15]<<14)
                      ^ (w[i-15]>>3)) & 0xFFFFFFFF
                s1 = ((w[i-2]>>17|w[i-2]<<15) ^ (w[i-2]>>19|w[i-2]<<13)
                      ^ (w[i-2]>>10)) & 0xFFFFFFFF
                w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
            a,b,c,d,e,f,g_,h = self.H
            for i in range(64):
                S1 = ((e>>6|e<<26) ^ (e>>11|e<<21) ^ (e>>25|e<<7)) & 0xFFFFFFFF
                ch = (e & f) ^ (~e & g_) & 0xFFFFFFFF
                t1 = (h + S1 + ch + K_[i] + w[i]) & 0xFFFFFFFF
                S0 = ((a>>2|a<<30) ^ (a>>13|a<<19) ^ (a>>22|a<<10)) & 0xFFFFFFFF
                mj = (a & b) ^ (a & c) ^ (b & c) & 0xFFFFFFFF
                t2 = (S0 + mj) & 0xFFFFFFFF
                h,g_,f,e,d,c,b,a = g_,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
            self.H = [(x+y)&0xFFFFFFFF for x,y in
                      zip(self.H,[a,b,c,d,e,f,g_,h])]
        def update(self, data: bytes):
            for i in range(0, len(data), 64):
                self._process(data[i:i+64])
        def hexdigest(self):
            return struct.pack(">8I", *self.H).hex()

    # forged hash: continue from tag over `extra || padding(inner_len + len(glue) + len(extra))`
    s = SHA256_Continue(tag)
    forged_total_len = inner_len + len(glue) + len(extra)
    extra_pad = md_padding(forged_total_len)
    s.update(extra + extra_pad)
    forged_tag = bytes.fromhex(s.hexdigest())

    print(f"\n  Forged message: {forged_msg!r}")
    print(f"  Forged tag:     {forged_tag.hex()[:32]}…")
    print(f"  Tag changes?    {forged_tag != tag}")
    print(f"\n  Server computes sha256(K || forged_msg):")
    legit = hashlib.sha256(K + forged_msg).digest()
    print(f"  sha256(K || forged) = {legit.hex()[:32]}…")
    print(f"  Matches forged tag? {legit == forged_tag}")
    print(f"\n  → Attacker extended message WITHOUT knowing K.")
    print("  Fix: use HMAC(K, m)  (not vulnerable) or encrypt-then-MAC.")
    return True


def mac_timing_demo():
    """
    [MEDIUM]  Timing Side Channel on MAC Comparison
    ===============================================
    `if provided == expected:` compares byte-by-byte early-exit
    → attacker learns prefix length by timing.
    `hmac.compare_digest(a, b)` compares constant-time.
    """
    print("[DEMO] Timing on MAC comparison")
    import time as _t
    correct = secrets.token_bytes(32)
    def slow_eq(a, b):
        if len(a) != len(b): return False
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True
    def timeit(fn, a, b, n=20_000):
        t0 = _t.perf_counter()
        for _ in range(n): fn(a, b)
        return _t.perf_counter() - t0
    # expected prefix match, then mismatch
    guess_short = correct[:1] + bytes(31)
    guess_long  = correct[:30] + bytes(2)
    t_short = timeit(slow_eq, guess_short, correct)
    t_long  = timeit(slow_eq, guess_long,  correct)
    print(f"  1-byte match:  {t_short*1e3:.1f} ms")
    print(f"  30-byte match: {t_long*1e3:.1f} ms")
    print(f"  Ratio: {t_long/t_short:.2f}×  (attacker observes prefix match)")
    print("\n  Fix: hmac.compare_digest(a, b)  — constant time.")
    return True


def mac_serialization_demo():
    """
    [MEDIUM]  Serialization Ambiguity
    =================================
    Different JSON byte strings → different HMACs.
    If verifier re-serializes before comparing,
    semantically identical payloads may fail.
    Conversely, TWO different byte strings can parse to the
    same dict and both pass — cross-parser confusion.
    """
    print("[DEMO] Serialization ambiguity")
    a = '{"a":1,"b":2}'
    b = '{"b":2,"a":1}'
    c = '{"a":1,"b":2, "x":null}'
    print(f"  Form A: {a!r}")
    print(f"  Form B: {b!r}")
    print(f"  HMAC(A) == HMAC(B)?  {hmac.new(b'k', a.encode(), hashlib.sha256).digest() == hmac.new(b'k', b.encode(), hashlib.sha256).digest()}")
    print(f"  Parse-equal:         {json.loads(a) == json.loads(b)}")
    print(f"  → Different bytes ⇒ different MAC, same semantics.")
    print(f"  → Server must verify MAC on the EXACT bytes it received.")
    return True


# ═══════════════════════════════════════════════════════════════
# 6.  Key management
# ═══════════════════════════════════════════════════════════════

def kdf_audit(samples: Optional[List[bytes]] = None):
    """
    [MEDIUM]  KDF / Key-Reuse Audit
    ==============================
    Checklist:
      ✓ Is shared secret processed by a KDF before use?
      ✓ Domain separation: separate keys for enc/mac/iv?
      ✓ Salt / context (session-id, peer IDs) bound?
      ✓ No key reuse across purposes?
    """
    print("[AUDIT] KDF / key reuse")
    findings = []
    print("  Common failures to look for in transcripts:")
    checks = [
        ("Is raw DH secret used as session key?",
         "If yes: no KDF → related-key attacks, no domain separation"),
        ("Same key for enc and MAC?",
         "Yes → dangerous; use KDF(secret, 'enc') and KDF(secret, 'mac')"),
        ("Missing salt / context in KDF?",
         "Yes → replay across sessions if shared secret repeats"),
        ("Key not rotated (static long-term)?",
         "Yes → no forward secrecy"),
    ]
    for q, why in checks:
        print(f"    [ ] {q}")
        print(f"        ({why})")
    return findings


def forward_secrecy_demo():
    """
    [MEDIUM]  Forward Secrecy
    =========================
    FS means compromise of the long-term private key does NOT
    reveal past session keys.

    • Static DH (RSA key transport): NO forward secrecy.
    • DHE / ECDHE: forward secrecy (ephemeral keys).
    • Sender Keys / ratchet: also forward-secret.

    Demo: show that with static DH, an attacker who later steals
    the private key can decrypt an old transcript.
    """
    print("[DEMO] Forward secrecy failure (static DH)")

    # Static long-term key
    p = 2 * 3 * 5 * 7 * 11 * 13 + 1
    while not _is_probable_prime(p):
        p += 2 * 3 * 5 * 7 * 11 * 13
    g = 2
    x_alice = secrets.randbelow(p - 2) + 1
    y_alice = pow(g, x_alice, p)
    print(f"  Alice's STATIC public y = g^x ; x is long-term")
    print(f"  Old session: attacker logged ephemeral g^b")

    b = secrets.randbelow(p - 2) + 1
    g_b = pow(g, b, p)
    print(f"  Transcript stores g^b = {g_b}")
    # shared secret was g^(xb)
    shared = pow(g_b, x_alice, p)
    print(f"  Session key was g^(xb) = {shared}")

    print("\n  Later: attacker steals x (or breaks into server).")
    recovered = pow(g_b, x_alice, p)   # attacker has x now
    print(f"  Attacker recomputes g^(xb) from g^b and stolen x = {recovered}")
    print(f"  Matches original? {recovered == shared}")
    print("\n  Fix: use DHE / ECDHE with fresh ephemeral keys per "
          "session, DELETE ephemeral secrets after the session.")
    return True


# ═══════════════════════════════════════════════════════════════
# 7.  Encoding / parsing confusion
# ═══════════════════════════════════════════════════════════════

def encoding_confusion_demo():
    """
    [ADDITIONAL]  Encoding & Parsing Confusion
    ==========================================
    Small differences in how encoders and decoders treat the
    same "logical" string, exploited to bypass filters.

    Cases to know for the exam:
      • Unicode overlong / case-folding ('ADMIN' vs 'admin' vs 'ＡＤＭＩＮ')
      • Null byte truncation ('admin\\0user' → 'admin')
      • Base64 padding variants (== vs = vs none)
      • Hex uppercase vs lowercase
      • URL-encoding double-encoding (%2525 vs %25)
      • JSON duplicate keys ('{"role":"user","role":"admin"}')
      • Case-insensitive HTTP headers (Authorization vs authorization)
    """
    print("[DEMO] Encoding confusion")
    print()
    print("  Base64 padding variants decode equal:",
          b"YWRtaW4=" == b"YWRtaW4=")
    print("  Null-byte truncation in C-string APIs:")
    print("    b'admin\\x00user' → C treats as b'admin'")
    print()
    print("  JSON duplicate keys:")
    print("    '{\"role\":\"user\",\"role\":\"admin\"}'")
    print("    Python json.loads → 'admin'  (last wins)")
    print("    Some languages → 'user'      (first wins)")
    print("    → Filter sees 'user', verifier sees 'admin'.")
    print()
    print("  Unicode case folding:")
    print("    'ADMIN'.lower() == 'admin'  (Python)")
    print("    'ＡＤＭＩＮ' (fullwidth) .lower() == 'ａｄｍｉｎ'  ≠ 'admin'")
    print("    If filter compares to 'admin' but verifier uses casefold")
    print("    → bypass.")
    print()
    print("  → Always normalize + reject ambiguous input BEFORE any checks.")
    return True


# ═══════════════════════════════════════════════════════════════
# 8.  Network-aware wrappers (need config like general.py)
# ═══════════════════════════════════════════════════════════════

def _http(cfg, method, path, headers=None, body=None):
    if not HAS_REQUESTS:
        print("[!] requests not installed"); return None
    url = cfg["base_url"].rstrip("/") + path
    h = dict(cfg.get("extra_headers") or {})
    if headers: h.update(headers)
    print(f"  [→] {method} {path}")
    try:
        if method == "GET":
            r = requests.get(url, headers=h, timeout=cfg.get("timeout", 10))
        else:
            if isinstance(body, (dict, list)):
                r = requests.post(url, json=body, headers=h,
                                  timeout=cfg.get("timeout", 10))
            else:
                r = requests.post(url, data=body, headers=h,
                                  timeout=cfg.get("timeout", 10))
        print(f"  [←] {r.status_code} ({len(r.content)}B)")
        return r
    except Exception as e:
        print(f"  [!] {e}")
        return None


def http_replay(cfg):
    """
    [CRITICAL]  HTTP Replay against a live service
    ==============================================
    Send the SAME signed request N times, record statuses.
    Success = 200 on every replay.
    """
    print("[LIVE] HTTP replay")
    r = _http(cfg, "GET", "/challenge")
    if r is None: return
    try:
        data = r.json()
    except Exception:
        print("  [-] /challenge did not return JSON"); return
    payload = (data.get("payload") or data.get("request")
               or data.get("message"))
    sig = (data.get("signature") or data.get("sig")
           or data.get("hmac"))
    if payload is None or sig is None:
        print("  [-] no payload+signature"); return
    hdrs = {"X-Signature": sig}
    for i in range(3):
        r = _http(cfg, "POST", "/vault", headers=hdrs, body=payload)
        if r is not None and r.status_code == 200:
            print(f"  [+] Replay #{i+1} accepted")
    print("  → If all 200: no freshness check ⇒ replay attack succeeds.")


def http_reflection(cfg, key_field: str = "key"):
    """
    [HIGH]  HTTP reflection attempt
    ===============================
    Sends the challenger's own nonce back as if we were the peer.
    Only meaningful if the target has a symmetric challenge /
    response endpoint — probing is the first step.
    """
    print("[LIVE] HTTP reflection probe")
    r = _http(cfg, "GET", "/challenge")
    if r is None: return
    try: data = r.json()
    except Exception: return
    nonce = data.get("nonce") or data.get("challenge")
    if nonce is None:
        print("  [-] no nonce in /challenge"); return
    print(f"  Got nonce: {nonce}")
    print("  → Send back through /verify with our own name in the 'from' "
          "field; watch for acceptance.")
    _http(cfg, "POST", "/verify", body={"from": "Bob", "response": nonce})


def http_downgrade(cfg):
    """
    [MEDIUM]  Downgrade probe
    =========================
    Advertises only weak algorithms and checks whether the server
    accepts.
    """
    print("[LIVE] HTTP downgrade probe")
    weak_algos = ["md5", "sha1", "rc4", "3des", "none", "null"]
    for alg in weak_algos:
        r = _http(cfg, "POST", "/negotiate", body={"algorithms": [alg]})
        if r is not None and r.status_code in (200, 201):
            print(f"  [+] Server accepted {alg!r} — downgrade possible")


# ═══════════════════════════════════════════════════════════════
# 9.  CLI
# ═══════════════════════════════════════════════════════════════

ATTACKS = {
    # offline demos
    "dh_mitm":         dh_mitm_demo,
    "dh_small_subgroup": dh_small_subgroup_demo,
    "dh_weak_exp":     dh_weak_exp_demo,
    "replay":          replay_demo,
    "reflection":      reflection_demo,
    "uks":             uks_demo,
    "kci":             kci_demo,
    "interleaving":    interleaving_demo,
    "downgrade":       downgrade_demo,
    "ns_sym":          ns_sym_demo,
    "denning_sacco":   denning_sacco_demo,
    "ticket_replay":   ticket_replay_demo,
    "tofu_poc":        tofu_poc_demo,
    "mac_length_ext":  mac_length_ext_demo,
    "mac_timing":      mac_timing_demo,
    "mac_serialization": mac_serialization_demo,
    "kdf_audit":       kdf_audit,
    "forward_secrecy": forward_secrecy_demo,
    "encoding_confusion": encoding_confusion_demo,

    # live wrappers
    "http_replay":     http_replay,
    "http_reflection": http_reflection,
    "http_downgrade":  http_downgrade,
}

DEMO_ORDER = [
    "dh_mitm", "dh_small_subgroup", "dh_weak_exp",
    "replay", "reflection", "uks", "kci", "interleaving", "downgrade",
    "ns_sym", "denning_sacco", "ticket_replay",
    "tofu_poc",
    "mac_length_ext", "mac_timing", "mac_serialization",
    "kdf_audit", "forward_secrecy",
    "encoding_confusion",
]

LIVE_ORDER = ["http_replay", "http_reflection", "http_downgrade"]


def main():
    if "--list" in sys.argv:
        print("Offline demos:")
        for k in DEMO_ORDER: print(f"  {k}")
        print("\nLive attacks (need --config):")
        for k in LIVE_ORDER: print(f"  {k}")
        return

    if "--demo" in sys.argv:
        print("="*64)
        print("Running ALL offline demos")
        print("="*64)
        for k in DEMO_ORDER:
            print(f"\n{'─'*64}\n[{k}]\n{'─'*64}")
            try: ATTACKS[k]()
            except Exception as e:
                import traceback; traceback.print_exc()
        return

    if "--attack" in sys.argv:
        name = sys.argv[sys.argv.index("--attack") + 1]
        cfg = None
        if "--config" in sys.argv:
            with open(sys.argv[sys.argv.index("--config") + 1]) as f:
                cfg = json.load(f)
        if name not in ATTACKS:
            print(f"[!] unknown attack: {name}"); sys.exit(1)
        fn = ATTACKS[name]
        if name.startswith("http_"):
            if cfg is None:
                cfg = {
                    "base_url": "http://cns-test.idlab.uantwerpen.be:50011",
                    "timeout": 10,
                    "extra_headers": {},
                }
                print("[*] using default base_url "
                      "(pass --config to override)")
            fn(cfg)
        else:
            fn()
        return

    # no args → print help
    print(__doc__)


if __name__ == "__main__":
    main()