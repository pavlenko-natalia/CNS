# SHA-1: Theory, Every Attack Case, Ready-to-Use Scripts

SHA-1 (Secure Hash Algorithm 1) is **the cautionary tale of hash functions**. Designed by NSA, standardized by NIST in 1995 as FIPS 180-1. It was supposed to be the successor to SHA-0, which had a flaw. But **SHA-1 inherited similar flaws** and was **completely broken by 2017**. It's the algorithm behind **LinkedIn 2012** (unsalted, 117 million passwords leaked) and still lingers in **legacy systems** — Git (until very recently), old TLS, some CMS/PKI.

It's **not in your session tasks** directly, but the attacks are identical to MD5, and legacy tasks may use it.

---

## 1. What is SHA-1 (formally)

### 1.1 Parameters

| Property | Value |
|---|---|
| Output size | **160 bits (20 bytes)** = **40 hex chars** |
| Block size | **512 bits (64 bytes)** |
| Word size | 32 bits |
| Rounds | **80** (4 stages × 20 rounds each) |
| Structure | **Merkle–Damgård** (like MD5) |
| Padding | `1` bit + zeros + **64-bit length** (mod 512) |
| Endianness | **Big-endian** (unlike MD5!) |

### 1.2 Internal state (5 words, not 4 like MD5)

```python
SHA1_IV = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
]
```

### 1.3 Standard Python usage

```python
import hashlib

h = hashlib.sha1(b"hello").hexdigest()
# 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'

h = hashlib.sha1(b"hello").digest()
# 20 bytes
```

### 1.4 Merkle–Damgård (critical for length extension)

Identical structure to MD5:
```
h_0 = IV
h_1 = compress(h_0, M_1)
...
h_n = compress(h_{n-1}, M_n) = SHA1(M)
```

**The output IS the state.** → **Length extension** works exactly as in MD5.

---

## 2. Security status — what's broken and what's not

| Attack | Difficulty (2024) | Practical? |
|---|---|---|
| **Preimage** | 2¹⁶⁰ | ❌ No |
| **Second preimage** | 2¹⁶⁰ | ❌ No |
| **Collision** | **2⁶³.1** (SHAttered 2017) — **~10⁶ GPU-hours** | ✅ **Yes** (with resources) |
| **Chosen-prefix collision** | **2⁶³.4** (Leurent–Peyrin 2020) | ✅ Yes (with resources) |
| **Length extension** | O(1) | ✅ **Trivial** |
| **Dictionary** | O(\|wordlist\|) | ✅ Yes (seconds) |
| **Brute force** | 2^(8 × length) | ✅ For short passwords |

**Summary:**
- **Collisions**: **practical** since 2017 — two PDFs with same SHA-1 exist (SHAttered).
- **Chosen-prefix collisions**: practical since 2020 — can forge a fake PGP key, fake CA cert, etc.
- **Preimage**: still 2¹⁶⁰ — **not broken**.

**NIST SP 800-131A:** SHA-1 **disallowed** for digital signatures since **2014**.

---

## 3. Attack taxonomy

| # | Attack | Use case | Input needed |
|---|---|---|---|
| 1 | **Dictionary / wordlist** | Password hash recovery | Hash + wordlist |
| 2 | **Brute force (short)** | Short password | Hash + charset |
| 3 | **Length extension** | MAC forgery (`H(secret \|\| msg)`) | Hash + msg + key length |
| 4 | **Collision (chosen-prefix)** | Forge signature / file | Two arbitrary prefixes |
| 5 | **HMAC-SHA1 weak key** | Signed cookie with weak key | HMAC + wordlist |
| 6 | **Timing attack** | Login bypass | Network access |
| 7 | **Truncated SHA-1** | Collision on truncated hash | Truncated hash (birthday) |
| 8 | **Unsalted batch cracking** | LinkedIn-style | Hash DB + wordlist |
| 9 | **Identification** | Unknown hash type | Hash length |

Cases 1–3 are the most likely to appear in a CTF.

---

## 4. Attack 1 — Dictionary / wordlist attack ⭐

### 4.1 Description

Given `target = SHA1(password)`, test each password from a wordlist.

### 4.2 Full script (`crack_sha1_wordlist.py`)

```python
#!/usr/bin/env python3
"""SHA-1 dictionary attack.
Usage:
    python crack_sha1_wordlist.py <hash> [wordlist]
    python crack_sha1_wordlist.py --file hashes.txt --wordlist rockyou.txt
"""
import hashlib
import argparse

def crack_single(target_hash: str, wordlist_path: str) -> str | None:
    target = target_hash.lower().strip()
    with open(wordlist_path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            if hashlib.sha1(pw).hexdigest() == target:
                return pw.decode(errors="replace")
    return None

def crack_many(target_hashes: list[str], wordlist_path: str) -> dict[str, str]:
    """Batch attack: check ALL hashes per password (efficient)."""
    targets = {h.lower().strip() for h in target_hashes}
    found = {}
    with open(wordlist_path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            h = hashlib.sha1(pw).hexdigest()
            if h in targets:
                found[h] = pw.decode(errors="replace")
                targets.discard(h)
                if not targets:
                    break
    return found


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?", help="SHA-1 hash to crack")
    ap.add_argument("--file", help="file with one hash per line")
    ap.add_argument("--wordlist", default="rockyou.txt")
    args = ap.parse_args()

    if args.file:
        hashes = [l.strip() for l in open(args.file) if l.strip()]
        results = crack_many(hashes, args.wordlist)
        for h, pw in results.items():
            print(f"{h}:{pw}")
        missing = set(hashes) - set(results)
        if missing:
            print(f"\n[!] Unbroken: {len(missing)}")
    elif args.hash:
        pw = crack_single(args.hash, args.wordlist)
        print(f"[+] Found: {pw}" if pw else "[!] Not found")
    else:
        ap.error("Provide hash or --file")
```

### 4.3 Performance

- **rockyou.txt** (14M): ~20–40 s in Python (SHA-1 is a bit slower than MD5).
- **GPU** (`hashcat -m 100`): ~10 billion/sec.

### 4.4 When to use

- **Any task with `SHA1(password)` stored.**
- **LinkedIn 2012-style scenario** (unsalted SHA-1).

---

## 5. Attack 2 — Brute force (short passwords)

### 5.1 Full script (`crack_sha1_brute.py`)

```python
#!/usr/bin/env python3
"""SHA-1 brute force.
Usage:
    python crack_sha1_brute.py <hash> --charset alnum --max 6
"""
import hashlib
import itertools
import string
import argparse

CHARSETS = {
    "lower":  string.ascii_lowercase,
    "upper":  string.ascii_uppercase,
    "alpha":  string.ascii_letters,
    "digit":  string.digits,
    "alnum":  string.ascii_letters + string.digits,
    "hex":    "0123456789abcdef",
    "print":  string.printable[:95],
}

def brute(target: str, charset: str, min_len: int, max_len: int):
    target = target.lower().strip()
    for length in range(min_len, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            pw = "".join(tup)
            if hashlib.sha1(pw.encode()).hexdigest() == target:
                return pw
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash")
    ap.add_argument("--charset", default="alnum", choices=CHARSETS.keys())
    ap.add_argument("--custom", help="custom charset")
    ap.add_argument("--min", type=int, default=1)
    ap.add_argument("--max", type=int, default=6)
    args = ap.parse_args()

    charset = args.custom or CHARSETS[args.charset]
    pw = brute(args.hash, charset, args.min, args.max)
    print(f"[+] Found: {pw}" if pw else "[!] Not found")
```

### 5.2 Feasibility (identical to MD5)

| Length | Charset | Python |
|---|---|---|
| 4 | alnum | seconds |
| 5 | alnum | minutes |
| 6 | alnum | hours |
| 7 | alnum | days–weeks |

**For longer:** `hashcat -m 100 -a 3 <hash> ?a?a?a?a?a?a`.

---

## 6. Attack 3 — Length extension ⭐ (critical)

### 6.1 Description

**Setup:** server uses **`MAC = SHA1(secret || message)`** (bad construction).
You know `message` and `MAC`, **not** `secret`.

**Attack:** Compute `SHA1(secret || message || padding || extension)` **without knowing the secret**.

**Exactly the same as MD5** — but with 5-word state, 80-round compression, and **big-endian** padding.

### 6.2 Full script (`sha1_length_extension.py`)

```python
#!/usr/bin/env python3
"""SHA-1 length extension attack.
Usage:
    python sha1_length_extension.py --hash <hex> --original "..." --append "..." --key-len 16
"""
import struct
import argparse
import hashlib

MASK = 0xFFFFFFFF

def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK


def sha1_compress(state: list[int], block: bytes) -> list[int]:
    """Process one 64-byte block. Returns new 5-word state."""
    # Message schedule: 80 words
    W = list(struct.unpack(">16I", block))
    for t in range(16, 80):
        W.append(rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1))

    a, b, c, d, e = state

    for t in range(80):
        if t < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif t < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (rotl(a, 5) + f + e + k + W[t]) & MASK
        e = d
        d = c
        c = rotl(b, 30)
        b = a
        a = temp

    return [
        (state[0] + a) & MASK,
        (state[1] + b) & MASK,
        (state[2] + c) & MASK,
        (state[3] + d) & MASK,
        (state[4] + e) & MASK,
    ]


def sha1_padding(msg_len: int) -> bytes:
    """SHA-1 padding for a message of msg_len bytes (big-endian length)."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", msg_len * 8)     # BIG-endian (unlike MD5!)
    return pad


def sha1_state_from_hash(h: bytes) -> list[int]:
    """Convert 20-byte digest to 5-word state (big-endian)."""
    return list(struct.unpack(">5I", h))


def sha1_state_to_hash(state: list[int]) -> bytes:
    return struct.pack(">5I", *state)


def sha1_length_extension(original_hash: bytes, original_msg: bytes,
                            append: bytes, key_len: int) -> tuple[bytes, bytes]:
    """
    Compute SHA1(key || original_msg || padding || append)
    given SHA1(key || original_msg) and len(key).
    Returns (new_message, new_hash).
    """
    state = sha1_state_from_hash(original_hash)

    # Step 1: padding used for the original message
    total_len = key_len + len(original_msg)
    padding = sha1_padding(total_len)

    # Step 2: glue bytes
    new_msg = original_msg + padding + append

    # Step 3: process the append (starting from known state)
    prior_len = total_len + len(padding)
    append_padded = append + sha1_padding(prior_len + len(append))

    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64]
        if len(block) < 64:
            block = block + b"\x00" * (64 - len(block))
        state = sha1_compress(state, block)

    return new_msg, sha1_state_to_hash(state)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hash", required=True)
    ap.add_argument("--original", required=True)
    ap.add_argument("--append", required=True)
    ap.add_argument("--key-len", type=int, required=True)
    args = ap.parse_args()

    orig_hash = bytes.fromhex(args.hash)
    orig_msg = args.original.encode()
    append = args.append.encode()

    new_msg, new_hash = sha1_length_extension(
        orig_hash, orig_msg, append, args.key_len)

    print(f"[+] New message (hex):  {new_msg.hex()}")
    print(f"[+] New message (repr): {new_msg!r}")
    print(f"[+] New hash:           {new_hash.hex()}")
```

### 6.3 Usage

```bash
python sha1_length_extension.py \
  --hash aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d \
  --original "user=guest" \
  --append "&role=admin" \
  --key-len 16
```

### 6.4 Validate against `hashpumpy`

```python
import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="aaf4...",
    old_msg="user=guest",
    append_data="&role=admin",
    key_len=16,
    hash_type="sha1",   # <-- important!
)
# Should match our implementation
```

### 6.5 Verification

```python
import hashlib

def verify_length_extension():
    secret = b"MY_SECRET_KEY"       # 13 bytes
    msg = b"user=guest&role=user"
    append = b"&role=admin"

    orig_hash = hashlib.sha1(secret + msg).digest()
    new_msg, new_hash = sha1_length_extension(
        orig_hash, msg, append, key_len=len(secret))

    # Verify: SHA1(secret || new_msg) == new_hash
    check = hashlib.sha1(secret + new_msg).digest()
    assert check == new_hash, "FAIL"
    print("[+] Length extension works!")

verify_length_extension()
```

### 6.6 When to use

- **Server uses `SHA1(secret || message)` as MAC** — anti-pattern.
- **Signed cookies** with `SHA1(secret || cookie)`.
- **API tokens** = `SHA1(secret || user_id)`.

**If HMAC-SHA1 is used**, length extension **does NOT work**.

### 6.7 Detection

```python
# BAD: vulnerable
sig = hashlib.sha1(SECRET + message).hexdigest()

# GOOD: HMAC
sig = hmac.new(SECRET, message, hashlib.sha1).hexdigest()
```

---

## 7. Attack 4 — Collision (chosen-prefix) ⚠️ **rare in CTF**

### 7.1 Description

Find **two different messages** with the **same SHA-1 hash**.

**Milestones:**
- **2005** — Wang et al.: theoretical 2⁶⁹ collision attack.
- **2017** — **SHAttered** (Google + CWI): **two colliding PDFs**, ~2⁶³ operations. Practical.
- **2020** — **Leurent–Peyrin**: **chosen-prefix collision** (SHA-1 is a Shambles) — can forge a fake PGP key.

### 7.2 Tools

- **`sha1coll`** (C) — collision for arbitrary prefix.
- **`hashclash`** — Stevens' toolchain (also MD5).
- **Pre-computed shattered PDFs** — available online.

### 7.3 Practical attack

**For CTF:** rarely feasible. Requires **hours of GPU compute** (or special software).

**For a session:** if a task **claims** SHA-1 collisions, it usually provides:
- **The two colliding files** (SHAttered PDFs), or
- **Reduced-round SHA-1** (broken with a custom tool).

### 7.4 Script (detect SHA-1 collision services — trivial)

```python
def is_sha1_collision_pair(file1: bytes, file2: bytes) -> bool:
    """True if file1 and file2 have the same SHA-1."""
    return hashlib.sha1(file1).digest() == hashlib.sha1(file2).digest()
```

**Real collision generation:** use pre-computed pairs or `sha1coll` (see §7.2).

### 7.5 When to use

- **Very rare in CTF.**
- If task says "find two inputs with same SHA-1" → may have pre-computed pair in the file.
- **Not** in your session tasks.

---

## 8. Attack 5 — HMAC-SHA1 (correct construction)

### 8.1 Description

**HMAC-SHA1** is **NOT vulnerable** to length extension:
```
HMAC(K, M) = SHA1((K⊕opad) || SHA1((K⊕ipad) || M))
```

**Collisions in SHA-1 don't directly break HMAC-SHA1**, because HMAC doesn't sign the raw message — it signs a **two-level** construction.

### 8.2 Script — compute / verify

```python
import hmac
import hashlib

def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha1).digest()

def verify_hmac_sha1(key: bytes, msg: bytes, tag: bytes) -> bool:
    expected = hmac.new(key, msg, hashlib.sha1).digest()
    return hmac.compare_digest(expected, tag)   # constant-time!
```

### 8.3 Attack — weak key (wordlist)

```python
import hmac, hashlib

def crack_hmac_sha1(msg: bytes, target_tag: bytes, wordlist: str) -> bytes | None:
    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key:
                continue
            if hmac.compare_digest(
                hmac.new(key, msg, hashlib.sha1).digest(), target_tag
            ):
                return key
    return None
```

### 8.4 When to use

- **Signed cookie uses HMAC-SHA1** → try weak-key wordlist.
- **Not** length extension.
- If code uses `hmac.new(..., hashlib.sha1)` → safe from length extension.

---

## 9. Attack 6 — Timing attack (rare)

### 9.1 Description

If server compares SHA-1 hashes with `==` (non-constant-time), timing leaks.

### 9.2 Detection

```python
# BAD
if computed_sha1 == stored_sha1:
    return True

# GOOD
import hmac
if hmac.compare_digest(computed_sha1, stored_sha1):
    return True
```

### 9.3 Script

Same as MD5 §10. **Rare in CTF**.

---

## 10. Attack 7 — Truncated SHA-1 (birthday)

### 10.1 Description

If the server **truncates** to first N bytes:
```python
stored = SHA1(password)[:8]     # first 4 bytes
```
Birthday attack: `2¹⁶` random inputs → collision.

### 10.2 Script

```python
import hashlib
import os

def find_truncated_collision(bits: int = 32) -> tuple[bytes, bytes, bytes]:
    """Find two inputs with same SHA1[0:bits//8]."""
    n_bytes = bits // 8
    seen = {}
    for _ in range(1 << 30):
        msg = os.urandom(8)
        h = hashlib.sha1(msg).digest()[:n_bytes]
        if h in seen and seen[h] != msg:
            return seen[h], msg, h
        seen[h] = msg
    return None

# 32-bit collision in ~2^16 = 65536 tries
a, b, h = find_truncated_collision(32)
print(f"[+] MD5[:4] = {h.hex()}")
print(f"    msg1 = {a.hex()}")
print(f"    msg2 = {b.hex()}")
```

### 10.3 When to use

- Task says "truncated", "short hash", "fingerprint".
- Rare for SHA-1 (more common for **Secure Bank 2** with SHA-256).

---

## 11. Attack 8 — LinkedIn 2012 style (unsalted batch cracking)

### 11.1 Description

**LinkedIn stored passwords as raw SHA-1** (no salt). This is the same batch attack as MD5 §12.

### 11.2 Script — batch crack file

```python
import hashlib

def crack_linkedin_style(leaked_file: str, wordlist: str) -> dict[str, str]:
    """
    leaked_file: 'user:sha1hash' lines.
    Returns {user: password}.
    """
    # Parse
    users_hashes = {}
    for line in open(leaked_file):
        if ":" not in line:
            continue
        user, h = line.strip().split(":", 1)
        users_hashes[user] = h.lower()

    target_hashes = set(users_hashes.values())
    print(f"[*] {len(target_hashes)} unique SHA-1 hashes")

    # Crack
    found = {}
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            h = hashlib.sha1(pw).hexdigest()
            if h in target_hashes:
                found[h] = pw.decode(errors="replace")
                target_hashes.discard(h)
                if not target_hashes:
                    break

    # Map
    result = {user: found[h] for user, h in users_hashes.items() if h in found}

    # Stats
    print(f"[+] Cracked {len(result)}/{len(users_hashes)} users")
    from collections import Counter
    pw_counts = Counter(result.values())
    shared = {pw: n for pw, n in pw_counts.items() if n > 1}
    print(f"[!] {len(shared)} passwords shared among users")
    return result
```

### 11.3 When to use

- **Password database** challenge.
- **LinkedIn-style** scenario.

---

## 12. Attack 9 — Identify SHA-1 from hash format

### 12.1 Description

**40 hex chars** → SHA-1 (or SHA-0, or RIPEMD-160).

### 12.2 Script

```python
def identify_hash(h: str) -> str:
    h = h.strip()
    n = len(h)
    is_hex = all(c in "0123456789abcdef" for c in h.lower())

    if not is_hex:
        if h.startswith("$2a$") or h.startswith("$2b$"):
            return "bcrypt"
        if h.startswith("$argon2"):
            return "argon2"
        if h.startswith("$6$"):
            return "sha512-crypt"
        return "unknown"

    if n == 32:   return "MD5 (or MD4, NTLM)"
    if n == 40:   return "SHA-1 (or SHA-0, RIPEMD-160)"
    if n == 56:   return "SHA-224"
    if n == 64:   return "SHA-256"
    if n == 96:   return "SHA-384"
    if n == 128:  return "SHA-512"
    return f"unknown (length {n})"

print(identify_hash("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"))   # SHA-1
```

### 12.3 When to use

- **Before** cracking — always.
- **40 hex chars** → likely SHA-1.

---

## 13. Attack 10 — HMAC with weak KDF

### 13.1 Description

If HMAC-SHA1 key is derived from a **password** via MD5/SHA1:
```python
key = hashlib.sha1(password).digest()    # 20 bytes → used as HMAC key
sig = hmac.new(key, msg, hashlib.sha1).hexdigest()
```

### 13.2 Script

```python
import hmac, hashlib

def crack_hmac_sha1_derived(msg: bytes, target_sig: str,
                             wordlist: str, derivation: str = "sha1") -> tuple[bytes, str] | None:
    """HMAC-SHA1 with key derived from password."""
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n")
        if not pw:
            continue

        if derivation == "raw":
            key = pw.encode().ljust(20, b"\x00")[:20]
        elif derivation == "sha1":
            key = hashlib.sha1(pw.encode()).digest()
        elif derivation == "md5":
            key = hashlib.md5(pw.encode()).digest()
        else:
            continue

        if hmac.compare_digest(
            hmac.new(key, msg, hashlib.sha1).hexdigest(), target_sig
        ):
            return key, pw
    return None
```

### 13.3 When to use

- Server derives HMAC key from password (common in CTF).
- Check code for **key derivation**.

---

## 14. Quick reference: "I see SHA-1 — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Have `SHA1(password)` | **Wordlist** | §4 |
| Wordlist fails, short pw | **Brute force** | §5 |
| `MAC = SHA1(secret \|\| msg)` | **Length extension** | §6 |
| Need collision | `sha1coll` / `hashclash` | §7 |
| HMAC-SHA1 signature | **Weak key wordlist** | §8 |
| Timing leak | **Timing** | §9 |
| Truncated SHA-1 | **Birthday** | §10 |
| Unsalted DB | **Batch crack** | §11 |
| Unknown hash | **Length = 40** | §12 |

---

## 15. Mapping to session tasks

| Task | Uses SHA-1? | Attack |
|---|---|---|
| **Security Cam** | ❌ (MD5) | — |
| **Noncense** | ❌ (AES-CTR) | — |
| **Secure Bank** | ❌ (Salsa20) | — |
| **Secure Bank 2** | ❌ (SHA-256 truncated) | Birthday |
| **Better Hash** | ❌ (custom) | Reverse |
| **Signed, Sealed** | ❌ (HMAC-SHA256) | JSON canonicalization |
| **Token of Trust** | ❌ (JWT, likely HS256) | alg:none / weak key |
| **Key standardisation** | ❌ (DES) | Prefix brute |
| **Replanting** | ❌ (LCG) | Seed brute |
| **Dutch Exclusivity** | ❌ (XOR) | Known key |
| **AES 2 demo** | ❌ (AES) | MITM |

**No explicit SHA-1 task in the session.** But SHA-1 is referenced in **slides as the LinkedIn 2012 example**, and the attacks are identical to MD5 — so it's good to have on hand for legacy tasks.

---

## 16. SHA-1 vs MD5 — key differences

| Aspect | MD5 | SHA-1 |
|---|---|---|
| Output | 128 bits (32 hex) | **160 bits (40 hex)** |
| Rounds | 64 | **80** |
| State words | 4 (32-bit) | **5 (32-bit)** |
| Endianness | Little | **Big** |
| Padding length field | 8 bytes LE | **8 bytes BE** |
| Speed (Python) | ~10⁶ H/s | ~0.6 × MD5 |
| Length extension | ✅ | ✅ **same attack, same code structure** |
| Collision practical? | **seconds** (2¹⁸) | **hours–days** (2⁶³) |
| NIST status | disallowed | disallowed |

**For length extension, the code is nearly identical** — main differences: 5-word state, big-endian padding, 80 rounds.

---

## 17. Ready-to-use `sha1_toolkit.py`

Options:

- **A)** Build `sha1_toolkit.py` — one file with all attacks:
  ```
  - crack_single, crack_many (dictionary)
  - brute (charset brute force)
  - sha1_length_extension (full)
  - crack_hmac_sha1 (weak key)
  - identify_hash (format)
  - find_truncated_collision (birthday)
  - crack_linkedin_style (batch)
  ```
  + CLI subcommands mirroring MD5 toolkit.
