# MD5: Theory, Every Attack Case, Ready-to-Use Scripts

MD5 is the **most misused hash function in history**. It's **broken** in every meaningful sense: collisions in seconds, preimage attacks feasible for short passwords, length extension for MAC constructions. Yet it persists in legacy protocols (RTSP Digest, HTTP Digest, old TLS, some CMS/PKI) — which is exactly why **Security Cam** and similar CTF tasks target it.

This section covers **all practical MD5 attacks** with copy-paste scripts you can run at the session.

---

## 1. What is MD5 (formally)

MD5 (Message Digest 5) was designed by **Ron Rivest** in 1991 as a successor to MD4. It produces a **128-bit (16-byte) hash**, typically written as **32 hex characters**.

### 1.1 Parameters

| Property | Value |
|---|---|
| Output size | **128 bits (16 bytes)** |
| Block size | **512 bits (64 bytes)** |
| Word size | 32 bits |
| Rounds | 4 (16 operations each = **64 total**) |
| Structure | **Merkle–Damgård** |
| Padding | `1` bit + zeros + 64-bit length (mod 512) |
| Little-endian | Yes (words are little-endian) |

### 1.2 Merkle–Damgård construction (critical for length extension)

```
M = M_1 || M_2 || ... || M_n     (each block 512 bits, with padding)

h_0 = IV (fixed)
h_1 = compress(h_0, M_1)
h_2 = compress(h_1, M_2)
...
h_n = compress(h_{n-1}, M_n) = MD5(M)
```

**Compression function:** `h_i = h_{i-1} + (process block M_i starting from h_{i-1})`.

**Critical property:** the **output IS the internal state** after processing the last block. There's **no finalization step** (unlike SHA-3's sponge). This enables **length extension**.

### 1.3 Standard Python usage

```python
import hashlib

h = hashlib.md5(b"hello").hexdigest()
# '5d41402abc4b2a76b9719d911017c592'

h = hashlib.md5(b"hello").digest()
# b']A@*\xbcK*v\xb9q\x9d\x91\x10\x17\xc5\x92'
```

### 1.4 The IV (needed for length extension)

```python
MD5_IV = [
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
]
```

---

## 2. Security status — what's broken and what's not

| Attack | Difficulty (2024) | Practical? |
|---|---|---|
| **Preimage** (find `x` for given `h`) | 2¹²⁸ | ❌ No |
| **Second preimage** (find `x' ≠ x` with `h(x') = h(x)`) | 2¹²³ | ❌ No |
| **Collision** (find any `x, y` with `h(x) = h(y)`) | **2¹⁸** (Wang et al. 2004) → **seconds** | ✅ **Yes** |
| **Chosen-prefix collision** | 2³⁹ → hours | ✅ Yes |
| **Length extension** | O(1) | ✅ **Yes** (trivial) |
| **Dictionary** (password from wordlist) | O(|wordlist|) | ✅ Yes (seconds) |
| **Brute force** (`≤ 8` chars) | 2^(8 × length) | ✅ For short passwords |
| **Rainbow tables** | Precomputed | ✅ For unsalted hashes |

**Summary:**
- **Preimage** on **full 128-bit space**: infeasible.
- **Preimage** on **short passwords**: feasible via dictionary/brute force.
- **Collision**: **trivial**.
- **Length extension**: **trivial**.

**NIST SP 800-131A (2019):** MD5 is **disallowed** for any security function.

---

## 3. Attack taxonomy

| # | Attack | Use case | Input needed |
|---|---|---|---|
| 1 | **Dictionary / wordlist** | Password hash recovery | Hash + wordlist |
| 2 | **Brute force (short)** | Short password | Hash + charset |
| 3 | **Rainbow table** | Mass recovery | Hash + precomputed table |
| 4 | **Length extension** | MAC forgery (`H(secret || msg)`) | Hash + original message + key length |
| 5 | **Collision (chosen-prefix)** | Two files with same hash | Two arbitrary prefixes |
| 6 | **Hash comparison timing** | Login bypass | Network access |
| 7 | **HMAC-MD5 misuse** | Signature forgery | Reuse signature (if MAC = H(K \|\| M)) |
| 8 | **RTSP/HTTP Digest (MD5)** | Authentication bypass | Network capture + wordlist |
| 9 | **Truncated MD5** | Collision on truncated hash | Truncated hash (birthday) |

Each has a full script below.

---

## 4. Attack 1 — Dictionary / wordlist attack (⭐ most common)

### 4.1 Description

Given `target = MD5(password)`, test each password from a wordlist.

### 4.2 Full script (`crack_md5_wordlist.py`)

```python
#!/usr/bin/env python3
"""MD5 dictionary attack. Usage:
    python crack_md5_wordlist.py <hash> [wordlist]
    python crack_md5_wordlist.py --file hashes.txt --wordlist rockyou.txt
"""
import hashlib
import sys
import argparse
from pathlib import Path

def crack_single(target_hash: str, wordlist_path: str) -> str | None:
    target = target_hash.lower().strip()
    with open(wordlist_path, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            if hashlib.md5(pw).hexdigest() == target:
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
            h = hashlib.md5(pw).hexdigest()
            if h in targets:
                found[h] = pw.decode(errors="replace")
                targets.discard(h)
                if not targets:
                    break
    return found


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash", nargs="?", help="MD5 hash to crack")
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
            print(f"\n[!] Unbroken: {len(missing)}", file=sys.stderr)
    elif args.hash:
        pw = crack_single(args.hash, args.wordlist)
        if pw:
            print(f"[+] Found: {pw}")
        else:
            print("[!] Not found")
    else:
        ap.error("Provide hash or --file")
```

### 4.3 Usage

```bash
# Single hash
python crack_md5_wordlist.py 5d41402abc4b2a76b9719d911017c592 rockyou.txt
# [+] Found: hello

# Batch
python crack_md5_wordlist.py --file hashes.txt --wordlist rockyou.txt
```

### 4.4 Performance

- **rockyou.txt** (14M passwords): ~15–30 s in Python on a laptop.
- With `hashlib` in `-O3` C: 5× faster.
- With GPU (`hashcat -m 0`): **billions/sec**.

### 4.5 When to use

- **Security Cam** (RTSP Digest → MD5-based).
- Any task with `MD5(password)` stored.
- **First thing to try** — cheap and often works.

---

## 5. Attack 2 — Brute force (short passwords)

### 5.1 Description

If dictionary fails, brute-force `≤ 6–8` character passwords in a charset.

### 5.2 Full script (`crack_md5_brute.py`)

```python
#!/usr/bin/env python3
"""MD5 brute force. Usage:
    python crack_md5_brute.py <hash> --charset alnum --max 6
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
    "print":  string.printable[:95],   # no whitespace
}

def brute(target: str, charset: str, max_len: int):
    target = target.lower().strip()
    for length in range(1, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            pw = "".join(tup)
            if hashlib.md5(pw.encode()).hexdigest() == target:
                return pw
    return None

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash")
    ap.add_argument("--charset", default="alnum", choices=CHARSETS.keys())
    ap.add_argument("--custom", help="custom charset string")
    ap.add_argument("--max", type=int, default=6)
    ap.add_argument("--min", type=int, default=1)
    args = ap.parse_args()

    charset = args.custom or CHARSETS[args.charset]
    pw = brute(args.hash, charset, args.max)
    if pw:
        print(f"[+] Found: {pw}")
    else:
        print("[!] Not found")
```

### 5.3 Feasibility

| Password length | Charset | Keyspace | Python (hours) |
|---|---|---|---|
| 4 | alnum (62) | 1.5 × 10⁷ | seconds |
| 5 | alnum (62) | 9.2 × 10⁸ | minutes |
| 6 | alnum (62) | 5.7 × 10¹⁰ | hours |
| 7 | alnum (62) | 3.5 × 10¹² | days–weeks |
| 8 | alnum (62) | 2.2 × 10¹⁴ | months |

**For longer passwords:** use **`hashcat -m 0 -a 3`** on GPU — 10⁹–10¹⁰ H/s.

### 5.4 When to use

- Dictionary failed + short passwords (`≤ 6` chars).
- **Common in CTF** (short random passwords).

---

## 6. Attack 3 — Length extension (⭐ critical for MAC misuse)

### 6.1 Description

**Setup:** server authenticates with **`MAC = MD5(secret || message)`** (wrong construction). You know `message` and `MAC`, but **not** `secret`.

**Attack:** Given `H(secret || message)`, you can compute:
```
H(secret || message || padding || attacker_extension)
```
**without knowing the secret.**

**Root cause:** Merkle–Damgård — the hash **IS** the internal state. If you know the hash of a message, you can start hashing from that state.

### 6.2 Full script (`md5_length_extension.py`)

```python
#!/usr/bin/env python3
"""MD5 length extension attack.
Usage:
    python md5_length_extension.py --original "message" --hash <hex> --append "&admin=1" --key-len 16
"""
import hashlib
import struct
import argparse

# MD5 constants
F_MASK = 0xFFFFFFFF

def _left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & F_MASK

def _md5_compress(state: list[int], block: bytes) -> list[int]:
    """Process one 64-byte block. Returns new state (a, b, c, d)."""
    # Constants (T[i] = floor(2^32 * abs(sin(i+1))))
    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ]
    S = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    ]

    a, b, c, d = state
    M = list(struct.unpack("<16I", block))

    for i in range(64):
        if i < 16:
            F = (b & c) | (~b & d)
            g = i
        elif i < 32:
            F = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            F = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            F = c ^ (b | ~d)
            g = (7 * i) % 16

        F = (F + a + K[i] + M[g]) & F_MASK
        a, d, c, b = d, c, b, (b + _left_rotate(F, S[i])) & F_MASK

    return [(state[0] + a) & F_MASK,
            (state[1] + b) & F_MASK,
            (state[2] + c) & F_MASK,
            (state[3] + d) & F_MASK]


def md5_padding(msg_len: int) -> bytes:
    """Compute the MD5 padding for a message of `msg_len` bytes."""
    pad = b"\x80"
    pad += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack("<Q", msg_len * 8)
    return pad


def md5_state_from_hash(h: bytes) -> list[int]:
    """Convert 16-byte digest to 4-word state (little-endian)."""
    return list(struct.unpack("<4I", h))


def md5_state_to_hash(state: list[int]) -> bytes:
    return struct.pack("<4I", *state)


def md5_length_extension(original_hash: bytes, original_msg: bytes,
                          append: bytes, key_len: int) -> tuple[bytes, bytes]:
    """
    Compute MD5(key || original_msg || padding || append)
    given MD5(key || original_msg) and len(key).

    Returns (new_message, new_hash).
    """
    state = md5_state_from_hash(original_hash)
    
    # Padding that was used for (key || original_msg)
    total_len = key_len + len(original_msg)
    padding = md5_padding(total_len)
    
    # The "glue" bytes: attacker's append, processed starting from
    # the known state. Any block-aligned position works — but the
    # canonical attack puts `append` right after `padding`.
    new_msg = original_msg + padding + append
    
    # Now we need to hash `append` starting from `state`,
    # but we must treat the state as if `total_len + len(padding)` bytes
    # have already been processed.
    # We can only process full blocks, so we pad `append` again.
    # The length used in the second padding must account for all prior bytes.
    prior_len = total_len + len(padding)
    
    # If `append` is not a multiple of 64, pad it
    append_padded = append + md5_padding(prior_len + len(append))
    
    # Process append_padded block by block, starting from `state`
    for i in range(0, len(append_padded), 64):
        block = append_padded[i:i+64]
        if len(block) < 64:
            block = block + b"\x00" * (64 - len(block))
        state = _md5_compress(state, block)
    
    return new_msg, md5_state_to_hash(state)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hash", required=True, help="Original hash (hex)")
    ap.add_argument("--original", required=True, help="Original message (string)")
    ap.add_argument("--append", required=True, help="Data to append (string)")
    ap.add_argument("--key-len", type=int, required=True, help="Secret key length")
    args = ap.parse_args()

    orig_hash = bytes.fromhex(args.hash)
    orig_msg = args.original.encode()
    append = args.append.encode()

    new_msg, new_hash = md5_length_extension(orig_hash, orig_msg, append, args.key_len)
    
    print(f"[+] New message (hex): {new_msg.hex()}")
    print(f"[+] New message (repr): {new_msg!r}")
    print(f"[+] New hash:          {new_hash.hex()}")
    print()
    print("[!] Submit `new_msg` with hash `new_hash` to the server.")
    print(f"[!] If server uses `MD5(key || message)`, this bypasses auth.")
```

### 6.3 Usage

```bash
# Original MAC: MD5(secret || "user=guest") = 3b8f...
python md5_length_extension.py \
  --hash 3b8f...abc \
  --original "user=guest" \
  --append "&role=admin" \
  --key-len 16
```

### 6.4 Validate against `hashpumpy`

```python
import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="3b8f...abc",
    old_msg="user=guest",
    append_data="&role=admin",
    key_len=16,
)
print(new_hash, new_msg)
# Should match our implementation
```

### 6.5 When to use

- **Server uses `H(secret || message)` as MAC** — the anti-pattern.
- **Signed cookies** with `MD5(secret || cookie)`.
- **API tokens** = `MD5(secret || user_id)`.

**If server uses `HMAC-MD5`**, this attack **does NOT work** — HMAC uses two hash calls with derived keys.

### 6.6 Detection

Look for:
```python
# BAD: length extension vulnerable
sig = hashlib.md5(SECRET + message).hexdigest()

# GOOD: HMAC
import hmac
sig = hmac.new(SECRET, message, hashlib.md5).hexdigest()
```

---

## 7. Attack 4 — Collision (chosen-prefix)

### 7.1 Description

Find **two different messages** with the **same MD5 hash**.

### 7.2 Methods

| Method | Cost | Tool |
|---|---|---|
| **Wang et al. (2004)** — arbitrary collision | ~2¹⁸ operations | Academic |
| **Stevens et al. (2007)** — chosen-prefix | ~2³⁹ | Academic |
| **Stevens et al. (2009)** — rogue CA cert | ~2⁴⁹ | Academic |
| **SHAttered-style** (MD5 version) | Fast | Tooling |

### 7.3 Tools

- **`fastcoll`** — collision generation for arbitrary prefixes (Stevens).
- **`hashclash`** — Stevens' full toolchain.
- **`md5coll`** — newer implementation.

### 7.4 Practical CTF use

Rare, but:
- **"Find two files with same MD5, one signed as user, one as admin"** — if a server signs files with MD5, you can swap them.
- **"Upload a benign file and an evil file with same MD5"** — bypass checks.

### 7.5 Script (using `hashclash`)

```bash
# Install hashclash first
git clone https://github.com/cr-marcstevens/hashclash
cd hashclash && ./build.sh

# Generate collision
./bin/md5_fastcoll -p prefix.bin -o out1.bin out2.bin
# out1.bin and out2.bin have the same MD5
```

**Note:** For chosen-prefix (Stevens 2009), use `cpc.sh` in the toolchain.

### 7.6 When to use

- **Rare in CTF** — but if there's a "MD5-based signature validation" challenge with file upload, consider it.
- **Not** in your session tasks.

---

## 8. Attack 5 — RTSP Digest authentication (⭐ **Security Cam**)

### 8.1 Description

**Security Cam** uses **RTSP Digest Authentication**, which is **MD5-based** per **RFC 2617**.

**Digest authentication formula:**
```
HA1 = MD5(username : realm : password)
HA2 = MD5(method : uri)
response = MD5(HA1 : nonce : HA2)
```

Server sends `WWW-Authenticate: Digest realm="...", nonce="...", ...`.
Client sends `Authorization: Digest username="user", realm="...", nonce="...", uri="...", response="...", ...`.

### 8.2 Full script for Security Cam

```python
#!/usr/bin/env python3
"""Security Cam solver: RTSP Digest auth with MD5 + wordlist."""
import hashlib
import sys

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def try_digest(user: str, realm: str, password: str,
               method: str, uri: str, nonce: str) -> str:
    ha1 = md5(f"{user}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{nonce}:{ha2}")

def crack_rtsp_digest(user: str, realm: str, nonce: str,
                       attempts: list[tuple[str, str, str]],
                       wordlist: str) -> str | None:
    """
    attempts: list of (method, uri, expected_response).
    Try each password in wordlist against ALL attempts.
    """
    # Precompute HA2 for each attempt
    ha2s = [md5(f"{m}:{u}") for m, u, _ in attempts]

    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n").decode(errors="ignore")
            if not pw:
                continue
            ha1 = md5(f"{user}:{realm}:{pw}")
            for ha2, (_, _, expected) in zip(ha2s, attempts):
                if md5(f"{ha1}:{nonce}:{ha2}") == expected:
                    return pw
    return None


# ===== Security Cam task data =====
USER = "user"
REALM = "PythonRTSP"
NONCE = "4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"

ATTEMPTS = [
    ("DESCRIBE", "rtsp://cns-test.idlab.uantwerpen.be:50002/video",
     "b3539154c5b784bba2c47a1a6c7c4ab0"),
    ("SETUP", "rtsp://cns-test.idlab.uantwerpen.be:50002/video/trackID=0",
     "083ae471a613399abb781f9e36111893"),
    ("PLAY", "rtsp://cns-test.idlab.uantwerpen.be:50002/video/",
     "be8c3203cdda65b8f6687bb134354562"),
]

if __name__ == "__main__":
    wordlist = sys.argv[1] if len(sys.argv) > 1 else "rockyou.txt"
    print(f"[*] Cracking with {wordlist}...")
    pw = crack_rtsp_digest(USER, REALM, NONCE, ATTEMPTS, wordlist)
    if pw:
        print(f"[+] PASSWORD FOUND: {pw}")
    else:
        print("[!] Not found in wordlist")
```

### 8.3 Full solve for Security Cam — connect and get the flag

Once you have the password, connect to the RTSP server and authenticate:

```python
#!/usr/bin/env python3
"""Connect to RTSP server with recovered password."""
import socket
import sys
import hashlib
import re

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

def build_digest_header(user, realm, password, method, uri, nonce) -> str:
    ha1 = md5(f"{user}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    response = md5(f"{ha1}:{nonce}:{ha2}")
    return (
        f'Digest username="{user}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}"'
    )

HOST, PORT = "cns-test.idlab.uantwerpen.be", 50002
USER = "user"
PASSWORD = "..."   # from cracking script
REALM  = "PythonRTSP"

# Step 1: DESCRIBE → get nonce
s = socket.create_connection((HOST, PORT), timeout=10)
uri = f"rtsp://{HOST}:{PORT}/video"
request = (
    f"DESCRIBE {uri} RTSP/1.0\r\n"
    f"CSeq: 1\r\n"
    f"User-Agent: python-rtsp\r\n"
    f"\r\n"
)
s.sendall(request.encode())

response = b""
while b"\r\n\r\n" not in response:
    response += s.recv(4096)
print(response.decode(errors="replace"))

# Parse nonce from WWW-Authenticate
m = re.search(rb'nonce="([^"]+)"', response)
if not m:
    print("[!] No nonce in response")
    sys.exit(1)
nonce = m.group(1).decode()
print(f"[+] Nonce: {nonce}")

# Step 2: DESCRIBE with auth
auth = build_digest_header(USER, REALM, PASSWORD, "DESCRIBE", uri, nonce)
request = (
    f"DESCRIBE {uri} RTSP/1.0\r\n"
    f"CSeq: 2\r\n"
    f"User-Agent: python-rtsp\r\n"
    f"Authorization: {auth}\r\n"
    f"\r\n"
)
s.sendall(request.encode())

response = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    response += chunk
    if b"cns{" in response:
        break
print(response.decode(errors="replace"))

# Step 3: SETUP, PLAY — repeat with same nonce
for method, track in [("SETUP", "trackID=0"), ("PLAY", "")]:
    uri2 = f"rtsp://{HOST}:{PORT}/video"
    if track:
        uri2 += "/" + track
    auth = build_digest_header(USER, REALM, PASSWORD, method, uri2, nonce)
    request = (
        f"{method} {uri2} RTSP/1.0\r\n"
        f"CSeq: 3\r\n"
        f"User-Agent: python-rtsp\r\n"
        f"Authorization: {auth}\r\n"
        f"\r\n"
    )
    s.sendall(request.encode())
    response = s.recv(65536)
    print(f"\n=== {method} ===\n{response.decode(errors='replace')}")

    if b"cns{" in response:
        idx = response.find(b"cns{")
        end = response.find(b"}", idx)
        print(f"\n[+] FLAG: {response[idx:end+1].decode()}")
        break
```

### 8.4 When to use

- **Security Cam** — exactly this.
- Any **RTSP / HTTP Digest** challenge.
- The `rockyou.txt` wordlist **will** contain the password (common in CTF).

---

## 9. Attack 6 — HMAC-MD5 (correct construction)

### 9.1 Description

**HMAC-MD5** is **NOT vulnerable to length extension** (unlike `MD5(secret || msg)`). The construction:
```
HMAC(K, M) = MD5((K ⊕ opad) || MD5((K ⊕ ipad) || M))
```

This is secure **as long as MD5 is collision-resistant for the specific attack**. Collisions in MD5 don't directly break HMAC-MD5 in practice (they require chosen-prefix, not key-related).

### 9.2 Script — compute/verify HMAC-MD5

```python
import hmac
import hashlib

def hmac_md5(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.md5).digest()

# Verify (constant-time!)
def verify_hmac_md5(key: bytes, msg: bytes, tag: bytes) -> bool:
    expected = hmac.new(key, msg, hashlib.md5).digest()
    return hmac.compare_digest(expected, tag)
```

### 9.3 Attack — HMAC-MD5 collision-based

**Rare in practice** — attacks require chosen-prefix collisions in the **key-prefixed inner hash**, which is much harder than plain MD5 collisions.

### 9.4 Attack — weak key

If the HMAC key is weak (short, dictionary word):
```python
import hmac, hashlib

def crack_hmac_md5(msg: bytes, target_tag: bytes, wordlist: str) -> bytes | None:
    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key:
                continue
            if hmac.compare_digest(
                hmac.new(key, msg, hashlib.md5).digest(),
                target_tag,
            ):
                return key
    return None
```

### 9.5 When to use

- **Signed cookie uses HMAC-MD5** — try weak-key wordlist.
- **NOT** length extension.
- If signature looks like `HMAC-MD5` (`hmac.new` in code) → no length extension.

---

## 10. Attack 7 — Hash comparison timing (login bypass)

### 10.1 Description

If the server compares hashes with **`==`** (non-constant-time), you can measure timing to recover the hash byte-by-byte.

**Python bug:**
```python
if computed_md5 == stored_md5:   # VULNERABLE
    return True
```

**Fix:**
```python
import hmac
if hmac.compare_digest(computed_md5, stored_md5):
    return True
```

### 10.2 Script — timing attack

```python
import time
import requests

def timing_attack_login(url: str, username: str,
                         known_prefix: str = "") -> str:
    """Recover MD5 hash byte-by-byte via timing."""
    hex_chars = "0123456789abcdef"
    recovered = known_prefix

    while len(recovered) < 32:
        timings = {}
        for c in hex_chars:
            trial = recovered + c
            times = []
            for _ in range(20):   # statistical
                t0 = time.perf_counter()
                requests.post(url, data={"user": username, "hash": trial})
                times.append(time.perf_counter() - t0)
            timings[c] = sum(times) / len(times)

        best = max(timings, key=timings.get)
        recovered += best
        print(f"[+] Recovered: {recovered}")

    return recovered
```

### 10.3 When to use

- **Very rare** in CTF (most servers use constant-time).
- **Only** if you suspect timing leak.

---

## 11. Attack 8 — Truncated MD5 (birthday)

### 11.1 Description

If the server **truncates** the hash (e.g., stores only first 4 bytes):
```
stored = MD5(password)[:8]      # 4 bytes = 8 hex chars
```
Birthday attack: `2¹⁶` random inputs → collision.

### 11.2 Script — truncated collision

```python
import hashlib
import os

def find_truncated_collision(bits: int = 32) -> tuple[bytes, bytes, bytes]:
    """Find two inputs with same MD5[0:bits//8]."""
    seen = {}
    for _ in range(1 << 30):   # up to 2^30 tries
        msg = os.urandom(8)
        h = hashlib.md5(msg).digest()[:bits//8]
        if h in seen and seen[h] != msg:
            return seen[h], msg, h
        seen[h] = msg
    return None

# Example: 32-bit collision in ~2^16 = 65536 tries
a, b, h = find_truncated_collision(32)
print(f"[+] Collision! MD5[:4] = {h.hex()}")
print(f"    msg1 = {a.hex()}")
print(f"    msg2 = {b.hex()}")
```

### 11.3 When to use

- **Rare in CTF** — but if the task says "fingerprint", "truncated", "short hash".
- **Secure Bank 2** uses truncated **SHA-256**, but the **same birthday principle** applies (see AES section).

---

## 12. Attack 9 — MD5 in password storage (no salt)

### 12.1 Description

Classic LinkedIn 2012 scenario: passwords stored as `MD5(password)`, **no salt**.
- Same password → same hash.
- Rainbow tables work.
- One wordlist attack cracks **all** matching passwords.

### 12.2 Script — batch cracking

```python
import hashlib

def crack_unsalted_md5_file(hash_file: str, wordlist: str) -> dict[str, str]:
    """Crack a file of `user:hash` lines using unsalted MD5."""
    # Parse
    users_hashes = {}
    for line in open(hash_file):
        if ":" not in line:
            continue
        user, h = line.strip().split(":", 1)
        users_hashes[user] = h.lower()

    target_hashes = set(users_hashes.values())
    print(f"[*] {len(target_hashes)} unique hashes to crack")

    # Crack
    found = {}
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            h = hashlib.md5(pw).hexdigest()
            if h in target_hashes:
                found[h] = pw.decode(errors="replace")
                target_hashes.discard(h)
                if not target_hashes:
                    break

    # Map back
    result = {}
    for user, h in users_hashes.items():
        if h in found:
            result[user] = found[h]

    # Stats
    print(f"[+] Cracked {len(result)}/{len(users_hashes)} users")
    dup = sum(1 for h in users_hashes.values() if list(users_hashes.values()).count(h) > 1)
    print(f"[!] {dup} users share passwords with someone else")
    return result
```

### 12.3 When to use

- **Password database** challenge.
- **LinkedIn-style** scenario.
- Any **unsalted MD5** storage.

---

## 13. Attack 10 — Detecting MD5 from hash format

### 13.1 Description

If you have an unknown hash, how do you know it's MD5?

### 13.2 Detection script

```python
def identify_hash(h: str) -> str:
    """Guess hash type by length and format."""
    h = h.strip()
    n = len(h)
    is_hex = all(c in "0123456789abcdef" for c in h.lower())

    if not is_hex:
        if h.startswith("$2a$") or h.startswith("$2b$"):
            return "bcrypt"
        if h.startswith("$argon2"):
            return "argon2"
        if h.startswith("$pbkdf2"):
            return "pbkdf2"
        if h.startswith("$6$"):
            return "sha512-crypt"
        if h.startswith("$5$"):
            return "sha256-crypt"
        return "unknown"

    if n == 32:   return "MD5 (or MD4, NTLM)"
    if n == 40:   return "SHA-1"
    if n == 56:   return "SHA-224"
    if n == 64:   return "SHA-256"
    if n == 96:   return "SHA-384"
    if n == 128:  return "SHA-512"
    return f"unknown (length {n})"

print(identify_hash("5d41402abc4b2a76b9719d911017c592"))   # MD5
```

### 13.3 When to use

- **Before** cracking — know what you're cracking.
- **Hash length 32** → MD5 (or NTLM, or MD4 — same length).

---

## 14. Attack 11 — MD5 in "Better Hash" — not MD5

**Note:** The **Better Hash** challenge uses a **custom hash**, not MD5. The attack is **reversing** the custom round function (see previous section). **Don't waste time on MD5 there.**

---

## 15. Quick reference: "I see MD5 — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Have `MD5(password)` | **Wordlist** | §4 |
| Wordlist fails, short pw | **Brute force** | §5 |
| `MAC = MD5(secret \|\| msg)` | **Length extension** | §6 |
| Need collision | **fastcoll / hashclash** | §7 |
| RTSP/HTTP Digest | **Wordlist + Digest formula** | §8 |
| HMAC-MD5 signature | **Weak key wordlist** | §9 |
| Timing leak | **Timing attack** | §10 |
| Truncated MD5 | **Birthday** | §11 |
| Unsalted DB | **Batch crack** | §12 |
| Unknown hash | **Identify length** | §13 |

---

## 16. Mapping to session tasks

| Task | Uses MD5? | Attack |
|---|---|---|
| **Security Cam** | ✅ **YES** (RTSP Digest) | §8 (wordlist + Digest) |
| **Noncense** | ❌ (AES-CTR) | — |
| **Secure Bank** | ❌ (Salsa20) | — |
| **Secure Bank 2** | ❌ (SHA-256 truncated) | Birthday (different primitive) |
| **Better Hash** | ❌ (custom hash) | Reverse |
| **Signed, Sealed** | ❌ (HMAC-SHA256) | JSON canonicalization |
| **Token of Trust** | ❌ (JWT) | alg:none / weak key |
| **Key standardisation** | ❌ (DES) | Prefix brute |
| **Replanting** | ❌ (LCG) | Seed brute |
| **Dutch Exclusivity** | ❌ (XOR) | Known key |
| **AES 2 demo** | ❌ (AES) | MITM |

**Only Security Cam uses MD5.** The attack is §8.

---

## 17. Ready-to-use `md5_toolkit.py`

If you want a single self-contained file, here's the structure:

```python
#!/usr/bin/env python3
"""
MD5 toolkit — all attacks in one file.
Usage:
    python md5_toolkit.py crack       --hash <hex> [--wordlist rockyou.txt]
    python md5_toolkit.py brute       --hash <hex> [--charset alnum] [--max 6]
    python md5_toolkit.py length-ext  --hash <hex> --original "..." --append "..." --key-len 16
    python md5_toolkit.py rtsp        --user user --realm X --nonce Y --attempts attempts.json --wordlist rockyou.txt
    python md5_toolkit.py identify    --hash <hex>
"""
import hashlib, hmac, itertools, struct, string, argparse, json, sys

# --- included from sections above ---
# (all functions from §4–§13)
```

**Want me to build the complete `md5_toolkit.py`?** It would consolidate:
- `crack_single`, `crack_many` (dictionary)
- `brute` (charset brute force)
- `md5_length_extension` (full implementation)
- `crack_rtsp_digest` (Security Cam)
- `crack_hmac_md5` (weak key)
- `identify_hash` (format detection)
- `find_truncated_collision` (birthday)
- CLI with subcommands
