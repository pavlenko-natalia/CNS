# SHA-3 / Keccak: Theory, Every Attack Case, Ready-to-Use Scripts

SHA-3 is the **only modern hash function structurally immune to length extension**. It was designed after SHA-1/SHA-2 (and after MD5/SHA-1 were broken) specifically to avoid MD's structural weaknesses. It's the winner of the NIST competition (2012, Keccak by Daemen & Rijmen — the **same designers as AES**), standardized as FIPS 202 in 2015.

**For your session**: SHA-3 is **not in the explicit task list**, but it's referenced in the slides as the "safe alternative" to SHA-2, and it may appear in HMAC constructions or truncated-hash tasks. The key point to know: **length extension does NOT work**, unlike MD5/SHA-1/SHA-2.

This section covers:
- Theory + sponge construction
- Why length extension is impossible (with a demonstration)
- All practical attacks (which are the same as SHA-2, **minus length extension**)
- Ready-to-run scripts for each case

---

## 1. What is SHA-3 (the family)

### 1.1 Parameters

| Variant | Output | Capacity `c` | Rate `r` | Rounds | Hex length |
|---|---|---|---|---|---|
| **SHA3-224** | 224 bits | 448 | 1152 | 24 | 56 |
| **SHA3-256** | 256 bits | 512 | 1088 | 24 | **64** |
| **SHA3-384** | 384 bits | 768 | 832 | 24 | 96 |
| **SHA3-512** | 512 bits | 1024 | 576 | 24 | **128** |
| **SHAKE128** | arbitrary | **256** | 1344 | 24 | any |
| **SHAKE256** | arbitrary | **512** | 1088 | 24 | any |

**Constraint:** `r + c = 1600` bits (always, for all variants).

**Key observation:** SHAKE has **lower capacity** than SHA3 — SHAKE128 with `c = 256` gives only **128-bit collision security**, regardless of output length. That's why it's "SHAKE128" and not "SHAKE256".

### 1.2 Output lengths in hex

| Variant | Hex chars |
|---|---|
| SHA3-224 | 56 |
| SHA3-256 | **64** |
| SHA3-384 | 96 |
| SHA3-512 | **128** |
| SHAKE128 (if 32B output) | 64 |
| SHAKE256 (if 32B output) | 64 |

**Ambiguity:** SHA3-256 and SHAKE128/SHAKE256 with 32-byte output all produce 64 hex chars. Distinguish by **context** (does the code use `sha3_256` or `shake_128`?), not by output.

### 1.3 The sponge construction (fundamentally different from MD)

**Merkle–Damgård** (MD5, SHA-1, SHA-2):
```
h_0 = IV
h_i = compress(h_{i-1}, M_i)
H(M) = h_n
```
**Output = internal state → length extension possible.**

**Sponge** (SHA-3):
```
State = 1600 bits (r + c)
Initial: all zeros

ABSORBING:
for each r-bit block M_i:
    state[0:r] ^= M_i          # XOR into rate portion
    state = Keccak_f(state)    # permute entire 1600-bit state

SQUEEZING (for n-bit output):
Z = state[0:r]                 # first r bits of rate
while |Z| < n:
    state = Keccak_f(state)    # more permutation
    Z += state[0:r]
return Z[:n]
```

**Critical property:** the **capacity `c` bits of state are never output**. An attacker who sees `n` output bits knows at most `n` bits of the 1600-bit state — the `c`-bit capacity remains **unknown**. Without knowing the full state, you **cannot** continue the sponge.

### 1.4 Keccak-f permutation (24 rounds)

Each round applies 5 steps (**θ, ρ, π, χ, ι**):

| Step | Type | What it does |
|---|---|---|
| **θ (theta)** | Substitution | XOR each bit with two column parities |
| **ρ (rho)** | Permutation | Rotate each lane by a fixed amount |
| **π (pi)** | Permutation | Permute the 5×5 matrix of lanes |
| **χ (chi)** | Substitution | Non-linear row-wise transformation (the ONLY nonlinear step) |
| **ι (iota)** | XOR with round constant | Break symmetry |

**State layout:** 5 × 5 × 64-bit lanes = 1600 bits.

### 1.5 Standard Python usage

```python
import hashlib

# SHA-3 family
hashlib.sha3_256(b"hello").hexdigest()
hashlib.sha3_512(b"hello").hexdigest()
hashlib.sha3_224(b"hello").hexdigest()
hashlib.sha3_384(b"hello").hexdigest()

# SHAKE (extendable output)
hashlib.shake_128(b"hello").hexdigest(32)    # 32-byte output
hashlib.shake_256(b"hello").hexdigest(64)    # 64-byte output
```

### 1.6 Keccak vs SHA-3 — a subtle but important difference

**Original Keccak** (pre-2015 submissions) used **padding `0x01`**.
**NIST SHA-3** (FIPS 202) uses **padding `0x06`** (multi-rate padding).

This means **Keccak("hello") ≠ SHA3("hello")** — different output! If a challenge says "Keccak", it might use the original (pre-NIST) variant.

```python
# Original Keccak-256 (used in Ethereum before "SHA3" was standardized)
# Install: pip install pysha3
import sha3
sha3.keccak_256(b"hello").hexdigest()    # Different from hashlib.sha3_256

# NIST SHA-3
import hashlib
hashlib.sha3_256(b"hello").hexdigest()
```

**Ethereum uses Keccak-256, not SHA3-256!** So `eth_utils.keccak()` ≠ `hashlib.sha3_256()`. Same algorithm, different padding.

---

## 2. Security status

| Attack | SHA-256 | SHA3-256 | Comment |
|---|---|---|---|
| **Preimage** | 2²⁵⁶ | **2²⁵⁶** | Same |
| **Collision** | 2¹²⁸ | **2¹²⁸** | Same |
| **Length extension** | ✅ **works** | ❌ **impossible** | **Structural** |
| **Dictionary** | ✅ works | ✅ works | (same) |
| **Brute force** | ✅ works | ✅ works | (same) |
| **Truncated birthday** | ✅ works | ✅ works | (same) |
| **HMAC weak key** | ✅ works | ✅ works | (same) |

**SHA-3's advantage over SHA-2:** **length extension is structurally impossible**.

**No practical attacks on full SHA-3 exist.** Like SHA-2, all practical attacks are on **usage**, not the algorithm.

---

## 3. Attack taxonomy

| # | Attack | Applies to SHA-3 | Session relevance |
|---|---|---|---|
| 1 | **Dictionary / brute force** | ✅ Same as SHA-2 | Possible |
| 2 | **Length extension** | ❌ **Impossible** | — |
| 3 | **HMAC-SHA3 weak key** | ✅ Same as SHA-2 | Possible |
| 4 | **Truncated birthday** | ✅ Same as SHA-2 | Possible |
| 5 | **SHAKE XOF misuse** | ✅ Special to SHA-3 | Rare |
| 6 | **Reduced-round Keccak** | ✅ CTF-only | Rare |
| 7 | **Detection / identification** | — | Always useful |
| 8 | **Full break** | ❌ None | — |

---

## 4. Case 1 — Why length extension is impossible (with demo)

### 4.1 The structural argument

To perform length extension on a hash `H(M)`:
- You need the **full internal state** after absorbing `M`.
- For MD5/SHA-1/SHA-2: the output **IS** the internal state (all bits are in the hash).
- For SHA-3: the output is only `n` bits, but the state is 1600 bits. The `c` capacity bits are **never output**.
- You cannot continue the sponge without knowing **all 1600 bits** — and you only have `n ≤ 512`.

**For SHA3-256:** you see 256 bits of state, you're missing `1600 - 256 = 1344` bits. **No way to continue.**

**For SHAKE256 with 64-byte output:** you see 512 bits, missing 1088 bits. Still impossible.

### 4.2 Demonstration script (length extension fails)

```python
#!/usr/bin/env python3
"""Demonstrate that length extension does NOT work on SHA-3."""
import hashlib

def try_length_extension_sha3(secret: bytes, msg: bytes, append: bytes):
    """
    Try to forge SHA3(secret || msg || padding || append)
    WITHOUT knowing secret. This should FAIL on SHA-3.
    """
    # Real hash
    orig_hash = hashlib.sha3_256(secret + msg).digest()

    # Attacker's attempt: pretend they know state and continue
    # Compute the padding that would have been used
    def sha3_padding(n):
        # SHA-3 padding: 0x06 + zeros + 0x80 at block boundary
        # (multi-rate padding for NIST SHA-3)
        block = 136  # SHA3-256 rate in bytes = 136
        pad = b"\x06"
        pad += b"\x00" * ((block - (n + 1) % block) % block)
        pad += b"\x80"
        return pad

    # Attacker's fake state = orig_hash (32 bytes, way too short)
    # SHA-3 state is 200 bytes (1600 bits), and output is only 32 bytes
    # So attacker is missing 168 bytes of state
    print(f"[*] SHA-3 state size:  200 bytes (1600 bits)")
    print(f"[*] SHA-3-256 output:   32 bytes (256 bits)")
    print(f"[*] Attacker is missing: {200 - 32} bytes of state")
    print(f"[*] Cannot continue the sponge — length extension IMPOSSIBLE")

    # For contrast: MD5 works because output = state
    orig_md5 = hashlib.md5(secret + msg).digest()
    print(f"\n[*] MD5 state size:    16 bytes")
    print(f"[*] MD5 output:        16 bytes")
    print(f"[*] Attacker has:      16 bytes = full state")
    print(f"[*] MD5 length extension WORKS")


# Prove it
secret = b"SECRET_KEY_12345"
msg = b"user=guest"
append = b"&role=admin"

print("=== SHA-3 (fails) ===")
try_length_extension_sha3(secret, msg, append)

# Actual try:
new_msg = msg + b"\x06" + b"\x00" * 10 + append   # attacker's guess
try:
    # We can't compute SHA3(secret || new_msg) without secret
    # because we don't know full state
    pass
except Exception as e:
    print(f"Cannot compute: {e}")
```

### 4.3 When it matters

**If server uses `SHA3(secret || msg)` as MAC:**
- **No length extension** — good for the server.
- **But still vulnerable to other attacks**: weak secret → dictionary; JSON canonicalization; truncation birthday.

**If server uses `SHA256(secret || msg)` as MAC:**
- **Length extension works** — attacker forges auth.
- This is why MD5/SHA-1/SHA-2 length extension appears in CTF.

**If server uses `SHA3(secret || msg)` as MAC** — it's still **bad practice** (HMAC-SHA3 is correct), but **at least length extension is off the table**.

---

## 5. Case 2 — Dictionary / brute force (same as SHA-2)

### Full script (`crack_sha3_wordlist.py`)

```python
#!/usr/bin/env python3
"""SHA-3 dictionary/brute force attack.
Usage:
    python crack_sha3_wordlist.py <hash> [wordlist] [--algo sha3_256]
"""
import hashlib
import argparse
import string
import itertools

ALGOS = {
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "keccak_256": None,   # needs pysha3
}

def get_hasher(algo: str):
    if algo == "keccak_256":
        try:
            import sha3
            return sha3.keccak_256
        except ImportError:
            raise ImportError("pip install pysha3")
    return ALGOS[algo]

def crack_wordlist(target: str, wordlist: str, algo: str) -> str | None:
    hasher = get_hasher(algo)
    target = target.lower().strip()
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if pw and hasher(pw).hexdigest() == target:
                return pw.decode(errors="replace")
    return None

def crack_brute(target: str, charset: str, min_len: int, max_len: int,
                 algo: str) -> str | None:
    hasher = get_hasher(algo)
    target = target.lower().strip()
    for length in range(min_len, max_len + 1):
        for tup in itertools.product(charset, repeat=length):
            pw = "".join(tup)
            if hasher(pw.encode()).hexdigest() == target:
                return pw
    return None

CHARSETS = {
    "lower": string.ascii_lowercase, "upper": string.ascii_uppercase,
    "alpha": string.ascii_letters, "digit": string.digits,
    "alnum": string.ascii_letters + string.digits,
    "hex": "0123456789abcdef", "print": string.printable[:95],
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("hash")
    ap.add_argument("--wordlist", default="rockyou.txt")
    ap.add_argument("--algo", default="sha3_256", choices=ALGOS.keys())
    ap.add_argument("--brute", action="store_true")
    ap.add_argument("--charset", default="alnum", choices=CHARSETS.keys())
    ap.add_argument("--max", type=int, default=6)
    args = ap.parse_args()

    if args.brute:
        pw = crack_brute(args.hash, CHARSETS[args.charset], 1, args.max, args.algo)
    else:
        pw = crack_wordlist(args.hash, args.wordlist, args.algo)

    print(f"[+] Found: {pw}" if pw else "[!] Not found")
```

### Performance

SHA-3 is **~2× slower** than SHA-256 in Python (Keccak-f is 24 rounds of permutation).

| Hash | Speed (Python) |
|---|---|
| MD5 | ~10⁶ H/s |
| SHA-256 | ~10⁶ H/s |
| SHA3-256 | ~5 × 10⁵ H/s |

**rockyou.txt** with SHA3-256: ~45–60 s in Python.

---

## 6. Case 3 — HMAC-SHA3 (correct construction)

### Description

HMAC-SHA3 is the **correct** way to authenticate with SHA-3:
```
HMAC(K, M) = SHA3((K ⊕ opad) || SHA3((K ⊕ ipad) || M))
```

**Safe from length extension** — not because SHA-3 needs it (it doesn't), but because HMAC's two-level structure adds defense in depth.

### Full script (`hmac_sha3_toolkit.py`)

```python
#!/usr/bin/env python3
"""HMAC-SHA3 compute / verify / crack."""
import hmac, hashlib, argparse

def hmac_sha3(key: bytes, msg: bytes, algo: str = "sha3_256") -> bytes:
    hasher = getattr(hashlib, algo)
    return hmac.new(key, msg, hasher).digest()

def verify_hmac_sha3(key: bytes, msg: bytes, tag: bytes, algo: str = "sha3_256") -> bool:
    expected = hmac_sha3(key, msg, algo)
    return hmac.compare_digest(expected, tag)

def crack_hmac_sha3(msg: bytes, target_sig: bytes, wordlist: str,
                     algo: str = "sha3_256") -> bytes | None:
    """Recover weak HMAC key from wordlist."""
    hasher = getattr(hashlib, algo)
    with open(wordlist, "rb") as f:
        for line in f:
            key = line.rstrip(b"\r\n")
            if not key: continue
            if hmac.compare_digest(
                hmac.new(key, msg, hasher).digest(), target_sig
            ):
                return key
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--key")
    ap.add_argument("--msg")
    ap.add_argument("--algo", default="sha3_256")
    ap.add_argument("--crack", help="wordlist path to crack")
    ap.add_argument("--sig", help="target signature (hex) for cracking")
    args = ap.parse_args()

    if args.crack:
        if not args.msg or not args.sig:
            ap.error("--crack requires --msg and --sig")
        key = crack_hmac_sha3(
            bytes.fromhex(args.msg),
            bytes.fromhex(args.sig),
            args.crack, args.algo)
        print(f"[+] Key: {key!r}" if key else "[!] Not found")
    else:
        tag = hmac_sha3(bytes.fromhex(args.key), bytes.fromhex(args.msg), args.algo)
        print(f"[+] HMAC-{args.algo}: {tag.hex()}")
```

### When to use

- **HMAC-SHA3 in a challenge** — same attacks as HMAC-SHA256:
  - **Weak key** → wordlist.
  - **JSON canonicalization** → same as §8 of SHA-2.
  - **JWT with HS3xx** (rare — JWT doesn't standardize SHA-3 by default, but custom implementations may).
- **No length extension** — good.

---

## 7. Case 4 — Truncated SHA-3 birthday (same as SHA-2)

### Description

If server stores only first `N` bytes of SHA-3 → **birthday attack**, exactly as SHA-256.

### Full script (`sha3_birthday.py`)

```python
#!/usr/bin/env python3
"""Truncated SHA-3 birthday attack (same algorithm as SHA-256 version)."""
import hashlib, json, time, argparse

def canonicalize(payment: dict) -> bytes:
    return json.dumps(payment, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")

def fingerprint(payment: dict, trunc_bytes: int, algo: str = "sha3_256") -> bytes:
    hasher = getattr(hashlib, algo)
    return hasher(canonicalize(payment)).digest()[:trunc_bytes]

def find_collision(trunc_bytes: int, algo: str = "sha3_256",
                    max_tries: int = 1 << 30):
    """Birthday collision on truncated SHA-3."""
    print(f"[*] Finding {trunc_bytes*8}-bit collision in {algo}...")
    seen = {}
    t0 = time.time()
    for i in range(max_tries):
        ref = f"ref-{i:08x}"
        payment = {
            "reference": ref,
            "from_account": "SIM-ATTACKER",
            "to_account": "SIM-BOB",
            "amount": 10,
            "currency": "EUR",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        fp = fingerprint(payment, trunc_bytes, algo)
        if fp in seen and seen[fp] != payment:
            dt = time.time() - t0
            print(f"[+] Collision after {i+1} tries in {dt:.1f}s")
            print(f"    fingerprint: {fp.hex()}")
            return seen[fp], payment, fp
        seen[fp] = payment
        if i % 100000 == 0 and i > 0:
            print(f"    ... {i} tries ({time.time()-t0:.1f}s)")
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--bytes", type=int, default=4, help="truncation bytes")
    ap.add_argument("--algo", default="sha3_256")
    args = ap.parse_args()

    result = find_collision(args.bytes, args.algo)
    if result:
        a, b, fp = result
        print("\n=== Submit these two ===")
        print(json.dumps(a, sort_keys=True, separators=(",", ":")))
        print(json.dumps(b, sort_keys=True, separators=(",", ":")))
```

### When to use

- **Secure Bank 2** style — if server uses SHA-3 instead of SHA-256 for fingerprints.
- **Any truncated hash** challenge.
- **Same math as SHA-256** (birthday attack doesn't care which hash).

**Performance caveat:** SHA-3 is ~2× slower than SHA-256 in Python, so the birthday search takes **2× longer**.

---

## 8. Case 5 — SHAKE XOF misuse (SHA-3 specific)

### Description

**SHAKE128** and **SHAKE256** are **extendable output functions (XOF)** — they produce arbitrary-length output from the same input:
```python
hashlib.shake_128(b"seed").hexdigest(1000)   # 1000 hex chars = 500 bytes
hashlib.shake_256(b"seed").hexdigest(32)     # 32 hex chars = 16 bytes
```

**Misuse patterns:**

| Pattern | Vulnerability |
|---|---|
| **Same seed → same output prefix** | Two "keys" derived from same seed share a prefix |
| **SHAKE128 for KDF** | Only 128-bit collision security — insufficient for 256-bit keys |
| **SHAKE output used as AES key** | If seed weak, key recoverable via brute force |
| **Truncated SHAKE** | Birthday on truncated output |
| **SHAKE with fixed seed** | Deterministic → two-time pad |

### Full script (`shake_misuse.py`)

```python
#!/usr/bin/env python3
"""SHAKE XOF misuse attacks."""
import hashlib, os


def derive_keys(seed: bytes, n: int = 4) -> list[bytes]:
    """Derive n 32-byte keys from a seed (BAD: same prefix, different suffix)."""
    out = hashlib.shake_256(seed).digest(32 * n)
    return [out[i*32:(i+1)*32] for i in range(n)]


def crack_shake_seed(known_output: bytes, wordlist: str,
                      out_len: int = None) -> bytes | None:
    """
    If SHAKE output = SHAKE256(password), recover password from wordlist.
    known_output: first N bytes of SHAKE output.
    """
    out_len = out_len or len(known_output)
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw: continue
            if hashlib.shake_256(pw).digest(out_len) == known_output:
                return pw
    return None


def detect_short_seed_usage():
    """
    If server uses SHAKE128 (256-bit capacity) to derive a 256-bit key,
    effective security is 2^128 (not 2^256).
    """
    print("[!] SHAKE128 provides only 128-bit security")
    print("[!] SHAKE256 provides 256-bit security")
    print("[!] Use SHAKE256 for 256-bit keys")


def find_shake_collision(trunc_bytes: int = 4):
    """
    If SHAKE output is truncated, birthday attack works.
    (Same as truncated SHA-256, just slower.)
    """
    seen = {}
    for i in range(1 << 30):
        msg = os.urandom(8)
        fp = hashlib.shake_256(msg).digest(trunc_bytes)
        if fp in seen and seen[fp] != msg:
            return seen[fp], msg, fp
        seen[fp] = msg
    return None


if __name__ == "__main__":
    # Example: SHAKE-derived keys share prefix (bad)
    print("=== Key derivation misuse ===")
    keys = derive_keys(b"seed123", n=3)
    for i, k in enumerate(keys):
        print(f"Key {i}: {k.hex()[:32]}...")
    print("[!] All share the same first 32 bytes — insecure!")

    # Example: crack weak seed
    print("\n=== Brute force SHAKE seed ===")
    target = hashlib.shake_256(b"password123").digest(8)
    for pw in [b"password123", b"admin", b"letmein"]:
        if hashlib.shake_256(pw).digest(8) == target:
            print(f"[+] Seed: {pw}")
            break
```

### When to use

- **SHAKE in a challenge** — check if:
  - Output is truncated → birthday attack.
  - Seed is weak → brute force wordlist.
  - Same seed → same output → deterministic.
  - SHAKE128 used for 256-bit keys → security reduced.

---

## 9. Case 6 — Reduced-round Keccak (CTF-specific)

### Description

If a CTF uses **Keccak with fewer than 24 rounds** (e.g., Keccak-4, Keccak-8), it's **breakable with differential cryptanalysis**.

### Detection

Read the challenge code. If it says something like:
```python
def custom_keccak(data, rounds=4):
    ...
```

→ **reduced rounds** → attackable.

### Attack script (conceptual)

Reduced-round Keccak attacks exist in academic literature (Biryukov, Khovratovich, Nikolić 2008+). **Not practical to implement from scratch in a session** — but if a CTF provides a **known-output oracle**, you can:

1. **Differential fuzzing**: try many inputs, look for collisions.
2. **Use published reduced-round solvers** (e.g., `KeccakTools`).
3. **Brute force internal state** if only 1–2 rounds.

### Quick collision finder for reduced-round Keccak

```python
import hashlib

def reduced_keccak_demo():
    """If CTF provides reduced-round Keccak, look for collisions via fuzzing."""
    # This is illustrative — real attack needs differential analysis
    seen = {}
    for i in range(1 << 20):
        msg = i.to_bytes(4, "big")
        # Replace with actual reduced-round Keccak call
        h = hashlib.sha3_256(msg).digest()   # NOT reduced-round — just demo
        if h in seen and seen[h] != msg:
            print(f"[+] Collision: {seen[h].hex()} vs {msg.hex()}")
            return
        seen[h] = msg
    print("[*] No collision in 2^20 tries")


reduced_keccak_demo()
```

### When to use

- **Only if the challenge uses reduced-round Keccak.**
- **Standard 24-round Keccak is unbreakable** with this approach.
- **Not in your session tasks.**

---

## 10. Case 7 — Detection & identification

### Description

How to detect SHA-3 in a challenge:
- **64 hex chars** → SHA3-256 or SHAKE128/256 with 32-byte output.
- **128 hex chars** → SHA3-512 or SHAKE with 64-byte output.
- **Code uses `hashlib.sha3_256` / `sha3.sha3_256`** → SHA-3.
- **Code uses `sha3.keccak_256`** → **Keccak** (Ethereum variant, different from NIST SHA-3!).
- **Output is variable length** → **SHAKE**.

### Detection script

```python
def identify_hash(h: str) -> str:
    h = h.strip()
    n = len(h)
    if not all(c in "0123456789abcdef" for c in h.lower()):
        return "not hex"
    return {
        32:  "MD5 / MD4 / NTLM",
        40:  "SHA-1 / SHA-0 / RIPEMD-160",
        56:  "SHA-224 / SHA-512/224 / SHA3-224",
        64:  "SHA-256 / SHA-512/256 / SHA3-256 / SHAKE128(32B) / SHAKE256(32B)",
        96:  "SHA-384 / SHA3-384",
        128: "SHA-512 / SHA3-512 / SHAKE128(64B) / SHAKE256(64B)",
    }.get(n, f"unknown length {n}")


# Test vector: differentiate by known output
def distinguish_sha3_variants():
    """Use known input 'hello' to distinguish SHA-3 family."""
    import hashlib
    test = b"hello"
    print(f"SHA3-256:   {hashlib.sha3_256(test).hexdigest()}")
    print(f"SHA3-512:   {hashlib.sha3_512(test).hexdigest()}")
    print(f"SHAKE128:   {hashlib.shake_128(test).hexdigest(32)}")
    print(f"SHAKE256:   {hashlib.shake_256(test).hexdigest(32)}")
    try:
        import sha3
        print(f"Keccak-256: {sha3.keccak_256(test).hexdigest()}  ← Ethereum!")
    except ImportError:
        print("Keccak-256: (pip install pysha3 to check)")


distinguish_sha3_variants()
```

### When to use

- **Before cracking** — know which hash to use.
- **If code uses `sha3` library** → check if it's `keccak_256` (Ethereum) or `sha3_256` (NIST).

---

## 11. Case 8 — Full break? (Doesn't exist)

### Status

**No practical attacks on full 24-round SHA-3.**

- **Preimage**: 2²⁵⁶ (for SHA3-256) — infeasible.
- **Collision**: 2¹²⁸ — infeasible.
- **Distinguishing**: no practical distinguisher from random.
- **Side-channel**: cache timing exists on Keccak-f in some implementations, but **requires physical access / co-located VM**.

**If a challenge claims "break full SHA-3"**, it's either:
1. **Not actually SHA-3** (some custom hash).
2. **Reduced rounds**.
3. **Misuse** (dictionary / truncated / HMAC).
4. **Wrong padding** (Keccak vs SHA-3 mismatch — different output).

---

## 12. Keccak vs SHA-3 — the padding trap

### Description

**Critical difference:** Keccak (original) uses `0x01` padding, SHA-3 (NIST) uses `0x06`.

| Variant | Padding | Output for "hello" |
|---|---|---|
| SHA3-256 | `0x06` | `3338be69...` |
| Keccak-256 | `0x01` | `1c8aff95...` |

**Different outputs for same input!**

### Script to distinguish

```python
def detect_keccak_vs_sha3(known_hash: str, known_input: bytes) -> str:
    """Determine whether a 32-byte hash is SHA3-256 or Keccak-256."""
    import hashlib
    if hashlib.sha3_256(known_input).hexdigest() == known_hash.lower():
        return "SHA3-256 (NIST)"
    try:
        import sha3
        if sha3.keccak_256(known_input).hexdigest() == known_hash.lower():
            return "Keccak-256 (Ethereum)"
    except ImportError:
        pass
    return "unknown"

# Example
h = "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
print(detect_keccak_vs_sha3(h, b"hello"))    # SHA3-256
```

### When to use

- **Ethereum-related challenges** use Keccak-256.
- **Crypto challenges** typically use NIST SHA-3.
- **CTF with "keccak" in code** → likely `pysha3.keccak_256`.
- **Subtle source of "why doesn't my hash match?"**

---

## 13. Quick reference

| Situation | Attack | Script |
|---|---|---|
| Have `SHA3(password)` | Dictionary | §5 |
| Short pw | Brute force | §5 |
| `H(secret \|\| msg)` | **Length extension impossible** | §4 (demo) |
| HMAC-SHA3 weak key | Wordlist | §6 |
| Truncated SHA-3 | Birthday | §7 |
| SHAKE misuse | Seed brute / prefix leak | §8 |
| Reduced-round Keccak | Differential | §9 |
| Unknown hash | Identify length | §10 |
| Keccak vs SHA-3 mismatch | Padding check | §12 |

---

## 14. Mapping to session tasks

| Task | Uses SHA-3? | Attack |
|---|---|---|
| **Signed, Sealed** | ❌ HMAC-SHA256 | (SHA-2 §8) |
| **Secure Bank 2** | ❌ SHA-256 truncated | (SHA-2 §9) |
| **Token of Trust** | ❌ JWT HS256 | (SHA-2 §10) |
| **Security Cam** | ❌ MD5 | (MD5 §8) |
| **Noncense** | ❌ AES-CTR | (AES §12) |
| **Secure Bank** | ❌ Salsa20 | (Salsa20 §7) |
| **Better Hash** | ❌ Custom hash | (Better Hash section) |
| **Key standardisation** | ❌ DES | (DES §6) |
| **Replanting** | ❌ LCG | (PRG §5) |
| **Dutch Exclusivity** | ❌ XOR | (XOR §5) |
| **AES 2 demo** | ❌ AES | (AES §7) |

**No session task uses SHA-3.** The section is for completeness, defensive knowledge, and handling "surprise" challenges.

---

## 15. SHA-3 vs the rest — summary table

| Aspect | MD5 | SHA-1 | SHA-256 | **SHA3-256** | SHAKE256 |
|---|---|---|---|---|---|
| Output | 128 | 160 | 256 | 256 | any |
| Structure | MD | MD | MD | **Sponge** | **Sponge** |
| **Length extension** | ✅ | ✅ | ✅ | ❌ | ❌ |
| Collision | 2¹⁸ | 2⁶³ | 2¹²⁸ | 2¹²⁸ | 2¹²⁸ (if n ≤ 256) |
| Preimage | 2¹²⁸ | 2¹⁶⁰ | 2²⁵⁶ | 2²⁵⁶ | 2²⁵⁶ |
| Speed (Python) | fast | fast | fast | **~2× slower** | ~2× slower |
| NIST status | ❌ | ❌ | ✅ | ✅ | ✅ |
| Padding | 0x80 | 0x80 | 0x80 | **0x06** | **0x06** |
| Ethereum? | — | — | — | — | Keccak-256 (0x01) |

**Use SHA-3 when:**
- You want **length-extension immunity** (though HMAC fixes MD too).
- You want **defense in depth** (different structure from AES-based constructions).
- **Ethereum** uses **Keccak-256** (not NIST SHA-3).

**Use SHA-2 when:**
- Everywhere else — it's the default, faster, and just as secure.