# ChaCha20: Theory, All Cases, Scripts
#
# ChaCha20 is the modern successor to Salsa20, also by Daniel J. Bernstein (2008). It's the stream cipher behind **TLS 1.3**, **WireGuard**, **SSH**, **Signal**, and **ChaCha20-Poly1305**. Unlike Salsa20, it has **better diffusion**, faster on modern CPUs, and is standardized in **RFC 8439**.
#
# Like Salsa20, ChaCha20 is **cryptographically strong by design** — every practical attack targets **misuse** (nonce reuse, malleability, library confusion, counter overflow). This section covers all of those.
#
# ---
#
# ## 1. What is ChaCha20 (formally)
#
# ChaCha20 is an **ARX-based stream cipher**. State = **4×4 matrix of 32-bit words** (64 bytes total).
#
# ### 1.1 Initial state layout (IETF / RFC 8439)
#
# ```
# [ C0  C1  C2  C3 ]     ← constants "expand 32-byte k"
# [ K0  K1  K2  K3 ]     ← key words
# [ K4  K5  K6  K7 ]
# [ P0  N0  N1  N2 ]     ← 32-bit counter + 96-bit nonce
# ```
#
# Where:
# - `C0..C3` = `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574` (ASCII `"expand 32-byte k"`)
# - `K0..K7` = key parsed as 8 little-endian 32-bit words (256-bit key = 32 bytes)
# - `P0` = block counter (**32 bits** — starts at 0 or 1)
# - `N0..N2` = nonce (96 bits = 12 bytes)
#
# ### 1.2 Original variant (Bernstein 2008)
#
# ```
# [ C0  C1  C2  C3 ]
# [ K0  K1  K2  K3 ]
# [ K4  K5  K6  K7 ]
# [ P0  P1  N0  N1 ]     ← 64-bit counter + 64-bit nonce
# ```
#
# **Critical difference from IETF:**
# - IETF (RFC 8439, used in TLS 1.3): 96-bit nonce + 32-bit counter
# - Original (Bernstein, used in some older libraries): 64-bit nonce + 64-bit counter
#
# **Always check which variant your library uses** — nonce length tells you:
# - 8-byte nonce → original (64/64)
# - 12-byte nonce → IETF (32/96)
# - 24-byte nonce → XChaCha20 (192/32)
#
# ### 1.3 Quarter round `QR()` — in-place, different from Salsa20
#
# ChaCha20's `QR()` updates **in-place**, in a specific order:

def QR(x: list, a: int, b: int, c: int, d: int):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;  x[d] ^= x[a];  x[d] = ROTL(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;  x[b] ^= x[c];  x[b] = ROTL(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;  x[d] ^= x[a];  x[d] = ROTL(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;  x[b] ^= x[c];  x[b] = ROTL(x[b], 7)

# Where `ROTL(x, n)` is 32-bit left rotation.
#
# **Difference from Salsa20:**
# - Salsa20 rotates by `7, 9, 13, 18`; ChaCha20 rotates by `16, 12, 8, 7`.
# - Salsa20's QR computes `y0..y3` as **new** values (non-overwriting order); ChaCha20 **overwrites in place**.

### 1.4 Round function — column + diagonal

# Each **double round** = **columnround** + **diagonalround**:

def double_round(x: list):
    # Column rounds
    QR(x, 0, 4,  8, 12)
    QR(x, 1, 5,  9, 13)
    QR(x, 2, 6, 10, 14)
    QR(x, 3, 7, 11, 15)
    # Diagonal rounds
    QR(x, 0, 5, 10, 15)
    QR(x, 1, 6, 11, 12)
    QR(x, 2, 7,  8, 13)
    QR(x, 3, 4,  9, 14)

# **10 double rounds** = 20 rounds total (hence "ChaCha20").

### 1.5 Full keystream generation

def chacha20_keystream(key: bytes, nonce: bytes, n_bytes: int) -> bytes:
    assert len(key) == 32
    assert len(nonce) == 12                          # IETF variant

    C = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    K = [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)]
    N = [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4)]

    out = bytearray()
    counter = 0
    while len(out) < n_bytes:
        S = [
            C[0], C[1], C[2], C[3],
            K[0], K[1], K[2], K[3],
            K[4], K[5], K[6], K[7],
            counter & 0xFFFFFFFF, N[0], N[1], N[2],
        ]
        counter += 1
        x = S[:]
        for _ in range(10):
            double_round(x)
        # Add to initial state
        for i in range(16):
            S[i] = (S[i] + x[i]) & 0xFFFFFFFF
        out.extend(b"".join(w.to_bytes(4, "little") for w in S))
    return bytes(out[:n_bytes])

def ROTL(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

### 1.6 Encryption / decryption

def chacha20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    ks = chacha20_keystream(key, nonce, len(data))
    return bytes(p ^ k for p, k in zip(data, ks))

# **Encryption = decryption** (XOR).

### 1.7 Using PyCryptodome

from Crypto.Cipher import ChaCha20

# IETF variant: 12-byte nonce
cipher = ChaCha20.new(key=key, nonce=nonce_12)
ct = cipher.encrypt(data)

# **PyCryptodome auto-detects:** 8-byte nonce → original; 12-byte nonce → IETF.

### 1.8 XChaCha20 — 192-bit nonce

# To avoid nonce collisions, **XChaCha20** uses a **192-bit (24-byte) nonce** by first deriving a subkey with **HChaCha20**:

subkey = HChaCha20(key, nonce[0:16])
keystream = ChaCha20(subkey, nonce[16:24])   # 8-byte nonce for inner

# This is what **libsodium**, **PyNaCl**, and many modern systems use. It's **safe from nonce collision** because 2¹⁹² is enormous.

### 1.9 ChaCha20-Poly1305 (AEAD, RFC 8439)

# The **standard AEAD** combining ChaCha20 (encryption) with **Poly1305** (MAC):

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, pt: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    cipher = ChaCha20Poly1305(key)
    ct = cipher.encrypt(nonce, pt, aad)              # ct includes tag (last 16 bytes)
    return ct[:-16], ct[-16:]                        # (ciphertext, tag)

# **ChaCha20-Poly1305 is what TLS 1.3 uses.** It provides **confidentiality + integrity + authenticity** → **malleability is blocked**.

### 1.10 Key parameters summary
#
# | Parameter | Salsa20 | ChaCha20 (IETF) | XChaCha20 |
# |---|---|---|---|
# | Nonce | 64 bits (8 bytes) | **96 bits (12 bytes)** | 192 bits (24 bytes) |
# | Counter | 64 bits | **32 bits** | 32 bits |
# | Block size | 64 bytes | 64 bytes | 64 bytes |
# | Rounds | 20 | 20 | 20 |
# | Max per (key,nonce) | 2⁷⁰ bytes | **2³⁸ bytes (256 GB)** | 2³⁸ bytes |
#
# **⚠️ The 32-bit counter means: after 2³² blocks = 2³⁸ bytes = 256 GB with the same `(key, nonce)`, the counter wraps and keystream repeats.** This is why:
# - You must **never reuse a nonce**.
# - For very large data, rotate keys.
#
# ---

## 2. Security requirements — and where ChaCha20 fails
#
# ChaCha20 is **cryptographically strong**. All practical failures are **misuse**.
#
# | Property | ChaCha20 status | Why |
# |---|---|---|
# | Unpredictability | ✅ | ARX, 20 rounds, better diffusion than Salsa20 |
# | Statistical randomness | ✅ | Passes all tests |
# | Key independence | ✅ | No key correlation |
# | Nonce support | ✅ (12-byte IETF) | Built-in |
# | Integrity | ❌ (raw) / ✅ (with Poly1305) | Depends on usage |
# | Reuse resistance | ❌ | Nonce reuse = catastrophic |
# | Counter limit | ⚠️ | Only 2³² blocks |
#
# **Two attack vectors:**
# 1. **Nonce reuse** (same as Salsa20, but 12-byte nonce = larger search space; collisions still possible after ~2⁴⁸ messages).
# 2. **Malleability** if raw ChaCha20 is used without Poly1305.
#
# ---

## 3. Attack taxonomy
#
# | # | Attack | Input needed | Difficulty |
# |---|---|---|---|
# | 1 | **Known plaintext → keystream** | One `(p, c)` pair | Trivial |
# | 2 | **Nonce reuse (two-time pad)** | Two ciphertexts, same `(key, nonce)` | Easy |
# | 3 | **Nonce reuse + known plaintext** | One known `(p, c)` + secret `c` | Trivial |
# | 4 | **Malleability (raw ChaCha20)** | One ciphertext + structure | Trivial |
# | 5 | **Counter overflow** | >256 GB with one `(key, nonce)` | Rare |
# | 6 | **Nonce collision detection** | Many packets with nonces | Easy |
# | 7 | **Weak / short / dictionary key** | Known keystream | Easy (if key weak) |
# | 8 | **Full key recovery** | — | Infeasible (2²⁵⁶) |
# | 9 | **AEAD misuse** | Nonce reuse + no AAD check | Medium |
# | 10 | **Library confusion** | Wrong nonce length | Common bug |
#
# Cases 1–4, 6, 7, 9, 10 are CTF-relevant.
#
# ---

## 4. Case 1: Known plaintext → keystream recovery

### Description
# Same as any stream cipher:
# ```
# keystream = p ⊕ c
# ```
#
# Then decrypt other ciphertexts with the same `(key, nonce)`, or feed into further analysis.

### Script
def recover_keystream(known_pt: bytes, known_ct: bytes) -> bytes:
    assert len(known_pt) <= len(known_ct)
    return bytes(p ^ c for p, c in zip(known_pt, known_ct))

def decrypt_with_keystream(ct: bytes, ks: bytes) -> bytes:
    return bytes(c ^ ks[i] if i < len(ks) else c
                 for i, c in enumerate(ct))

# Example
ks = recover_keystream(b"STATUS: SERVER ONLINE", known_ct)
print(decrypt_with_keystream(secret_ct, ks))

### When to use
# - **Noncense** (AES-CTR, same principle).
# - Any challenge with `known plaintext`.

### Limitation
# Only up to `len(known_pt)`. For full recovery → need nonce reuse (Case 2).


## 5. Case 2: Nonce reuse (two-time pad)

### Description
# Same `(key, nonce)` → same keystream:
# ```
# c1 = p1 ⊕ ks
# c2 = p2 ⊕ ks
# c1 ⊕ c2 = p1 ⊕ p2
# ```
#
# **Same math as OTP/Salsa20 key reuse.**
#
# ### Why nonce reuse happens with ChaCha20
# - **Random nonce via weak PRNG**: `random.randbytes(12)` instead of `secrets.token_bytes(12)` → predictable.
# - **Counter-based nonce starting at 0** → repeats on restart.
# - **Fixed nonce in code** (developer laziness).
# - **Counter overflow** (Case 5): 2³² blocks with same `(key, nonce)`.
# - **WEP-style**: `nonce = counter` shared across multiple messages.
# - **XChaCha20 misuse**: developer uses 24-byte nonce but only fills the first 12 bytes with random data.

### Script
def xor_two(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

x = xor_two(c1, c2)    # p1 ⊕ p2
# Then crib dragging (from OTP section)


### Full two-time pad with crib dragging
def crib_drag(x: bytes, crib: bytes):
    """x = p1 ⊕ p2; find where crib matches p1."""
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if all(32 <= b < 127 or b in (9, 10, 13) for b in guess):
            yield i, guess

for pos, p2_frag in crib_drag(x, b"cns{"):
    print(f"pos {pos}: if p1[{pos}:] = 'cns{{', then p2[{pos}:] = {p2_frag!r}")

### When to use
# - Any challenge with two ciphertexts and the same nonce.
# - Server logs, reused IV, fixed nonce.

## 6. Case 3: Nonce reuse + known plaintext

### Description
# Combine Cases 1 and 2: if `p1` is known/guessable, recover keystream, then decrypt `p2`.
#
# **Most practical attack** in CTF, because you can usually guess something (a fixed header, a known JSON structure, etc.).

### Script
def nonce_reuse_with_known(c1: bytes, c2: bytes, known_pt: bytes) -> bytes:
    """If p1 is known, recover p2."""
    ks = bytes(p ^ c for p, c in zip(known_pt, c1))
    return bytes(c ^ k for c, k in zip(c2, ks))

# Example
p2 = nonce_reuse_with_known(c1, c2, known_pt=b"According to all known laws of aviation...")
print(p2)

### When to use
# - **Noncense**: AES-CTR with reused nonce (same principle, different cipher).
# - Any "known plaintext + reused nonce" challenge.
# - **Very common** in CTF.
#
# ---

## 7. Case 4: Malleability (raw ChaCha20, no Poly1305)

### Description
# **This is the core vulnerability in Secure Bank** — but Secure Bank uses **Salsa20**, not ChaCha20. Same principle:
# ```
# c = p ⊕ ks
# c' = c ⊕ (p ⊕ p')  →  decrypts to p'
# ```
#
# If the plaintext has **known structure** (JSON, XML, protocol headers), you can flip bits to change specific fields **without knowing the key**.

### Script
def bitflip(ct: bytes, p_old: bytes, p_new: bytes, offset: int = 0) -> bytes:
    assert len(p_old) == len(p_new)
    out = bytearray(ct)
    for i, (a, b) in enumerate(zip(p_old, p_new)):
        out[offset + i] ^= a ^ b
    return bytes(out)

# Example: change amount 10 → 99 in a JSON transaction
original = b'"amount":10'
target   = b'"amount":99'
new_ct = bitflip(ct, original, target)

# ### When to use
# - **Secure Bank** (Salsa20, same math).
# - Any raw stream cipher with known structure.
# - **Important**: only works if **no MAC** (no Poly1305). Check the code — if it uses `ChaCha20_Poly1305`, malleability is **blocked**.

### Finding the offset
# - Look at the hint code: `print(plaintext)` before encryption → exact bytes visible.
# - `json.dumps(transaction, separators=(",", ":"))` — match exactly.
# - First bytes are predictable: `{"amount":` → `b'{"amount":'`.
# - Use `binascii` to inspect.

## 8. Case 5: Counter overflow (ChaCha20-specific!)

### Description
# **ChaCha20's counter is only 32 bits** (vs Salsa20's 64 bits). Max = **2³² blocks × 64 bytes = 2³⁸ bytes = 256 GB** per `(key, nonce)` pair.
#
# If you encrypt **>256 GB** with the same `(key, nonce)`:
# - Counter wraps to 0.
# - Keystream **repeats** from byte 0.
# - Subsequent data is effectively **two-time pad** with the first 256 GB.
#
# ### Detection
# - Encrypted file size > 256 GB with one key/nonce.
# - Server logs showing **counter restart**.

### Script (conceptual)

def detect_counter_overflow(ciphertexts_sizes: list[int], max_per_nonce=2**38) -> bool:
    """If total data with one (key, nonce) > 256 GB → counter overflow."""
    return sum(ciphertexts_sizes) > max_per_nonce

### When to use
# - **Very rare in CTF**. Usually doesn't happen because servers rotate keys.
# - Real-world concern: large file encryption with **a single nonce**.
# - **XChaCha20** doesn't fix this — 32-bit counter is still 256 GB.
#
# **Better solution:** use **XChaCha20-Poly1305** and **rotate keys** for large data.


## 9. Case 6: Nonce collision detection in traffic

### Description
# If you intercept **many** ChaCha20 ciphertexts and each has a **nonce prepended** (e.g., `nonce || ciphertext`), scan for nonce collisions:

from collections import defaultdict

def find_nonce_reuse(packets: list[bytes], nonce_len: int = 12):
    """packets: list of (nonce || ciphertext)."""
    by_nonce = defaultdict(list)
    for pkt in packets:
        nonce = pkt[:nonce_len]
        ct = pkt[nonce_len:]
        by_nonce[nonce].append(ct)
    return {nonce: cts for nonce, cts in by_nonce.items() if len(cts) >= 2}

### When to use
# - Any capture with many ChaCha20 packets.
# - Server logs of TLS 1.3 sessions.
# - **Very practical** in CTF with pcaps.

## 10. Case 7: Weak / short / dictionary key

### Description
# If the key is short (e.g., a **dictionary word** padded to 32 bytes) or predictable:

from Crypto.Cipher import ChaCha20

def crack_chacha20_wordlist(ct: bytes, nonce: bytes, wordlist: str) -> tuple[bytes, bytes] | None:
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n").encode()
        if not pw: continue
        # pad / truncate to 32 bytes
        key = (pw + b"\x00" * 32)[:32]
        try:
            pt = ChaCha20.new(key=key, nonce=nonce).decrypt(ct)
            if b"cns{" in pt or pt.startswith(b"{"):
                return key, pt
        except:
            continue
    return None

### When to use
# - Challenge uses a **dictionary key** (e.g., `key = b"secret" + b"\x00"*26`).
# - **Rare** — ChaCha20's key is 256-bit, so challenges usually use proper random keys.

## 11. Case 8: Full state / key recovery

### Description
# **Not feasible** for full 20-round ChaCha20. No known attack better than brute force (2²⁵⁶).
#
# **Exceptions:**
# - **Reduced rounds** (8-round variant is attacked, but full 20-round is not).
# - **Side-channel attacks** on CPU-level implementation (power analysis, cache timing) — out of scope for CTF.
#
# ### When to use
# - **Never** for full ChaCha20. If a challenge claims this, it's probably using reduced rounds or a different cipher.

## 12. Case 9: AEAD misuse (ChaCha20-Poly1305)

### Description
"""
**ChaCha20-Poly1305** is AEAD — it provides **integrity + authenticity**. So **malleability is blocked**:
- Any bit-flip in ciphertext → tag verification fails.
- Bit-flip in tag → verification fails.
- Bit-flip in nonce → decryption yields wrong plaintext, but tag also fails (because Poly1305 key is derived from nonce).

**But AEAD has its own misuse patterns:**

### 12a. Nonce reuse in AEAD
If the same `(key, nonce)` is reused:
- **Confidentiality breaks** (two-time pad on ciphertext).
- **Authenticity breaks** too — you can **forge** new ciphertexts because the Poly1305 key is derived from `ChaCha20(key, nonce, counter=0)`. Two (c, tag) pairs with the same nonce → recover Poly1305 key → **forge any message**.

### Script — nonce reuse in AEAD (forgery)
"""
# Recover Poly1305 key from two messages with same nonce
# Complex; requires solving the Poly1305 polynomial over GF(2^130 - 5)
# Most CTF challenges use the `cryptography` library:
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
# ... but forgery is not trivial. For decryption, use Case 3 (known plaintext).


### 12b. AAD not verified
"""
Some implementations only verify the tag over ciphertext, not over AAD (Associated Authenticated Data). This means:
- **AAD (e.g., headers) can be tampered** without breaking the tag.
- Exploits: protocol-level manipulation (e.g., change a session ID in a header).

### When to use
- **Nonce reuse in AEAD** → usually you can just decrypt with known plaintext (Case 3).
- **Forgery** → requires advanced Poly1305 math; rare in CTF.
- **AAD bypass** → depends on implementation.


## 13. Case 10: Library confusion (very common in CTF!)

### Description
Different libraries implement **different variants** of ChaCha20. This causes bugs:

| Library | Nonce | Counter | Standard |
|---|---|---|---|
| `Crypto.Cipher.ChaCha20` (PyCryptodome) | 8 or 12 bytes (auto) | 64 or 32 | Depends |
| `cryptography` (ChaCha20) | 16 bytes | 64 | Original (Bernstein) |
| `cryptography` (ChaCha20Poly1305) | 12 bytes | 32 | IETF |
| `nacl.secret.SecretBox` (XSalsa20-Poly1305) | 24 bytes | 64 | XSalsa20 |
| `nacl.bindings.crypto_stream_chacha20` | 8 bytes | 64 | Original |
| `nacl.bindings.crypto_stream_chacha20_ietf` | 12 bytes | 32 | IETF |

**Classic CTF bug:** challenge code uses **12-byte nonce** with `cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20`, which expects **16-byte nonce** (original Bernstein). Result: **wrong keystream** or **crash**.

**Or:** challenge uses **8-byte nonce** but decrypts with **12-byte nonce** library → everything breaks.

### Detection
- Read the source code carefully.
- Note nonce length, counter length, key length.
- Check the standard (IETF vs original vs XChaCha20).

### Script — sanity check
"""

def check_chacha20_variant(nonce: bytes) -> str:
    if len(nonce) == 8:  return "original (64-bit nonce, 64-bit counter)"
    if len(nonce) == 12: return "IETF (96-bit nonce, 32-bit counter)"
    if len(nonce) == 16: return "original cryptography.hazmat (128-bit nonce)"
    if len(nonce) == 24: return "XChaCha20 (192-bit nonce)"
    return f"unknown ({len(nonce)} bytes)"

### When to use
# - **Always** — before writing any attack, verify the variant.
# - If a challenge "doesn't work", it's almost always a **variant mismatch**.
#
# ---

## 14. Case 11: XChaCha20 — when nonce is 24 bytes

### Description
"""
**XChaCha20** = **HChaCha20** (key derivation) + **ChaCha20** (encryption). Uses **192-bit nonce** (24 bytes).

### Attack surface
- **Nonce collision** → 2¹⁹² is enormous → **no practical collisions**.
- **Counter overflow** → still 256 GB per `(key, nonce)`.
- **Malleability** → **blocked** if used with Poly1305 (XSalsa20-Poly1305 / XChaCha20-Poly1305).
- **Key recovery** → infeasible.

### When to use
- **Rare in CTF** — XChaCha20 is considered secure.
- If challenge uses 24-byte nonce → probably safe from nonce-collision attacks.
- **Only remaining attack**: **key weakness** (Case 7) or **implementation bugs** (Case 10).

---

## 15. Case 12: ChaCha20-Poly1305 — AEAD mode

### Description
**ChaCha20-Poly1305** combines ChaCha20 (encryption) with **Poly1305** (MAC) in **RFC 8439**:

```
1. Generate Poly1305 key: first 32 bytes of ChaCha20(key, nonce, counter=0)
2. Encrypt with ChaCha20 (counter starting at 1)
3. Compute Poly1305 over AAD || ciphertext || lengths
4. Tag = Poly1305 output
```

### Security properties
- **Confidentiality**: ✅
- **Integrity**: ✅
- **Authenticity**: ✅
- **Malleability**: ❌ blocked (any modification → tag fails)

### Attack surface (only via misuse)
- **Nonce reuse** → catastrophic (Poly1305 key recovery + forgery).
- **Key weakness** → same as raw ChaCha20.
- **AAD bypass** → if implementation doesn't include AAD in tag (bug, not standard).

### When to use
- If the challenge says **"ChaCha20-Poly1305"** or **"AEAD"** → **malleability is blocked**.
- Only remaining attack: **nonce reuse** (Case 12a) or **key weakness**.
- **For Secure Bank**: uses **raw Salsa20** (not AEAD) → malleability works.

---

## 16. Comparison: Salsa20 vs ChaCha20

| Aspect | Salsa20 | ChaCha20 |
|---|---|---|
| Nonce | 64-bit (8 bytes) | **96-bit (12 bytes)** IETF |
| Counter | 64-bit | **32-bit** |
| Max per (key, nonce) | 2⁷⁰ bytes | **2³⁸ bytes (256 GB)** |
| Rounds | 20 | 20 |
| Diffusion | Good | **Better** (each bit affects more output) |
| QR style | Assign `y0..y3` (non-overwriting) | **In-place** updates |
| QR rotation | `7, 9, 13, 18` | `16, 12, 8, 7` |
| Speed | Fast | **Faster** on modern CPUs |
| Standard | No formal RFC | **RFC 8439** |
| AEAD | XSalsa20-Poly1305 | **ChaCha20-Poly1305** |
| TLS 1.3 | No | **Yes** |
| WireGuard | No | **Yes** |
| SSH | Supported | **Preferred** |

**In practice:** always prefer ChaCha20 over Salsa20 in new code. The only reason to use Salsa20 in CTF is if the challenge explicitly uses it (e.g., Secure Bank).

---

## 17. Quick reference: "I see ChaCha20 — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Known plaintext | keystream recovery | §4 |
| Two ciphertexts, same nonce | `c1 ⊕ c2 = p1 ⊕ p2` | §5 |
| Known plaintext + reused nonce | decrypt secret | §6 |
| Raw ChaCha20 (no Poly1305) + structure | malleability | §7 |
| >256 GB with one (key, nonce) | counter overflow | §8 |
| Many packets, check nonce | collision scan | §9 |
| Weak key | brute force | §10 |
| Full key recovery | infeasible | — |
| ChaCha20-Poly1305 + reused nonce | AEAD forgery (advanced) | §12a |
| Nonce length mismatch | library confusion | §13 |
| XChaCha20 | safe from nonce collision | §14 |
| ChaCha20-Poly1305 | AEAD, malleability blocked | §15 |

---

## 18. Mapping to session tasks

**None of the explicit session tasks use ChaCha20** — but it's an important comparison:

| Task | Cipher | Relation to ChaCha20 |
|---|---|---|
| **Secure Bank** | **Salsa20** | Same ARX family, same malleability vulnerability (§7) |
| **Secure Bank 2** | Truncated SHA-256 | Different primitive, birthday attack |
| **Noncense** | AES-CTR | Same nonce reuse principle (§5/§6) |
| **Replanting** | LCG | Both stream ciphers; ChaCha20 has no recoverable seed |
| **Signed, Sealed** | HMAC-SHA256 | Different primitive |
| **Token of Trust** | JWT | Different primitive |
| **Security Cam** | RTSP/MD5 | Different primitive |

**Why it still matters:**
- If a challenge **upgrades** from Salsa20 to ChaCha20, the attack is **identical** (malleability, nonce reuse).
- **Library confusion** is real — knowing the variants saves debugging time.
- **ChaCha20-Poly1305** blocks malleability — knowing this prevents wasted effort.

---

## 19. Defender perspective

| Mistake | Fix |
|---|---|
| No MAC → malleability | **ChaCha20-Poly1305** (AEAD) |
| Nonce reuse | **XChaCha20** (192-bit nonce) or **random 96-bit nonce** with safe PRNG |
| Fixed nonce in code | **Never** — nonce must be unique per message |
| Weak key | 256-bit random key from CSPRNG (`secrets.token_bytes(32)`) |
| Counter overflow (>256 GB) | **Rotate keys**; use XChaCha20 |
| Library confusion | Pin library version; document variant |
| No key rotation | HKDF or periodic rekey |

**Golden rules for ChaCha20:**
1. **Always use AEAD** (ChaCha20-Poly1305) — never raw ChaCha20.
2. **Always use XChaCha20** if you can — it eliminates nonce-collision risk.
3. **Never reuse nonce** — even with random 96-bit nonces, 2⁴⁸ messages causes birthday collision.
4. **Rotate keys** if encrypting >256 GB with one `(key, nonce)`.

---

## 20. Ready-to-use `chacha20_toolkit.py`?

Same structure as before. Options:

- **A)** Build `chacha20_toolkit.py` now with:
  ```
  - chacha20_keystream(key, nonce, n)            # pure Python
  - chacha20_crypt(key, nonce, data)
  - chacha20_poly1305_encrypt(key, nonce, pt, aad) -> (ct, tag)
  - chacha20_poly1305_decrypt(key, nonce, ct, tag, aad) -> pt
  - xchacha20_crypt(key, nonce_24, data)         # HChaCha20 + ChaCha20
  - recover_keystream(known_pt, known_ct)
  - nonce_reuse_with_known(c1, c2, known_pt)
  - xor_two(c1, c2)
  - crib_drag(x, crib)
  - bitflip(ct, p_old, p_new, offset=0)
  - find_nonce_reuse(packets, nonce_len=12)
  - crack_chacha20_wordlist(ct, nonce, wordlist)
  - check_chacha20_variant(nonce)
  ```
  + CLI:
  ```
  python chacha20_toolkit.py decrypt    --key hex --nonce hex --ct hex
  python chacha20_toolkit.py ks         --pt "..." --ct hex
  python chacha20_toolkit.py nonce      --c1 c1.hex --c2 c2.hex --crib "cns{"
  python chacha20_toolkit.py bitflip    --ct hex --old "amount:10" --new "amount:99"
  python chacha20_toolkit.py wordlist   --ct hex --nonce hex --wordlist rockyou.txt
  python chacha20_toolkit.py detect     --pcap capture.pcap
  python chacha20_toolkit.py variant    --nonce hex
  ```
"""