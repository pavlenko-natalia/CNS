# Salsa20: Theory, All Cases, Scripts
#
# Salsa20 is one of the two modern stream ciphers in the course (alongside ChaCha20).
# It's the direct predecessor of ChaCha20, designed by Daniel J. Bernstein in 2005. It's **cryptographically strong by design** — all practical attacks are on **misuse** (nonce reuse, malleability, weak key handling), not on the algorithm itself.
#
# This is the cipher behind **Secure Bank** (Salsa20 malleability task) and potentially any stream cipher task that isn't LCG/RC4.
#
# ---

## 1. What is Salsa20 (formally)

# Salsa20 is an **ARX-based stream cipher** (Add-Rotate-XOR). Its state is a **4×4 matrix of 32-bit words** (64 bytes total), composed of:

# | Component | Size | Purpose |
# |---|---|---|
# | Constant `C` | 128 bits (16 bytes) | `"expand 32-byte k"` (ASCII) |
# | Key `K` | 256 bits (32 bytes) or 128 bits (16 bytes) | Secret |
# | Nonce `N` | 64 bits (8 bytes) | **Unique per message** |
# | Counter `P` | 64 bits (8 bytes) | Block counter |

### 1.1 Initial state layout

# ```
# [C1  K1  K2  K3]
# [K4  C2  N1  N2]
# [P1  P2  C3  K5]
# [K6  K7  K8  C4]
# ```
#
# If key is 128-bit, `K5..K8 = K1..K4` (key repeated).

### 1.2 Expansion function `H(K, N, P)`

# For each counter value `P`:
# 1. Build the initial 4×4 state from `(C, K, N, P)`.
# 2. Apply **10 double-rounds** (20 rounds total) of the round function `f()`.
# 3. **Add** the result word-by-word to the initial state (mod 2³²).
# 4. Output = 64 bytes of keystream.
#
# The final **addition** with the initial state is essential — it makes the function non-invertible without knowing `K, N, P`.

### 1.3 Round function `f()`

# Each round applies `QR()` (Quarterround) twice:
# - **Columnround**: `QR` on each of the 4 columns
# - **Rowround**: `QR` on each of the 4 rows

### 1.4 Quarterround `QR()`

# Given 4 words `(x₀, x₁, x₂, x₃)`:

def QR(x0, x1, x2, x3):
    y1 = x1 ^ ROTL(x0 + x3, 7)
    y2 = x2 ^ ROTL(y1 + x0, 9)
    y3 = x3 ^ ROTL(y2 + y1, 13)
    y0 = x0 ^ ROTL(y3 + y2, 18)
    return y0, y1, y2, y3

# Where `+` is 32-bit modular addition and `ROTL(x, n)` is 32-bit left rotation.

### 1.5 Full Salsa20 keystream generation

def salsa20_keystream(key: bytes, nonce: bytes, n_bytes: int) -> bytes:
    """Generate n_bytes of Salsa20 keystream."""
    assert len(key) in (16, 32)
    assert len(nonce) == 8
    if len(key) == 16:
        key = key + key  # repeat 128-bit key

    # Parse key into 8 words (little-endian)
    K = [int.from_bytes(key[i:i+4], "little") for i in range(0, 32, 4)]
    # Parse nonce into 2 words
    N = [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 8, 4)]
    # Constant "expand 32-byte k"
    C = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    out = bytearray()
    counter = 0
    while len(out) < n_bytes:
        # Build initial state
        S = [
            C[0], K[0], K[1], K[2],
            K[3], C[1], N[0], N[1],
            counter & 0xFFFFFFFF, (counter >> 32) & 0xFFFFFFFF, C[2], K[4],
            K[5], K[6], K[7], C[3],
        ]
        counter += 1
        # 10 double-rounds
        x = S[:]
        for _ in range(10):
            # Columnround
            x[0],  x[4],  x[8],  x[12] = QR(x[0],  x[4],  x[8],  x[12])
            x[5],  x[9],  x[13], x[1]  = QR(x[5],  x[9],  x[13], x[1])
            x[10], x[14], x[2],  x[6]  = QR(x[10], x[14], x[2],  x[6])
            x[15], x[3],  x[7],  x[11] = QR(x[15], x[3],  x[7],  x[11])
            # Rowround
            x[0],  x[1],  x[2],  x[3]  = QR(x[0],  x[1],  x[2],  x[3])
            x[5],  x[6],  x[7],  x[4]  = QR(x[5],  x[6],  x[7],  x[4])
            x[10], x[11], x[8],  x[9]  = QR(x[10], x[11], x[8],  x[9])
            x[15], x[12], x[13], x[14] = QR(x[15], x[12], x[13], x[14])
        # Add to initial state (mod 2^32)
        for i in range(16):
            S[i] = (S[i] + x[i]) & 0xFFFFFFFF
        # Pack as little-endian bytes
        out.extend(b"".join(w.to_bytes(4, "little") for w in S))
    return bytes(out[:n_bytes])


def ROTL(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

### 1.6 Encryption / decryption

def salsa20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    ks = salsa20_keystream(key, nonce, len(data))
    return bytes(p ^ k for p, k in zip(data, ks))

# **Encryption = decryption** (XOR).

# Or with PyCryptodome (faster, recommended for CTF):

from Crypto.Cipher import Salsa20

def salsa20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return Salsa20.new(key=key, nonce=nonce).encrypt(data)

### 1.7 Key parameters summary
#
# | Parameter | Salsa20 | ChaCha20 (IETF) |
# |---|---|---|
# | Nonce | **64 bits (8 bytes)** | 96 bits (12 bytes) |
# | Counter | **64 bits (8 bytes)** | 32 bits (4 bytes) |
# | Block size | 64 bytes | 64 bytes |
# | Rounds | 20 | 20 |
# | State | 4×4 × 32-bit | 4×4 × 32-bit |
#
# **Critical:** Salsa20's nonce is only **8 bytes**. That's why it's used with a counter — but if the same `(key, nonce)` pair is reused, you get keystream reuse.
#
# ---

## 2. Security requirements — and where Salsa20 fails

# Salsa20 is **cryptographically secure** as a PRG. Its round function has been analyzed extensively; no practical break of the full 20-round version is known. **All failures are misuse.**

# | Property | Salsa20 status | Why |
# |---|---|---|
# | Unpredictability | ✅ | ARX design, 20 rounds |
# | Statistical randomness | ✅ | Passes all tests |
# | Key independence | ✅ | No key correlation biases |
# | Nonce support | ✅ (8-byte) | Built-in |
# | Integrity | ❌ | No MAC — malleable |
# | Reuse resistance | ❌ | Nonce reuse = catastrophic |
#
# The two attack vectors: **nonce reuse** and **malleability**.
#
# ---

## 3. Attack taxonomy
#
# | # | Attack | Input needed | Difficulty |
# |---|---|---|---|
# | 1 | **Known plaintext → keystream** | One `(p, c)` pair | Trivial |
# | 2 | **Nonce reuse (two-time pad)** | Two ciphertexts, same `(key, nonce)` | Easy |
# | 3 | **Nonce reuse + known plaintext** | One known `(p, c)` + one secret `c` | Trivial |
# | 4 | **Malleability (bit-flipping)** | One ciphertext + structure | Trivial |
# | 5 | **Nonce/counter collision** | Counter overflow or nonce collision | Rare |
# | 6 | **Weak key (short / dictionary)** | Known keystream + wordlist | Easy |
# | 7 | **Key recovery from full state** | Not possible with full 20 rounds | Infeasible |
# | 8 | **Reduced-round attacks** | 8-round variant | Academic |
#
# Cases 1–4 and 6 are CTF-relevant.
#
# ---

## 4. Case 1: Known plaintext → keystream recovery

### Description
# Same as any stream cipher:
# ```
# keystream = p ⊕ c
# ```
#
# Then:
# - Decrypt other ciphertexts with the same keystream (Case 2).
# - **Not** useful for seed recovery (Salsa20 doesn't have a recoverable seed — the key is the seed, and 256-bit key is not brute-forceable).

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
# - Any challenge with `known plaintext`.
# - Combined with Case 2 if the nonce is reused.
#
# ### Limitation
# Only up to `len(known_pt)`.
#
# ---

## 5. Case 2: Nonce reuse (two-time pad)

### Description
# Same `(key, nonce)` → same keystream:
# ```
# c1 = p1 ⊕ ks
# c2 = p2 ⊕ ks
# c1 ⊕ c2 = p1 ⊕ p2
# ```
#
# **This is the most important Salsa20 attack.**
#
# ### Why nonce reuse happens
# - **Random 8-byte nonce** generated with a weak PRNG → collision after ~2³² messages (birthday).
# - **Counter-based nonce** starting from 0 on restart → repeats.
# - **Fixed nonce** in code (developer laziness).
# - **`secrets.token_bytes(8)`** is fine cryptographically, but collisions still happen if you send >2³² messages.

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

# Example
for pos, p2_frag in crib_drag(x, b"cns{"):
    print(f"pos {pos}: if p1[{pos}:] = 'cns{{', then p2[{pos}:] = {p2_frag!r}")

### When to use
# - **Any challenge with two ciphertexts and the same nonce.**
# - GCM/CCM/Salsa20/ChaCha20 nonce reuse.
#
# ---

## 6. Case 3: Nonce reuse + known plaintext (the practical winner)

### Description
# Combine Cases 1 and 2:
# - If `p1` is known/guessable → recover keystream → decrypt `p2`.
# - This is **Noncense** (AES-CTR, but same principle).
# - Also works for **any Salsa20 challenge with a known message**.
#
# ### Script
def nonce_reuse_with_known(c1: bytes, c2: bytes, known_pt: bytes) -> bytes:
    """If p1 is known, recover p2."""
    ks = bytes(p ^ c for p, c in zip(known_pt, c1))
    return bytes(c ^ k for c, k in zip(c2, ks))

# Example
p2 = nonce_reuse_with_known(c1, c2, known_pt=b"According to all known laws...")
print(p2)

### When to use
# - **Secure Bank** (if you can leak another transaction with the same nonce).
# - **Noncense** (AES-CTR, same attack).
# - Any "known plaintext + reused nonce" challenge.
#
# ---

## 7. Case 4: Malleability (bit-flipping)

### Description
# This is the **core vulnerability** in **Secure Bank**.
#
# Salsa20 is a stream cipher, so:
# ```
# c = p ⊕ ks
# c' = c ⊕ (p ⊕ p')  →  decrypts to p'
# ```
#
# If you know (or can guess) the structure of the plaintext, you can flip **arbitrary bits** without knowing the key.

### Secure Bank scenario
# The server encrypts a JSON transaction:
# ```json
# {"amount": 10, "from_account": "SIM-ATTACKER", "to_account": "SIM-BOB", ...}
# ```
#
# If you want to pay Bob your debt differently — e.g., change `amount` from `10` to `99`, or change `from_account` — you can XOR the ciphertext accordingly.
#
# **But wait:** the server uses a **fresh nonce** per transaction (via `secrets.token_bytes(8)`), so you can't do a full ciphertext substitution. You need to be **man-in-the-middle**: intercept the ciphertext, modify it, forward it.

### Script
def bitflip(ct: bytes, p_old: bytes, p_new: bytes, offset: int = 0) -> bytes:
    """Change p_old → p_new in plaintext by modifying ciphertext."""
    assert len(p_old) == len(p_new)
    out = bytearray(ct)
    for i, (a, b) in enumerate(zip(p_old, p_new)):
        out[offset + i] ^= a ^ b
    return bytes(out)

# Example: change amount from 10 to 99
original = b'"amount":10'
target   = b'"amount":99'
new_ct = bitflip(ct, original, target)

### Finding the offset
# - The JSON is printed before encryption in the hint (`print(plaintext)`).
# - You can infer the format from server responses (e.g., "Balance: X EUR" tells you `amount` position).
# - The first bytes are predictable: `{"amount":` → `b'{"amount":'`.
# - Use `json.dumps` with `separators=(",", ":")` to match server output.
#
# ### When to use
# - **Secure Bank**: yes, this is the intended attack.
# - Any Salsa20 challenge with known structure.
#
# ### Defense (why it's a bug)
# - Salsa20 alone doesn't protect integrity.
# - **Should** use `Encrypt-then-MAC` (Salsa20 + Poly1305 = **XSalsa20-Poly1305** or **ChaCha20-Poly1305**).
# - The **Secure Bank** server does **not** authenticate the ciphertext — so bit-flipping works.
#
# ---

## 8. Case 5: Nonce/counter collision (theoretical)

# ### Description
# Salsa20's **counter is 64-bit** (2⁶⁴ blocks per message = 2⁷⁰ bytes). In practice, this never overflows. But:
#
# - **Nonce is 8 bytes** → after 2³² messages, nonce collision is expected (birthday paradox).
# - **Worse**: if nonce is a **counter** starting from 0, then after restart (e.g., reboot) it repeats.
# - **Worst**: if nonce is **fixed** (e.g., `b"\x00" * 8` in code), keystream is entirely determined by key.
#
# ### Detection
# - Look at the challenge code: `nonce = b"\x00" * 8` → red flag.
# - If nonce is `counter.to_bytes(8, "little")` and counter resets → collision.

### Script
# If you find a fixed nonce in the code:
key = b"..."          # not known
nonce = b"\x00" * 8   # fixed
# Two messages with the same key → two-time pad

### When to use
# - Look at the source. **Secure Bank** uses `secrets.token_bytes(8)` → no collision in practice.
# - Only relevant for **restarted servers with counter-based nonces**.
#
## 9. Case 6: Weak / short / dictionary key

### Description
# If the key is short or from a wordlist:
# ```
# ks = salsa20_keystream(key, nonce, len(ct))
# pt = ct ⊕ ks
# ```

# Then:
# - Test each word from wordlist.
# - Check if result contains `cns{` or is valid English.

### Script
from Crypto.Cipher import Salsa20

def crack_salsa20_wordlist(ct: bytes, nonce: bytes, wordlist: str) -> tuple[bytes, bytes]:
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n").encode()
        if not pw or len(pw) > 32: continue
        # pad / truncate to 16 or 32 bytes
        if len(pw) < 16: key = pw + b"\x00" * (16 - len(pw))
        elif len(pw) < 32: key = pw + b"\x00" * (32 - len(pw))
        else: key = pw[:32]
        try:
            pt = Salsa20.new(key=key, nonce=nonce).decrypt(ct)
            if b"cns{" in pt or pt.startswith(b"{"):
                return key, pt
        except:
            continue
    return None, None

### When to use
# - Challenge uses a **dictionary key** (e.g., `key = b"password123"` padded to 32).
# - **Very rare** — Salsa20's key is 256-bit, so challenges usually use proper keys.
#

## 10. Case 7: Full state / key recovery

### Description
# **Not feasible** for full 20-round Salsa20. There's no known attack better than brute force (2²⁵⁶ for 256-bit key).
#
# **Exceptions:**
# - **Reduced rounds** (8-round variant broken in ~2²⁵⁰, 2012 — academic only).
# - **Leaked state** (if the server dumps intermediate state — extremely unlikely in CTF).
# - **Related-key attacks** (theoretical, not practical).
#
# ### When to use
# - **Never** for full Salsa20. If the challenge claims this, it's probably using reduced rounds or a different variant.
#

## 11. Case 8: Nonce collision detection in traffic

### Description
# If you intercept **many** Salsa20 ciphertexts and each has a **nonce prepended** (e.g., `nonce || ciphertext`), you can scan for nonce collisions:

from collections import defaultdict

def find_nonce_reuse(packets: list[bytes], nonce_len: int = 8):
    """packets: list of (nonce || ciphertext)."""
    by_nonce = defaultdict(list)
    for pkt in packets:
        nonce = pkt[:nonce_len]
        ct = pkt[nonce_len:]
        by_nonce[nonce].append(ct)
    return {nonce: cts for nonce, cts in by_nonce.items() if len(cts) >= 2}

# If you find two ciphertexts with the same nonce → two-time pad → Case 2.
#
# ### When to use
# - **Secure Bank** if the server ever reuses nonce (it doesn't, but check).
# - Any traffic capture with many Salsa20 packets.
#

## 12. Case 9: Comparison with ChaCha20
#
# | Aspect | Salsa20 | ChaCha20 |
# |---|---|---|
# | Nonce | 8 bytes | 12 bytes (IETF) |
# | Counter | 8 bytes | 4 bytes |
# | Rounds | 20 | 20 |
# | Diffusion | Good | **Better** (each bit affects more output) |
# | QR order | `y0, y1, y2, y3` (linear) | In-place updates (better) |
# | Speed | Fast | **Faster** on modern CPUs |
# | Library support | `Crypto.Cipher.Salsa20` | `Crypto.Cipher.ChaCha20` |
# | Use in CTF | **Secure Bank** | modern TLS/SSH |
#
# **In practice:** always prefer ChaCha20 over Salsa20 in new code. If a challenge uses Salsa20, the vulnerability is the same as any stream cipher (nonce reuse, malleability).
#
# ---

## 13. Case 10: XSalsa20 (extended nonce)

### Description
# `XSalsa20` uses a **192-bit nonce** (24 bytes) by first deriving a subkey with HSalsa20:
# ```
# subkey = HSalsa20(key, nonce[0:16])
# keystream = Salsa20(subkey, nonce[16:24])
# ```
#
# This is used by **NaCl** and **PyNaCl** for authenticated encryption.
#
# ### Detection
# - If the challenge uses 24-byte nonces → likely XSalsa20.
# - If it uses `nacl.secret.SecretBox` → XSalsa20-Poly1305 (AEAD, **malleability blocked**).

### Script (XSalsa20 with PyCryptodome)
from Crypto.Cipher import Salsa20

# PyCryptodome's Salsa20 is plain Salsa20, not XSalsa20.
# For XSalsa20, use PyNaCl:
# pip install pynacl
from nacl.secret import SecretBox
# But SecretBox adds Poly1305 MAC → malleability blocked.

### When to use
# - If the challenge uses `nacl`, `libsodium`, or `PyNaCl` → it's **XSalsa20-Poly1305**, and malleability is **blocked**.
# - If it uses raw `Crypto.Cipher.Salsa20` → plain Salsa20, malleability works.
#
# **Important for Secure Bank:** verify the library. If it's `nacl`, bit-flipping won't work (MAC will fail). If it's `pycryptodome.Cipher.Salsa20`, bit-flipping works.
#
# ---

## 14. Quick reference: "I see Salsa20 — what do I do?"

# | Situation | Attack | Script |
# |---|---|---|
# | Known plaintext | keystream recovery | §4 |
# | Two ciphertexts, same nonce | `c1 ⊕ c2 = p1 ⊕ p2` | §5 |
# | Known plaintext + reused nonce | decrypt secret | §6 |
# | Bit-flipping / known structure | malleability | §7 |
# | Fixed nonce in code | two-time pad | §8 |
# | Short/dictionary key | brute force | §9 |
# | Full key recovery | infeasible | — |
# | Nonce collision detection | scan traffic | §11 |
# | PyNaCl / SecretBox | malleability **blocked** | — |
#
# ---

## 15. Mapping to session tasks

# ### **Secure Bank** (main Salsa20 task)
#
# **Setup:**
# - Server at `cns-test.idlab.uantwerpen.be:50001`.
# - Encrypts JSON transactions with Salsa20.
# - Nonce = `secrets.token_bytes(8)` → **fresh per transaction**.
# - Ciphertext = `nonce || ciphertext` transmitted.
# - **No MAC** → malleability works.
#
# **Attack strategy:**
#
# 1. **Connect and interact** with the server (nc).
# 2. **Observe the transaction format** — likely something like:
#    ```json
#    {"amount": 10, "from": "SIM-ATTACKER", "to": "SIM-BOB", ...}
#    ```
# 3. **Identify target fields** — e.g., change `amount` or `from_account`.
# 4. **Intercept** the next outgoing transaction (or send a crafted one).
# 5. **Bit-flip** the ciphertext:
#    ```python
#    ct = nonce + ciphertext
#    new_ct = bitflip(ciphertext, b'"amount":10', b'"amount":99')
#    ```
# 6. **Forward** modified `nonce || new_ct` to server.
# 7. **Server decrypts** → sees `amount: 99` → pays Bob 99.
#
# **Common pitfalls:**
# - **JSON canonicalization**: server may use `separators=(",", ":")` and `sort_keys=True`. Match exactly.
# - **Nonce collision**: if the server **reuses** nonce (e.g., if it's a counter that resets), you may get two-time pad instead.
# - **Library choice**: if the server uses `PyNaCl.SecretBox`, malleability is **blocked** (MAC). Verify the library.
#
# **Sample solve skeleton:**

import socket, json

HOST, PORT = "cns-test.idlab.uantwerpen.be", 50001

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        data += sock.recv(4096)
    return data

sock = socket.create_connection((HOST, PORT))
# 1) Read server's prompt
banner = recv_until(sock, b"> ")
print(banner.decode(errors="replace"))

# 2) Read the transaction format (if printed) — adjust accordingly
# 3) Send a normal payment request, observe ciphertext
# 4) Capture nonce + ciphertext from response
# 5) XOR bit-flip amount / account fields
# 6) Send modified transaction
# 7) Receive success / flag

# **Since the server is offline for you**, this is the **exact plan** to execute when it comes back online. The bit-flipping logic is the core — you can test it locally:


# Local simulation
from Crypto.Cipher import Salsa20
key = bytes(32)          # placeholder
nonce = b"\x00" * 8      # fixed for local test

original_json = b'{"amount":10,"to":"SIM-BOB"}'
ct = Salsa20.new(key=key, nonce=nonce).encrypt(original_json)

# Attack: change amount 10 → 99
modified_ct = bitflip(ct, b'"amount":10', b'"amount":99')
pt = Salsa20.new(key=key, nonce=nonce).decrypt(modified_ct)
print(pt)   # b'{"amount":99,"to":"SIM-BOB"}'

#
# ### **Secure Bank 2**
# - Uses **truncated SHA-256 fingerprint** → **birthday collision** (not Salsa20).
# - But the transaction format is the **same** → reuse the bit-flip logic if Salsa20 is still used for encryption.
#
# ### **Noncense** (AES-CTR)
# - **Different cipher** (AES-CTR), but the **same nonce reuse attack**.
# - Use §5/§6 (two-time pad / known plaintext).