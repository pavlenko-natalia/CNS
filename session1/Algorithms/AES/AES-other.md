# AES Modes: ECB, CBC, CFB, OFB, CTR, XTS-AES

AES itself is secure. **All practical AES attacks are mode-of-operation bugs.** This section walks through all six NIST-standardized modes, their cryptographic properties, and — crucially — the **specific attack** that each mode enables. This is the mode-level companion to the AES section.

---

## 0. Comparison table — the one thing to memorize

| Mode | Encrypts | Parallel? | IV/nonce type | Same PT → same CT? | Main attack |
|---|---|---|---|---|---|
| **ECB** | Block by block | ✅ | none | ✅ | Deterministic → pattern leaks, byte-at-a-time |
| **CBC** | Block chained | ❌ | Random IV | ❌ | Bit-flipping, padding oracle, IV manipulation |
| **CFB** | Stream-like (s-bit) | ⚠️ (encrypt only) | Random IV | ❌ | Bit-flipping (self-sync), IV reuse |
| **OFB** | Stream-like | ✅ (precompute) | **Nonce** (never reuse) | ❌ | Malleability, IV reuse |
| **CTR** | Stream-like | ✅ | **Nonce/counter** (never reuse) | ❌ | **Nonce reuse → keystream reuse** |
| **XTS-AES** | Disk sectors | ✅ | **Tweak (sector number)** | ❌ (per-tweak) | Tweak reuse, ciphertext stealing bugs |

**Universal rule:** No AES mode provides **integrity** by itself. **Always add MAC or use AEAD (GCM/CCM).**

---

## 1. ECB — Electronic Codebook

### 1.1 Description

```
C_i = E(K, P_i)
P_i = D(K, C_i)
```

Each block is encrypted **independently**. The simplest mode — essentially a "codebook" mapping every plaintext block to its ciphertext.

```
P_1 → [AES_K] → C_1
P_2 → [AES_K] → C_2
...
P_N → [AES_K] → C_N
```

**Padding required:** last block padded (PKCS#7 or ISO/IEC 7816-4).

### 1.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Deterministic** | Same PT block → same CT block |
| 2 | **Pattern leakage** | Visual patterns visible in images/data |
| 3 | **Block reordering** | Attacker can shuffle/replay blocks |
| 4 | **Byte-at-a-time** | If you control part of the plaintext, you can recover the rest |
| 5 | **Cut-and-paste** | Substitute one block for another |

**ECB is the most broken mode** — never use it for anything beyond a single block (e.g., encrypting a key).

### 1.3 Attack 1 — Detection (repeated blocks)

```python
def detect_ecb(ct: bytes, block_size=16) -> bool:
    """ECB iff any two ciphertext blocks are identical."""
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))

# Example: encrypt 48 bytes of "A" with AES-ECB vs AES-CBC
# ECB → 3 identical ciphertext blocks
# CBC → 3 different ciphertext blocks
```

### 1.4 Attack 2 — Visual pattern recovery (ECB "penguin")

If the ciphertext is an **image encrypted with ECB**, you can literally see the structure:

```python
from PIL import Image

def ecb_visualize(ct: bytes, width: int) -> Image:
    """Display ciphertext as an image; ECB preserves block structure."""
    height = len(ct) // width
    img = Image.frombytes("L", (width, height), ct[:width*height])
    img.save("ecb_visual.png")
    return img

# Classic example: encrypt a BMP of Tux with AES-ECB → you still see Tux.
```

### 1.5 Attack 3 — Byte-at-a-time ECB decryption ⭐

**Setup:** oracle returns `AES_ECB(user_input || SECRET)`. You control `user_input`.

**Algorithm:**
1. Determine block size (send `A`, `AA`, ... until length jumps).
2. Detect ECB (send `16 × "A"` → repeated blocks).
3. For each secret byte:
   - Align it to the end of a block using `pad = (BS - 1 - pos % BS)` bytes of filler.
   - Try all 256 candidates for the next byte, compare first block of ciphertext.

**Full implementation:**

```python
BLOCK_SIZE = 16

def ecb_byte_at_a_time(oracle, prefix_len=0, max_len=512):
    """
    oracle: function(user_input: bytes) -> ciphertext.
    prefix_len: length of any known prefix (e.g., header) before user_input.
    """
    recovered = b""
    for _ in range(max_len):
        # How much filler to align target byte at end of a block?
        pad_len = (BLOCK_SIZE - 1 - (prefix_len + len(recovered)) % BLOCK_SIZE) % BLOCK_SIZE
        filler = b"A" * pad_len
        target_ct = oracle(filler)
        block_idx = (prefix_len + len(recovered)) // BLOCK_SIZE

        # Try all 256 possible next bytes
        found = False
        for b in range(256):
            guess = filler + recovered + bytes([b])
            guess_ct = oracle(guess)
            if guess_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE] == \
               target_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]:
                recovered += bytes([b])
                found = True
                break
        if not found:
            break
    return recovered

# Local test
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
SECRET = b"FLAG{ecb_is_broken}"

def oracle(user_input):
    return AES.new(b"YELLOW_SUBMARINE", AES.MODE_ECB).encrypt(
        pad(user_input + SECRET, BLOCK_SIZE))

print(ecb_byte_at_a_time(oracle))   # b"FLAG{ecb_is_broken}"
```

**Cost:** 256 oracle calls per byte, so `256 × len(secret)` total. For a 32-byte secret → 8192 calls → seconds over HTTP.

### 1.6 Attack 4 — Block reordering / cut-and-paste

If a cookie is `AES_ECB(user || role || padding)`:
- Ciphertext blocks: `[C_user1] [C_user2] [C_admin] [C_pad]`
- Swap `[C_admin]` into the role position → server sees `admin`.

```python
def swap_blocks(ct: bytes, i: int, j: int, block_size=16) -> bytes:
    """Swap blocks i and j in the ciphertext."""
    blocks = [ct[k:k+block_size] for k in range(0, len(ct), block_size)]
    blocks[i], blocks[j] = blocks[j], blocks[i]
    return b"".join(blocks)
```

### 1.7 When to use

- **ECB challenge:** always try byte-at-a-time first — it's the intended attack.
- **Visual challenge** (encrypted image): display it.
- **Cookie with role/username:** block reordering / cut-and-paste.

---

## 2. CBC — Cipher Block Chaining

### 2.1 Description

```
C_0 = IV
C_i = E(K, P_i ⊕ C_{i-1})       for i ≥ 1
P_i = D(K, C_i) ⊕ C_{i-1}
```

Each plaintext block is XORed with the **previous ciphertext block** before encryption. IV required for first block.

```
P_1 ⊕ IV → [AES_K] → C_1
P_2 ⊕ C_1 → [AES_K] → C_2
P_3 ⊕ C_2 → [AES_K] → C_3
```

**Encryption: sequential. Decryption: parallelizable** (each `P_i` needs `C_i` and `C_{i-1}`).

**IV must be:**
- **Random** (or unpredictable)
- **Unique per message**
- **Not secret** (can be prepended to ciphertext)

**Padding:** PKCS#7 (or others).

### 2.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **IV manipulation** | Flip bits in first plaintext block without corrupting anything else |
| 2 | **Bit-flipping** | Flip a bit in `C_{i-1}` → flip corresponding bit in `P_i` (but **corrupts `P_{i-1}`**) |
| 3 | **Padding oracle** | If server leaks padding validity → recover plaintext + forge |
| 4 | **IV reuse** | First-block deterministic |
| 5 | **No integrity** | Malleable — attacker can modify data |

**CBC is safer than ECB** but still vulnerable to **active attacks**.

### 2.3 Attack 1 — Bit-flipping ⭐

**Goal:** change `P_i` byte from `old` to `new` by modifying `C_{i-1}`.

**Math:**
```
P_i = D(K, C_i) ⊕ C_{i-1}
P'_i = D(K, C_i) ⊕ C'_{i-1}
⟹ P'_i = P_i ⊕ C_{i-1} ⊕ C'_{i-1}
```

So: `C'_{i-1} = C_{i-1} ⊕ (P_i ⊕ P'_i)`.

**Drawback:** `P_{i-1} = D(K, C_{i-1}) ⊕ C_{i-2}` becomes garbage (because `C_{i-1}` changed → `D(K, C'_{i-1})` is random).

**IV manipulation** avoids the drawback: modify `IV` → affects only `P_1`, nothing else.

**Script:**

```python
def cbc_bitflip(ct: bytes, block_idx: int, p_old: bytes, p_new: bytes,
                block_size=16, iv_prepended=True) -> bytes:
    """
    Change block `block_idx` plaintext from p_old to p_new.
    block_idx is 0-based for plaintext blocks (P_0, P_1, ...).
    iv_prepended: if IV is the first block of `ct`, adjust offset.
    """
    assert len(p_old) == len(p_new) == block_size
    out = bytearray(ct)

    if block_idx == 0:
        # Modify IV directly
        iv_start = 0 if not iv_prepended else 0
        for i in range(block_size):
            out[iv_start + i] ^= p_old[i] ^ p_new[i]
    else:
        # Modify C_{block_idx-1}
        prev_start = block_idx * block_size
        if iv_prepended:
            prev_start += block_size
        for i in range(block_size):
            out[prev_start - block_size + i] ^= p_old[i] ^ p_new[i]

    return bytes(out)


# Concrete example
ct = iv + c1 + c2      # IV prepended
# Change "role=guest\x00\x00\x00\x00\x00\x00" to "role=admin\x00\x00\x00\x00\x00\x00" in block 1
p_old = b"role=guest\x00\x00\x00\x00\x00\x00"   # 16 bytes
p_new = b"role=admin\x00\x00\x00\x00\x00\x00"
new_ct = cbc_bitflip(ct, block_idx=1, p_old=p_old, p_new=p_new)
```

**When to use:** cookies, tokens, session IDs, anything with `AES_CBC(plaintext)` where you know part of the plaintext.

### 2.4 Attack 2 — IV manipulation (first block only)

Simpler than general bit-flipping: if you only need to modify **the first block**, modify the IV directly — nothing is corrupted.

```python
def iv_flip(iv: bytes, p_old: bytes, p_new: bytes) -> bytes:
    """Modify IV to change first plaintext block."""
    return bytes(a ^ b ^ c for a, b, c in zip(iv, p_old, p_new))
```

### 2.5 Attack 3 — Padding oracle ⭐⭐

**Setup:** server decrypts `AES_CBC(ct)` and returns **"padding error"** vs **"other error"** (or success vs failure).

**Impact:** recover **all plaintext** byte-by-byte, forge **valid ciphertexts**.

**Algorithm (per block):**

For each ciphertext block `C_i` with previous block `C_{i-1}`:
1. For `j = 15` downto `0` (last byte to first):
   - Target padding value is `p = 16 - j` (i.e., 0x01, 0x02, ..., 0x10).
   - Set known bytes to produce `p` padding.
   - Try all 256 values for `C_{i-1}[j]` until oracle says "valid".
   - Recovered `P_i[j] = guess ^ p ^ C_{i-1}[j]`.

**Full implementation:**

```python
def padding_oracle_attack(oracle, ct: bytes, block_size=16, iv=None):
    """
    oracle: function(ciphertext_bytes) -> True iff padding is valid.
    ct: ciphertext WITHOUT IV (or with IV; see below).
    iv: IV (16 bytes) or None if first block of ct.
    """
    if iv is None:
        iv = ct[:block_size]
        ct = ct[block_size:]

    plaintext = b""
    prev_block = iv

    for i in range(0, len(ct), block_size):
        current_block = ct[i:i+block_size]
        recovered = bytearray(block_size)

        for j in range(block_size - 1, -1, -1):
            pad_val = block_size - j

            # Set all known bytes (after j) to produce `pad_val` in plaintext
            test_prev = bytearray(prev_block)
            for k in range(j + 1, block_size):
                test_prev[k] = recovered[k] ^ pad_val

            # Try all 256 values for byte j
            found = False
            for guess in range(256):
                test_prev[j] = guess
                test_ct = bytes(test_prev) + current_block
                if oracle(test_ct):
                    # Edge case: if pad_val == 1, we might have hit 0x02 0x02
                    # by accident. Verify by changing byte j-1.
                    if pad_val == 1:
                        # Additional check: flip byte j-1 and see if still valid
                        if j > 0:
                            test_prev2 = bytearray(test_prev)
                            test_prev2[j-1] ^= 0x01
                            test_ct2 = bytes(test_prev2) + current_block
                            if oracle(test_ct2):
                                # Not a real 0x01 padding — skip
                                continue
                    recovered[j] = guess ^ pad_val
                    found = True
                    break
            if not found:
                raise ValueError(f"Padding oracle failed at block {i}, byte {j}")

        plaintext += bytes(recovered)
        prev_block = current_block

    return plaintext


# Local test: simulate a padding oracle
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b"YELLOW_SUBMARINE"
IV = b"0" * 16
SECRET = b"FLAG{padding_oracle_works!}" + b"X" * 5   # 31 bytes

def oracle(ct_blocks):
    """Server returns True iff padding is valid."""
    try:
        pt = AES.new(KEY, AES.MODE_CBC, iv=IV).decrypt(ct_blocks)
        unpad(pt, 16)
        return True
    except ValueError:
        return False

# Generate ciphertext
ct = AES.new(KEY, AES.MODE_CBC, iv=IV).encrypt(pad(SECRET, 16))
print(padding_oracle_attack(oracle, ct, iv=IV))
```

**When to use:** server distinguishes padding errors. **Very common in CTF** (e.g., "Killer Queen", "Bleichenbacher"-style tasks).

### 2.6 Attack 4 — IV reuse

If two messages use the **same IV** and the same key, the first block is deterministic:
```
C_1 = E(K, P_1 ⊕ IV)
C_1' = E(K, P_1' ⊕ IV)
```
If `P_1 = P_1'` → `C_1 = C_1'`. Also enables **first-block two-time pad** if attacker controls IV or knows it.

### 2.7 When to use

- **Cookie/token with known plaintext structure:** bit-flip.
- **Server distinguishes padding errors:** padding oracle.
- **First-block only:** IV manipulation (avoids corrupting `P_{i-1}`).
- **No padding oracle, no known structure:** really hard — CBC is genuinely secure for confidentiality.

---

## 3. CFB — Cipher Feedback

### 3.1 Description

CFB turns AES into a **self-synchronizing stream cipher**. Encrypts `s` bits at a time (typically `s = 8` or `s = 128`).

**Full-block CFB (CFB-128):**
```
C_i = P_i ⊕ E(K, C_{i-1})       with C_0 = IV
P_i = C_i ⊕ E(K, C_{i-1})
```

**s-bit CFB (e.g., s=8):**
```
O_i = E(K, IV_i)              (encrypt IV / previous ciphertext)
C_i = P_i ⊕ MSB_s(O_i)
IV_{i+1} = (IV_i << s) | C_i   (shift in s bits of ciphertext)
```

**Note:** **encryption uses E, not D**. This is because CFB is a stream cipher — decryption also uses E (with the same keystream).

### 3.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Bit-flipping** | Flip bits in `C_i` → flip corresponding bits in `P_i` AND `P_{i+1}` (self-sync) |
| 2 | **IV reuse** | First block deterministic |
| 3 | **Error propagation** | One corrupt block corrupts next block too |
| 4 | **No integrity** | Malleable |

**CFB propagates errors differently from CBC:**
- CBC: corrupt `C_i` → corrupts `P_i` (random) **and** `P_{i+1}` (bit-flipped).
- CFB: corrupt `C_i` → corrupts `P_i` (bit-flipped) **and** `P_{i+1}` (random).
- OFB/CTR: corrupt `C_i` → corrupts `P_i` **only**.

### 3.3 Attack 1 — Bit-flipping

**CFB bit-flip:** modifying `C_i` changes `P_i` (predictably) but **also propagates to `P_{i+1}`**.

```python
def cfb_bitflip(ct: bytes, pos: int, old_byte: int, new_byte: int) -> bytes:
    """Flip byte at `pos` from old_byte to new_byte in plaintext."""
    out = bytearray(ct)
    out[pos] ^= old_byte ^ new_byte
    return bytes(out)
```

**Advantage over CBC:** no padding needed, stream-like.

**Disadvantage:** next block gets corrupted (random garbage in next block).

**When usable:** if the corrupted block is in an **unimportant field** (e.g., a comment, metadata, trailing data).

### 3.4 Attack 2 — IV reuse / fixed IV

If IV is **fixed** (in code) or **reused**, first block is deterministic:
```
C_1 = P_1 ⊕ E(K, IV)
C_1' = P_1' ⊕ E(K, IV)
C_1 ⊕ C_1' = P_1 ⊕ P_1'     ← two-time pad
```

### 3.5 When to use

- **CFB with known next block "junk" (e.g., padding that gets ignored):** bit-flip.
- **CFB-8 with same IV:** first-block two-time pad.
- **Rare in CTF** — CFB is less common than CBC/CTR.

---

## 4. OFB — Output Feedback

### 4.1 Description

OFB is a **stream cipher mode** — keystream is generated by repeatedly encrypting the IV.

```
O_0 = IV
O_i = E(K, O_{i-1})              (keystream block i)
C_i = P_i ⊕ O_i
P_i = C_i ⊕ O_i
```

**Key properties:**
- **Encryption uses E only** (not D).
- **IV is a nonce** — must NEVER reuse (because keystream is fixed by `(K, IV)`).
- **No error propagation** — corrupt `C_i` affects only `P_i`.
- **Parallelizable** (precompute keystream).

### 4.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Malleability** | Bit-flip directly translates to plaintext bit-flip |
| 2 | **IV reuse** | Keystream reuse → two-time pad |
| 3 | **No integrity** | Zero malleability protection |

**OFB is essentially a stream cipher** — everything from the XOR / OTP / Salsa20 sections applies.

### 4.3 Attack — Malleability

```python
def ofb_bitflip(ct: bytes, p_old: bytes, p_new: bytes, offset: int = 0) -> bytes:
    """Change plaintext from p_old to p_new by XORing ciphertext."""
    assert len(p_old) == len(p_new)
    out = bytearray(ct)
    for i, (a, b) in enumerate(zip(p_old, p_new)):
        out[offset + i] ^= a ^ b
    return bytes(out)
```

**Identical to CTR / stream cipher malleability.**

### 4.4 Attack — IV reuse

If IV reused with same key:
```
C_i = P_i ⊕ O_i
C_i' = P_i' ⊕ O_i
C_i ⊕ C_i' = P_i ⊕ P_i'
```

Full two-time pad attack.

### 4.5 When to use

- **OFB challenge:** look for **fixed IV** or **reused IV**.
- If IV is random and unique, **OFB is secure** (for confidentiality).
- **Rare in CTF** — OFB is less common than CTR.

---

## 5. CTR — Counter Mode ⭐ (most common in CTF)

### 5.1 Description

CTR turns AES into a **parallelizable stream cipher**.

```
keystream_i = E(K, nonce || counter_i)
C_i = P_i ⊕ keystream_i
P_i = C_i ⊕ keystream_i
```

Where `counter_i` increments for each block (typically `counter_0 = 0` or `counter_0 = 1`).

**Common layouts:**
- **NIST SP 800-38A:** `counter` = entire 128-bit block (but typically split into `nonce || counter`).
- **PyCryptodome:** `nonce` = 8 bytes, `counter` = 8 bytes.
- **GCM/CCM:** `nonce` = 12 bytes, `counter` = 4 bytes.

**Properties:**
- **Encryption uses E only.**
- **Parallelizable** (encrypt all counters in advance).
- **Random access** (decrypt block `i` without decrypting `1..i-1`).
- **No padding required** (stream cipher).
- **Nonce MUST be unique** — if reused, catastrophic.

### 5.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Nonce reuse** | Same keystream → two-time pad ⭐⭐⭐ |
| 2 | **Malleability** | Bit-flip directly translates |
| 3 | **Counter overflow** | After 2^(counter_bits) blocks, keystream repeats |
| 4 | **No integrity** | Zero protection |

**Nonce reuse is THE attack** — this is **Noncense**.

### 5.3 Attack 1 — Nonce reuse (two-time pad) ⭐⭐⭐

**This is Noncense.** Same `(key, nonce)` → same keystream:
```
c1 ⊕ c2 = p1 ⊕ p2
```

**Script — nonce reuse with known plaintext:**

```python
def ctr_nonce_reuse(known_pt: bytes, known_ct: bytes, secret_ct: bytes) -> bytes:
    """Recover secret plaintext from nonce reuse with known plaintext."""
    ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))
    return bytes(c ^ k for c, k in zip(secret_ct, ks))


# Noncense-specific solve
def noncense_solve():
    c_flag = bytes.fromhex("def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c")
    c_known = bytes.fromhex("fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a")
    known_pt = b"According to all known laws of aviation, there is no way a bee should be able to fly."

    n = len(c_flag)
    p_flag = bytes(
        a ^ b ^ c
        for a, b, c in zip(c_flag, c_known[:n], known_pt[:n])
    )
    print(p_flag)
```

### 5.4 Attack 2 — Nonce reuse without known plaintext (crib dragging)

```python
def crib_drag(x: bytes, crib: bytes):
    """x = p1 ⊕ p2; find where crib matches p1."""
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if all(32 <= b < 127 or b in (9, 10, 13) for b in guess):
            yield i, guess

x = bytes(a ^ b for a, b in zip(c1, c2))
for pos, frag in crib_drag(x, b"cns{"):
    print(f"pos {pos}: p2[{pos}:] = {frag!r}")
```

### 5.5 Attack 3 — Bit-flipping

Same as OFB:

```python
def ctr_bitflip(ct: bytes, p_old: bytes, p_new: bytes, offset: int = 0) -> bytes:
    out = bytearray(ct)
    for i, (a, b) in enumerate(zip(p_old, p_new)):
        out[offset + i] ^= a ^ b
    return bytes(out)
```

**Common in Secure Bank-style tasks:** change `amount` / `from_account` / `role` in a JSON or cookie.

### 5.6 Attack 4 — Nonce reuse across sessions

If a server uses **counter-based nonce starting at 0**:
- After reboot → nonce `0` reused → keystream reused.
- Multiple sessions → nonce `0` reused each time.

**Detection:** connect twice, collect ciphertexts of the same plaintext → if identical, nonce is reused.

```python
def detect_nonce_reuse(ct_list: list[bytes]) -> bool:
    """If any two ciphertexts are identical, nonce is reused (assuming plaintext differs)."""
    return len(ct_list) != len(set(ct_list))
```

### 5.7 When to use

- **Noncense:** direct nonce reuse.
- **Any AES-CTR challenge:** check nonce first.
- **Nonce is `counter.to_bytes(8, "little")`:** check for reboot / reset.
- **Nonce is `secrets.token_bytes(8)`:** secure.

---

## 6. XTS-AES — XEX Tweakable Codebook with Ciphertext Stealing

### 6.1 Description

**XTS-AES is designed for disk encryption** (data-at-rest). Unlike other modes, it doesn't need an IV/nonce per message — instead it uses a **tweak** (usually the **sector number**).

**Structure (per block `j` in sector `i`):**

```
T = AES(K2, i) · α^j                     (tweak = sector number × α^j in GF(2^128))
C_j = AES(K1, P_j ⊕ T) ⊕ T
P_j = AES(K1, C_j ⊕ T) ⊕ T
```

Where:
- `K1, K2` = **two AES keys** (key length = 2 × AES key = 256 or 512 bits).
- `i` = **sector number** (tweak).
- `j` = **block index within sector**.
- `α` = primitive element of GF(2¹²⁸) (polynomial `x`).

**Key properties:**
- **Same plaintext at different positions → different ciphertext** (due to tweak `j`).
- **Same plaintext in different sectors → different ciphertext** (due to tweak `i`).
- **Random access** (encrypt/decrypt block `j` independently).
- **Ciphertext stealing** for partial last block (avoid padding).
- **Two keys** → key length 256 or 512 bits (**no AES-128 XTS**).

### 6.2 Vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Tweak reuse** | Same plaintext at same `(i, j)` → same ciphertext |
| 2 | **Sector reordering** | Attacker can move sectors → wrong data at wrong location |
| 3 | **Ciphertext stealing bugs** | Incorrect implementation leaks data |
| 4 | **No integrity** | Malleable (but limited — flipping a bit corrupts a whole block) |
| 5 | **Key separation** | If K1 = K2 → reduced security |

### 6.3 Attack 1 — Sector reordering (the classic)

If disk encryption uses XTS-AES with **sector number = tweak**:
- Attacker **swaps two sectors** → data appears at wrong location.
- This is **the same plaintext, different location**, so ciphertext matches — but it's **wrong for the filesystem**.

**Impact:** replace an admin file with a guest file. Server reads admin file from wrong sector → sees guest content (or vice versa).

**Not a direct plaintext recovery** — it's a **semantic attack**.

### 6.4 Attack 2 — Tweak reuse (misuse)

If the same `(K1, K2, i)` pair is used for two different messages (i.e., same sector number for different data), then same plaintext block at same `j` → same ciphertext.

**Rare in practice** — sector numbers are unique.

### 6.5 Attack 3 — Ciphertext stealing bugs

**Ciphertext stealing** is complex. Implementation bugs include:
- **Off-by-one errors** in last two blocks.
- **Wrong α power** for last block.
- **Incorrect handling of partial block** (0–15 bytes).

**Impact:** decrypt incorrectly, or **leak** structure.

**Not a practical CTF attack** — need the exact implementation.

### 6.6 Attack 4 — Key separation (K1 = K2)

If `K1 = K2`, security is reduced. XTS-AES with `K1 = K2` is **not standard** — NIST requires `K1 ≠ K2`.

**Rare**, but check: if key is 32 bytes (256-bit), it's **one key**; if 64 bytes (512-bit), it's **two keys**.

### 6.7 When to use

- **XTS-AES challenges are rare in CTF** — it's a disk-encryption mode.
- **Not in your session tasks.**
- If you see it: check **sector number handling**, **tweak**, **ciphertext stealing**.
- **Not directly breakable** if properly implemented.

---

## 7. Choosing the attack — decision tree

```
Input is ciphertext.
│
├── Same PT block → same CT block?
│     └── YES → ECB
│            ├── Have oracle with user input? → byte-at-a-time
│            ├── Cookie with role? → block reorder
│            └── Encrypted image? → visualize
│
├── Can flip one bit in PT by flipping one bit in CT?
│     └── YES → Stream-like: CFB / OFB / CTR
│            ├── Nonce reuse → two-time pad
│            └── Malleability → bit-flip
│
├── Flipping byte in C_{i-1} changes byte in P_i?
│     └── YES → CBC
│            ├── Server leaks padding errors? → padding oracle
│            ├── Known plaintext structure? → bit-flip
│            └── Only first block? → IV manipulation
│
└── Unknown / disk / sector-based?
      └── XTS-AES (very rare in CTF)
```

**In practice for CTF:**
1. **Check if ECB** (repeated blocks) → byte-at-a-time or block reorder.
2. **Check if stream-like** (malleable) → CTR/OFB/CFB → bit-flip or nonce reuse.
3. **Check if CBC** (padding errors) → padding oracle or bit-flip.
4. **XTS** → skip (rare).

---

## 8. Mode-specific pitfalls (the "gotchas")

### 8.1 ECB
- **PKCS#7 padding** — remember to strip it.
- **Last block** may be a full padding block (0x10 × 16) — always present.

### 8.2 CBC
- **IV is separate** from ciphertext — don't forget to include/exclude it.
- **PKCS#7 padding** — same as ECB.
- **Padding oracle edge cases:**
  - `pad_val == 1` → can match accidentally (0x02 0x02 vs 0x01).
  - **Last block** may be full padding block.
- **Bit-flip corrupts previous block** — if you can't tolerate that, use IV.

### 8.3 CFB
- **Segment size `s`** matters: CFB-8, CFB-128 behave differently.
- **Encryption uses E, not D** (unlike CBC).
- **Error propagation:** corrupt block → corrupts current (bit-flip) AND next (random).

### 8.4 OFB
- **IV is a nonce** — same as CTR.
- **No error propagation** — cleanest stream cipher.
- **Same PT → same CT** if IV reused → detection.

### 8.5 CTR
- **Nonce must be unique** across all messages with the same key.
- **Counter overflow:** if counter is 32-bit, after 2³² blocks → wrap. Never happens in practice.
- **Nonce reuse is catastrophic:** `c1 ⊕ c2 = p1 ⊕ p2`.
- **Library nonce sizes:** PyCryptodome `AES.MODE_CTR` uses `nonce=` (8 bytes by default) + counter (8 bytes).

### 8.6 XTS-AES
- **Requires 2 keys** (256 or 512 bit total) — no XTS-AES-128.
- **Tweak** = sector number (must be unique per sector).
- **Ciphertext stealing** for partial last block — no padding.
- **Not for network encryption** — designed for disk.

---

## 9. Full comparison: attack scripts by mode

| Mode | Attack | Function |
|---|---|---|
| ECB | Detect | `detect_ecb(ct)` |
| ECB | Byte-at-a-time | `ecb_byte_at_a_time(oracle)` |
| ECB | Block reorder | `swap_blocks(ct, i, j)` |
| CBC | Bit-flip | `cbc_bitflip(ct, idx, p_old, p_new)` |
| CBC | IV manipulation | `iv_flip(iv, p_old, p_new)` |
| CBC | Padding oracle | `padding_oracle_attack(oracle, ct)` |
| CFB | Bit-flip | `cfb_bitflip(ct, pos, old, new)` |
| OFB | Bit-flip | `ofb_bitflip(ct, p_old, p_new, offset)` |
| OFB | IV reuse | `xor_two(c1, c2)` + crib drag |
| CTR | Nonce reuse | `ctr_nonce_reuse(known_pt, known_ct, secret_ct)` |
| CTR | Bit-flip | `ctr_bitflip(ct, p_old, p_new, offset)` |
| CTR | Detect reuse | `detect_nonce_reuse(ct_list)` |
| XTS | Sector reorder | Manual (swap sectors) |

---

## 10. Mapping to session tasks

| Task | AES Mode | Attack |
|---|---|---|
| **Noncense** | **CTR** | **Nonce reuse → keystream → decrypt flag** (§5.3) |
| **AES 2 demo** | **ECB** (double) | MITM (§7 of AES section) |
| **Secure Bank** | N/A (Salsa20) | Malleability (same as CTR) |
| **Secure Bank 2** | N/A (SHA-256) | Birthday |
| **Better Hash** | N/A | Reversible hash |
| **Signed, Sealed** | N/A (HMAC) | JSON canonicalization |
| **Token of Trust** | N/A (JWT) | `alg:none` / weak key |
| **Security Cam** | N/A (RTSP) | MD5 dictionary |
| **Replanting** | N/A (LCG) | Seed brute force |
| **Dutch Exclusivity** | N/A (XOR) | Known key |
| **Key standardisation** | N/A (DES) | Prefix brute force |

**Only Noncense (CTR) and AES 2 demo (ECB) use AES modes.**

---

## 11. When a challenge says "AES" — read the code

```python
# 1) Look at mode
mode = AES.MODE_ECB  # → ECB → byte-at-a-time?
mode = AES.MODE_CBC  # → CBC → bit-flip / padding oracle?
mode = AES.MODE_CTR  # → CTR → check nonce reuse!
mode = AES.MODE_CFB  # → CFB → bit-flip
mode = AES.MODE_OFB  # → OFB → bit-flip / IV reuse
mode = AES.MODE_GCM  # → AEAD → nonce reuse (harder)

# 2) Look at nonce/IV generation
nonce = secrets.token_bytes(8)      # secure
nonce = b"\x00" * 8                 # FIXED → nonce reuse!
nonce = counter.to_bytes(8, "little")  # counter → check reset
iv = os.urandom(16)                 # secure
iv = b"\x00" * 16                   # FIXED → first block reused

# 3) Look at what's authenticated
# No MAC → malleable (all modes except GCM/CCM)
# HMAC appended → safe (if MAC-then-encrypt, padding oracle risk)
```

---

## 12. Ready-to-use `aes_modes_toolkit.py`?

Options:

- **A)** Build `aes_modes_toolkit.py` with all mode-specific attacks:
  ```
  # Detection
  - detect_ecb(ct)
  - detect_nonce_reuse(ct_list)
  
  # ECB
  - ecb_byte_at_a_time(oracle, prefix_len=0)
  - swap_blocks(ct, i, j)
  
  # CBC
  - cbc_bitflip(ct, block_idx, p_old, p_new)
  - iv_flip(iv, p_old, p_new)
  - padding_oracle_attack(oracle, ct)
  
  # CFB / OFB / CTR (stream-like)
  - stream_bitflip(ct, p_old, p_new, offset=0)
  - ctr_nonce_reuse(known_pt, known_ct, secret_ct)
  - xor_two(c1, c2)
  - crib_drag(x, crib)
  ```
  + CLI:
  ```
  python aes_modes_toolkit.py detect       --ct hex
  python aes_modes_toolkit.py ecb-bite     --oracle-url ...
  python aes_modes_toolkit.py cbc-flip     --ct hex --old hex --new hex --block 1
  python aes_modes_toolkit.py padding      --oracle-url ...
  python aes_modes_toolkit.py nonce-reuse  --c1 hex --c2 hex --pt "..."
  ```