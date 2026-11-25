# AES (AES-128 / AES-192 / AES-256): Theory, All Cases, Scripts

AES (Advanced Encryption Standard) is the **modern block cipher standard**, selected by NIST in 2000 (Rijndael, by Daemen & Rijmen), standardized as FIPS 197 in 2001. It's **cryptographically strong by design** — no practical attack on AES exists. **Every real-world failure is a mode-of-operation bug, implementation bug, or key management mistake.**

AES is the engine behind **Noncense** (AES-CTR nonce reuse) and **AES 2 demo** (double AES with 20-bit keys). This section covers both, plus all other relevant cases.

---

## 1. What is AES (formally)

AES is a **substitution-permutation network (SPN)**, **not** a Feistel network (unlike DES). It operates on a **4×4 byte matrix** (128-bit state).

### 1.1 Parameters

| Variant | Key size | Rounds | Round keys |
|---|---|---|---|
| **AES-128** | 128 bits (16 bytes) | **10** | 11 × 128-bit |
| **AES-192** | 192 bits (24 bytes) | **12** | 13 × 128-bit |
| **AES-256** | 256 bits (32 bytes) | **14** | 15 × 128-bit |

**Block size: always 128 bits (16 bytes).** Only the key size varies.

### 1.2 State layout

Input block = 16 bytes → 4×4 matrix in **column-major** order:

```
Input:   b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15

State:
[ b0  b4  b8   b12 ]
[ b1  b5  b9   b13 ]
[ b2  b6  b10  b14 ]
[ b3  b7  b11  b15 ]
```

### 1.3 Round structure

Each round (except the last) applies **four operations**:

```
┌─────────────────────────────────────┐
│  1. SubBytes:    S-box substitution │
│  2. ShiftRows:   cyclic row shifts  │
│  3. MixColumns:  GF(2⁸) matrix mult │
│  4. AddRoundKey: XOR with round key │
└─────────────────────────────────────┘
```

**First round**: `AddRoundKey` only (round 0).
**Last round**: `SubBytes`, `ShiftRows`, `AddRoundKey` — **no MixColumns**.

### 1.4 SubBytes (S-box)

Byte-wise nonlinear substitution using a **16×16 lookup table** (256 entries). The S-box is built from:
1. **Multiplicative inverse** in GF(2⁸) (with `0 → 0`).
2. **Affine transformation** (bit matrix + constant `0x63`).

**Rationale:** no fixed points, no linear relationship, invertible.

### 1.5 ShiftRows

Cyclic left-shifts of rows:

```
Row 0: no shift
Row 1: shift left by 1
Row 2: shift left by 2
Row 3: shift left by 3
```

**Purpose:** diffuse bytes across columns (so MixColumns mixes across rows).

### 1.6 MixColumns

Each column is multiplied by a fixed matrix in **GF(2⁸)**:

```
[s'0]   [02  03  01  01] [s0]
[s'1] = [01  02  03  01] [s1]
[s'2]   [01  01  02  03] [s2]
[s'3]   [03  01  01  02] [s3]
```

**Purpose:** full diffusion within each column.

### 1.7 AddRoundKey

XOR with the 128-bit round key:
```
state = state ⊕ round_key
```

**Only step that uses the key.** All other steps are key-independent (public).

### 1.8 Key schedule

Expands the master key into `4 × (Nr+1)` 32-bit **words** (Nr = 10/12/14):

```
AES-128: 4 words → 44 words   (11 round keys × 4)
AES-192: 6 words → 52 words   (13 round keys × 4)
AES-256: 8 words → 60 words   (15 round keys × 4)
```

Each round key = 4 consecutive words.

### 1.9 Python implementation (PyCryptodome)

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ECB
key = bytes(16)   # AES-128
cipher = AES.new(key, AES.MODE_ECB)
ct = cipher.encrypt(pad(b"plaintext", 16))
pt = unpad(cipher.decrypt(ct), 16)

# CBC
iv = bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv=iv)

# CTR
nonce = bytes(8)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

# GCM
nonce = bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
```

### 1.10 AES-128 vs AES-192 vs AES-256

**Conventional wisdom says AES-256 > AES-192 > AES-128** (bigger key = more secure). **In practice:**

- **AES-128 is already secure** (2¹²⁸ brute force infeasible).
- **AES-256 has a theoretical concern**: related-key attacks (Biryukov–Khovratovich 2009) — but only in **related-key model**, not applicable to standard use.
- **AES-256 is slower** on some CPUs (14 rounds vs 10).
- **AES-128 is sufficient** for almost everything.
- **AES-256 is required** for:
  - Top Secret / classified government (NSA Suite B).
  - Long-term storage (>30 years).
  - Post-quantum resistance (Grover: AES-128 → 2⁶⁴ quantum, AES-256 → 2¹²⁸ quantum).

**For CTF**: the variant doesn't matter — the attack is on the **mode** or **key management**, not on the cipher itself.

---

## 2. Security requirements — and where AES fails

AES **itself** is secure. **All practical failures are outside the cipher:**

| Property | AES status | Why |
|---|---|---|
| Confusion | ✅ | S-box |
| Diffusion | ✅ | ShiftRows + MixColumns |
| Round count | ✅ | 10/12/14 rounds |
| Key space | ✅ | 128/192/256 bits |
| Known attacks | ❌ (none practical) | Only reduced-round |
| **ECB mode** | ❌ | Deterministic |
| **CBC/CTR with fixed IV/nonce** | ❌ | Reuse attacks |
| **No authentication** | ❌ | Malleability |
| **Key management** | ❌ | Weak keys, weak KDF |
| **Implementation** | ❌ | Side channels (timing, cache, power) |
| **Library confusion** | ❌ | Wrong mode/parameters |

**Golden rule:** *"AES is secure. The people using AES are not."*

---

## 3. Attack taxonomy

| # | Attack | Input needed | Difficulty |
|---|---|---|---|
| 1 | **Known key → decrypt** | Key + ciphertext | Trivial |
| 2 | **Short key brute force** | (p, c) + small key | Seconds–hours |
| 3 | **Prefix brute force** | Known prefix + (p, c) | Seconds |
| 4 | **Double AES meet-in-the-middle** | (p, c) + short keys | Minutes–hours (**AES 2 demo**) |
| 5 | **ECB detection** | Two ciphertexts | Trivial |
| 6 | **ECB byte-at-a-time** | Oracle access | Easy |
| 7 | **CBC bit-flipping** | Known structure | Trivial |
| 8 | **CBC padding oracle** | Oracle access | Medium |
| 9 | **CTR nonce reuse** | Two ciphertexts, same nonce | Easy (**Noncense**) |
| 10 | **GCM/CCM nonce reuse** | Two AEAD ciphertexts, same nonce | Medium |
| 11 | **Weak KDF (MD5/SHA256 directly)** | Password-derived key | Minutes |
| 12 | **Side-channel (timing, cache)** | Physical access | Advanced |
| 13 | **Library confusion** | Code audit | Common |
| 14 | **Related-key attack** | Related keys | Academic only |
| 15 | **Full AES-128 brute force** | 2¹²⁸ | Infeasible |

**Cases 1–10 are the CTF-relevant ones.**

---

## 4. Case 1: Known key → decrypt (the easy case)

### Description
If you have the key, just decrypt.

### Script
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_decrypt(key: bytes, ct: bytes, mode="ECB", iv=None, nonce=None) -> bytes:
    if mode == "ECB":
        return unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
    if mode == "CBC":
        return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
    if mode == "CTR":
        return AES.new(key, AES.MODE_CTR, nonce=nonce).decrypt(ct)
    if mode == "CFB":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
    if mode == "OFB":
        return AES.new(key, AES.MODE_OFB, iv=iv).decrypt(ct)
    raise ValueError(f"Unknown mode: {mode}")

# Example
print(aes_decrypt(key=bytes(16), ct=bytes(16), mode="ECB"))
```

### When to use
- Challenge gives you the key (Base64/hex-encoded).
- **Sanity check** — before assuming you need an attack.

---

## 5. Case 2: Short key brute force

### Description
Key is short (≤ 24 bits) → brute force.

### Script
```python
from Crypto.Cipher import AES

def brute_aes_short(known_pt: bytes, known_ct: bytes,
                    key_bits: int = 20, key_prefix: bytes = b"") -> bytes | None:
    """Brute-force AES with short key (prefix + suffix)."""
    suffix_bytes = (key_bits + 7) // 8
    for i in range(1 << key_bits):
        key = key_prefix + i.to_bytes(suffix_bytes, "big")
        key = key.ljust(16, b"\x00")[:16]   # AES-128
        if AES.new(key, AES.MODE_ECB).encrypt(known_pt[:16]) == known_ct[:16]:
            return key
    return None
```

### When to use
- Key = `b"prefix" + i.to_bytes(2)` → 2¹⁶.
- Key = random `≤ 24 bits`.
- **Not** for full 128-bit keys (2¹²⁸ = impossible).

---

## 6. Case 3: Prefix brute force (like Key standardisation, but AES)

### Description
Key has known prefix: `key = b"COMPANY_" + unknown_8_bytes` → 2⁶⁴ (too much).
If prefix is **24 bytes** and unknown is **8 bytes** → 2⁶⁴ (too much).
If prefix is **28 bytes** → 2³² (feasible, hours).

### Script
```python
def brute_aes_prefix(known_pt: bytes, known_ct: bytes,
                     prefix: bytes, unknown_bytes: int) -> bytes | None:
    """Brute force AES with known prefix and n unknown bytes."""
    key_len = 16 if len(prefix) + unknown_bytes <= 16 else \
              24 if len(prefix) + unknown_bytes <= 24 else 32
    for i in range(1 << (8 * unknown_bytes)):
        key = prefix + i.to_bytes(unknown_bytes, "big")
        key = key.ljust(key_len, b"\x00")[:key_len]
        if AES.new(key, AES.MODE_ECB).encrypt(known_pt[:16]) == known_ct[:16]:
            return key
    return None
```

### When to use
- `Key standardisation` was DES (2¹⁶); AES analog would need 2⁴⁸+ — usually too slow.
- Only if unknown ≤ 4 bytes.

---

## 7. Case 4: Double AES meet-in-the-middle (⭐ **AES 2 demo**)

### Description
**This is the actual attack for "AES 2 demo".**

Server encrypts with:
```
C = AES(K2, AES(K1, P))
```

Where:
```
K1 = k1_small.to_bytes(3, "big") + b"\x00" * 13       # 20-bit key, 96 zero bits
K2 = k2_small.to_bytes(3, "big") + b"\x00" * 13
```

**Naive brute force**: 2²⁰ × 2²⁰ = 2⁴⁰ — too slow.

**MITM attack**: 2²⁰ + 2²⁰ = **2²¹** ≈ **2 million operations** — **minutes**.

### MITM algorithm
```
C = E(K2, E(K1, P))

1. For each k1 in [0, 2²⁰):
     build key1 = k1.to_bytes(3) + b"\x00"*13
     compute mid = E(K1, P)
     store  mid → k1  in hash table

2. For each k2 in [0, 2²⁰):
     build key2 = k2.to_bytes(3) + b"\x00"*13
     compute mid = D(K2, C)         ← decrypt from ciphertext side
     if mid in table:
          k1 = table[mid]
          verify: E(K2, E(K1, P)) == C
          return K1, K2
```

**Complexity:**
- Time: **2²¹ AES operations** (~2 minutes in Python)
- Memory: **2²⁰ entries** (~100 MB)

### Full solve script for AES 2 demo

```python
from Crypto.Cipher import AES

def mitm_double_aes(known_pt: bytes, known_ct: bytes,
                    key_bits: int = 20, key_len: int = 16) -> tuple[bytes, bytes] | None:
    """
    Meet-in-the-middle on double AES: C = E(K2, E(K1, P)).
    
    Assumes:
      - key_len: length of AES key (16 for AES-128, 32 for AES-256)
      - key_bits: effective bits of each key (rest is zero padding)
      - key = i.to_bytes(ceil(key_bits/8), "big") + b"\x00" * padding
    """
    assert len(known_pt) >= 16
    assert len(known_ct) >= 16
    pt_block = known_pt[:16]
    ct_block = known_ct[:16]
    
    space = 1 << key_bits
    key_bytes = (key_bits + 7) // 8
    pad_bytes = key_len - key_bytes
    
    # --- Step 1: forward table from P ---
    print(f"[*] Building table: {space} entries...")
    table = {}
    for k1 in range(space):
        key1 = k1.to_bytes(key_bytes, "big") + b"\x00" * pad_bytes
        mid = AES.new(key1, AES.MODE_ECB).encrypt(pt_block)
        table[mid] = key1
    print(f"[+] Table built ({len(table)} unique mids)")
    
    # --- Step 2: backward from C ---
    print(f"[*] Searching: {space} decryptions...")
    for k2 in range(space):
        key2 = k2.to_bytes(key_bytes, "big") + b"\x00" * pad_bytes
        mid = AES.new(key2, AES.MODE_ECB).decrypt(ct_block)
        if mid in table:
            key1 = table[mid]
            # Verify (in case of collision)
            test = AES.new(key2, AES.MODE_ECB).encrypt(
                AES.new(key1, AES.MODE_ECB).encrypt(pt_block))
            if test == ct_block:
                print(f"[+] Found K1={key1.hex()}, K2={key2.hex()}")
                return key1, key2
    return None


# ---- Use the actual challenge data ----
if __name__ == "__main__":
    # Promo code from the challenge
    ct_hex = (
        "df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe73824"
        "4027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a8"
        "4ffa6745294c224068e1cffd9e8c9e294"
    )
    ct = bytes.fromhex(ct_hex)
    print(f"[*] Ciphertext length: {len(ct)} bytes")
    
    # Known plaintext from BMP header (first 16 bytes of any BMP file)
    # BMP magic: 'BM' (0x42 0x4D) + 4-byte size + 2+2 reserved + 4-byte offset
    # But first 16 bytes might vary. Try BMP header of encrypted file.
    # Alternative: get known plaintext from 'enc.bmp' structure
    
    # If the file is BMP, header starts with b"BM" + ...
    # Try common first 16 bytes:
    known_pt_candidates = [
        b"BM" + b"\x00" * 14,           # partial
        b"BM\x36\x00\x00\x00\x00\x00",  # 54-byte header BM
    ]
    
    # Or: try guessing the first block of the plaintext BMP
    # BMP files typically start with:
    # 42 4D xx xx xx xx 00 00 00 00 36 00 00 00 28 00
    # (BM + size + reserved + offset + header size)
    
    # The most likely plaintext block (14-byte BMP header + 2 bytes of DIB header):
    bmp_header = bytes.fromhex("424d360000000000000036000000280000")
    print(f"[*] Trying BMP header: {bmp_header.hex()}")
    
    result = mitm_double_aes(bmp_header, ct, key_bits=20, key_len=16)
    if result:
        k1, k2 = result
        print(f"\n[+] Keys found!")
        print(f"    K1 = {k1.hex()}")
        print(f"    K2 = {k2.hex()}")
        
        # Decrypt full ciphertext
        # Note: the encryption is two AES blocks per 16-byte block
        # Decrypt: P = D(K1, D(K2, C))
        decrypted = bytearray()
        for i in range(0, len(ct), 16):
            block = ct[i:i+16]
            if len(block) < 16: break
            mid = AES.new(k2, AES.MODE_ECB).decrypt(block)
            pt = AES.new(k1, AES.MODE_ECB).decrypt(mid)
            decrypted.extend(pt)
        print(f"\n[+] Decrypted {len(decrypted)} bytes")
        print(f"    First 64 bytes: {decrypted[:64].hex()}")
        # BMP file starts with 'BM'
        if decrypted[:2] == b"BM":
            print("[+] Valid BMP header!")
            with open("decrypted.bmp", "wb") as f:
                f.write(decrypted)
            print("[+] Saved to decrypted.bmp")
```

### Why the BMP header matters

The `enc.bmp` file is a **BMP image encrypted with double AES**. The **first 16 bytes** of any BMP file have a **known/guessable structure**:

```
Offset  Size  Field
0       2     "BM" (0x42 0x4D)
2       4     File size
6       2     Reserved (0x00 0x00)
8       2     Reserved (0x00 0x00)
10      4     Pixel data offset (often 0x36)
14      4     DIB header size (often 0x28)
```

**First 16 bytes** of typical small BMP:
```
42 4D <size:4> 00 00 00 00 <offset:4> <dib_size:4>
```

If it's a **54-byte header BMP**:
```
42 4D ?? ?? ?? ?? 00 00 00 00 36 00 00 00 28 00
```

Where `??` = file size (varies) — but **bytes 6–15 are usually fixed**. So we have:
- **Byte 0–1**: `42 4D` (fixed)
- **Byte 2–5**: file size (varies, but **few candidates**)
- **Byte 6–15**: mostly fixed

**Better approach**: pick a **known plaintext block** from bytes 6–21 (fixed 16 bytes across many BMPs) — but the MITM needs **16-byte aligned block**. So we need bytes 0–15, and we need to **guess the file size**.

### Enhanced: try multiple plaintext guesses

```python
def try_bmp_headers(ct: bytes, key_bits=20):
    """Try common BMP header patterns as known plaintext."""
    # Candidate 16-byte first blocks for BMP
    # Format: 'BM' + filesize(4) + 00 00 00 00 + data_offset(4) + dib_size(4)
    candidates = []
    
    # Common sizes for small images
    for size in [0x36 + 10000, 0x36 + 50000, 0x36 + 100000, 
                 0x36 + 200000, 0x36 + 500000]:
        for offset in [0x36, 0x436]:
            for dib in [0x28, 0x6C]:
                candidate = b"BM" + size.to_bytes(4, "little") \
                            + b"\x00\x00\x00\x00" \
                            + offset.to_bytes(4, "little") \
                            + dib.to_bytes(2, "little") \
                            + b"\x00\x00"
                candidates.append(candidate)
    
    for pt in candidates:
        result = mitm_double_aes(pt, ct, key_bits=key_bits)
        if result:
            return pt, result
    return None
```

### Performance

For `key_bits=20`:
- Table build: 2²⁰ = 1,048,576 AES encryptions ≈ **60 seconds** in Python
- Table search: 2²⁰ = 1,048,576 AES decryptions ≈ **60 seconds**
- **Total: ~2 minutes per known plaintext candidate**

If you have 10 candidate plaintexts → **~20 minutes**. Parallelize with `multiprocessing` for speedup.

### Optimizations

1. **Reduce key_bits if possible**: if only part of the 20-bit key is unknown → 2^k smaller.
2. **Use `multiprocessing`**:
   ```python
   from multiprocessing import Pool
   
   def build_chunk(args):
       start, end, pt_block = args
       result = {}
       for k1 in range(start, end):
           key = k1.to_bytes(3, "big") + b"\x00" * 13
           result[AES.new(key, AES.MODE_ECB).encrypt(pt_block)] = k1
       return result
   
   def parallel_mitm(known_pt, known_ct, key_bits=20, n_proc=8):
       space = 1 << key_bits
       chunk = space // n_proc
       ranges = [(i*chunk, (i+1)*chunk, known_pt[:16]) for i in range(n_proc)]
       with Pool(n_proc) as p:
           tables = p.map(build_chunk, ranges)
       merged = {}
       for t in tables:
           merged.update(t)
       # Now search k2...
   ```
3. **Use `pycryptodomex` raw AES** (faster than high-level API).
4. **Use `cryptography` library** (OpenSSL-backed, faster).

### When to use
- **AES 2 demo**: exactly this attack.
- Any "double AES" / "AES²" challenge.
- Any AES challenge with **short keys** (< 2⁴⁰ total).

---

## 8. Case 5: ECB mode detection

### Description
Same as DES: ECB is **deterministic**; same plaintext block → same ciphertext.

### Script
```python
def detect_ecb(ct: bytes, block_size=16) -> bool:
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))
```

### When to use
- **Before** choosing the attack path.
- **Always** do this first.

### Extended diagnostic
```python
def analyze_modes(candidates: dict[str, bytes]) -> str:
    """candidates: {name: ciphertext} — same plaintext, different modes."""
    results = {}
    for name, ct in candidates.items():
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        repeats = len(blocks) - len(set(blocks))
        results[name] = repeats
    return results
```

---

## 9. Case 6: ECB byte-at-a-time attack

### Description
Server encrypts `user_input || SECRET` with **AES-ECB**. You control `user_input`. Recover `SECRET` byte-by-byte.

### Script
```python
BLOCK_SIZE = 16

def ecb_byte_at_a_time_aes(oracle, prefix_len=0, max_secret_len=256):
    """oracle: function(user_input: bytes) -> ciphertext."""
    recovered = b""
    for _ in range(max_secret_len):
        # Align target byte at end of a block
        pad_len = (BLOCK_SIZE - 1 - (prefix_len + len(recovered)) % BLOCK_SIZE) % BLOCK_SIZE
        filler = b"A" * pad_len
        target_ct = oracle(filler)
        block_idx = (prefix_len + len(recovered)) // BLOCK_SIZE
        
        found = False
        for b in range(256):
            guess = filler + recovered + bytes([b])
            guess_ct = oracle(guess)
            if guess_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE] == \
               target_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]:
                recovered += bytes([b])
                found = True
                break
        if not found:
            break
    return recovered
```

### Practical oracle examples

**Local:**
```python
from Crypto.Cipher import AES
key = b"YELLOW_SUBMARINE"
def oracle(user_input):
    return AES.new(key, AES.MODE_ECB).encrypt(
        pad(user_input + b"SECRET_MESSAGE_HERE", 16))
```

**Remote (HTTP):**
```python
import requests
def oracle(user_input):
    r = requests.post("http://target/encrypt", data={"input": user_input.hex()})
    return bytes.fromhex(r.text)
```

### When to use
- Any "encryption oracle with appended secret" challenge.
- **Very common in CTF** (Cryptopals-style).

---

## 10. Case 7: CBC bit-flipping

### Description
CBC: `P_i = D(C_i) ⊕ C_{i-1}`. Modify `C_{i-1}` → predictable change in `P_i` (but corrupts `P_{i-1}`).

### Script
```python
def cbc_bitflip(ct: bytes, block_idx: int, p_old: bytes, p_new: bytes,
                block_size=16) -> bytes:
    """Modify block (block_idx-1) ciphertext to change block (block_idx) plaintext."""
    assert len(p_old) == len(p_new) == block_size
    out = bytearray(ct)
    prev_start = (block_idx - 1) * block_size
    for i in range(block_size):
        out[prev_start + i] ^= p_old[i] ^ p_new[i]
    return bytes(out)

# Example: change "role=guest" to "role=admin"
ct_new = cbc_bitflip(ct, block_idx=1, p_old=b"role=guest\x00\x00\x00\x00\x00\x00",
                     p_new=b"role=admin\x00\x00\x00\x00\x00\x00")
```

### When to use
- Cookie manipulation in AES-CBC.
- **Very common in CTF**.

---

## 11. Case 8: CBC padding oracle

### Description
If the server reveals "padding invalid" vs "other error", you can:
- Recover **all plaintext** byte-by-byte.
- **Forge** any ciphertext (including admin tokens).

### Full script (using `padding-oracle` library pattern)
```python
def padding_oracle_attack(oracle, ct: bytes, block_size=16, iv=None):
    """oracle: function(ct_bytes) -> True if padding valid."""
    if iv is None:
        iv = ct[:block_size]
        ct = ct[block_size:]
    
    pt = b""
    prev_block = iv
    
    for i in range(0, len(ct), block_size):
        current_block = ct[i:i+block_size]
        recovered = bytearray(block_size)
        
        for byte_pos in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_pos
            
            # Set known bytes to match pad_val
            for j in range(byte_pos + 1, block_size):
                recovered[j] = 0  # placeholder
            
            # Try all 256 byte values
            for guess in range(256):
                # Craft prev_block modification
                test_prev = bytearray(prev_block)
                test_prev[byte_pos] ^= guess ^ pad_val
                for j in range(byte_pos + 1, block_size):
                    test_prev[j] ^= recovered[j] ^ pad_val
                
                test_ct = bytes(test_prev) + current_block
                if oracle(test_ct):
                    recovered[byte_pos] = guess ^ pad_val
                    break
        
        pt += bytes(recovered)
        prev_block = current_block
    
    return pt
```

### When to use
- Server distinguishes padding errors.
- CTF tasks labeled "padding oracle".

---

## 12. Case 9: CTR nonce reuse (⭐ **Noncense**)

### Description
**This is the actual attack for Noncense.**

AES-CTR:
```
C = P ⊕ E(K, nonce || counter)
```

If two ciphertexts use the **same (key, nonce)**, then keystream is the same:
```
c1 = p1 ⊕ ks
c2 = p2 ⊕ ks
c1 ⊕ c2 = p1 ⊕ p2
```

### Noncense scenario

The challenge uses **AES-CTR** (via `challenge.py`):
```python
def encrypt(key, nonce, msg):
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(msg)
```

- `c_flag`: encrypted flag
- `c_known`: encrypted known message (`known_message.txt`)

**Both with the same nonce** → same keystream → two-time pad.

### Full solve

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter

def noncense_solve():
    # Given ciphertexts from the challenge
    c_flag  = bytes.fromhex(
        "def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c"
    )
    c_known = bytes.fromhex(
        "fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a"
    )
    known_pt = b"According to all known laws of aviation, there is no way a bee should be able to fly."
    
    # Key insight: c1 XOR c2 = p1 XOR p2
    # p_flag = c_flag XOR c_known XOR known_pt
    n = len(c_flag)
    p_flag = bytes(
        a ^ b ^ c
        for a, b, c in zip(c_flag, c_known[:n], known_pt[:n])
    )
    print(f"[+] Flag: {p_flag}")
    return p_flag

noncense_solve()
# Output: b'cns{...}'
```

**Key length check:**
- `c_flag`: 41 bytes
- `c_known`: 63 bytes
- `known_pt`: 75 bytes

Since `c_flag` (41 bytes) < `c_known` (63 bytes) < `known_pt` (75 bytes), we take the first 41 bytes of each — plenty of known plaintext to XOR with.

### General AES-CTR nonce reuse attack
```python
def aes_ctr_nonce_reuse(c1: bytes, c2: bytes, known_pt: bytes) -> bytes:
    """Recover p2 given c1, c2, and p1."""
    ks = bytes(p ^ c for p, c in zip(known_pt, c1))
    return bytes(c ^ k for c, k in zip(c2, ks))
```

### When to use
- **Noncense**: exactly this.
- Any AES-CTR task with reused nonce.

---

## 13. Case 10: GCM/CCM nonce reuse (AEAD)

### Description
For **AES-GCM/CCM** (AEAD), nonce reuse:
- **Confidentiality breaks** (same as CTR): `c1 ⊕ c2 = p1 ⊕ p2`.
- **Authenticity breaks**: Poly1305/GHASH key derived from keystream → forge new ciphertexts.

### Script (keystream reuse)
```python
def gcm_nonce_reuse(c1: bytes, c2: bytes, known_pt: bytes = None) -> bytes:
    """Given two GCM ciphertexts with same nonce, recover plaintext."""
    if known_pt:
        ks = bytes(p ^ c for p, c in zip(known_pt, c1))
        return bytes(c ^ k for c, k in zip(c2, ks))
    return bytes(a ^ b for a, b in zip(c1, c2))   # p1 ⊕ p2
```

### Full GCM forgery (advanced, rare)
Requires solving GHASH polynomial in GF(2¹²⁸):
```python
# Sketch:
# - Recover H from two (c, tag) pairs
# - Compute tag for arbitrary new ciphertext
# Requires GF(2^128) multiplication, typically via galois library
```

### When to use
- AES-GCM/CCM with nonce reuse.
- **Noncense** is CTR (simpler); GCM would be harder.

---

## 14. Case 11: Weak KDF (key = MD5/SHA256 of password)

### Description
If the AES key is directly derived from a password:
```
key = MD5(password)           # 16 bytes → AES-128
key = SHA256(password)[:16]   # AES-128
key = SHA256(password)[:32]   # AES-256
```

Brute force with wordlist:
```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def crack_aes_weak_kdf(known_pt: bytes, known_ct: bytes,
                        wordlist: str, derivation: str = "md5") -> tuple[bytes, str] | None:
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n")
        if not pw: continue
        
        if derivation == "md5":
            key = hashlib.md5(pw.encode()).digest()             # 16B
        elif derivation == "sha256_16":
            key = hashlib.sha256(pw.encode()).digest()[:16]     # 16B
        elif derivation == "sha256_32":
            key = hashlib.sha256(pw.encode()).digest()[:32]     # 32B
        elif derivation == "pbkdf2":
            key = hashlib.pbkdf2_hmac("sha256", pw.encode(), b"salt", 1000)[:16]
        else:
            continue
        
        try:
            if AES.new(key, AES.MODE_ECB).encrypt(known_pt[:16]) == known_ct[:16]:
                return key, pw
        except:
            continue
    return None
```

### When to use
- Challenge code shows `key = hashlib.md5(password).digest()`.
- **Common in CTF**.

---

## 15. Case 12: Side-channel (timing, cache)

### Description
AES has **data-dependent memory access** (S-box lookups). If an attacker can measure:
- **Cache timing** (which S-box entries are accessed).
- **Power consumption**.
- **Electromagnetic emissions**.

...they can recover the key with ~thousands of measurements.

### Script (conceptual)
```python
# Not really CTF-able without physical access.
# But in a shared VM/container, cache timing attacks (Prime+Probe) are real.
# See: "Cache Template Attacks" by Gruss et al. (2015)
```

### When to use
- **Not CTF**. If a challenge mentions "timing", it's usually **string comparison timing**, not AES.
- Real hardware: cache attacks on AES.

---

## 16. Case 13: Library confusion

### Description
Different libraries interpret parameters differently:

| Library | ECB | CBC IV | CTR nonce | GCM nonce |
|---|---|---|---|---|
| `Crypto.Cipher.AES` | ✅ | explicit `iv=` | explicit `nonce=` (8B) | explicit `nonce=` (12B) |
| `cryptography.hazmat` | ✅ | explicit `iv=` | explicit `nonce=` | explicit `nonce=` |
| `openssl` CLI | `-aes-128-ecb` | `-aes-128-cbc -K k -iv v` | `-aes-128-ctr` | `-aes-128-gcm` |
| `nacl.secret.SecretBox` | XSalsa20-Poly1305 | — | — | — |
| `nacl.secret.Aead` | — | — | — | XChaCha20-Poly1305 |

**Common bug:** AES-CTR in PyCryptodome uses **8-byte nonce** by default, but AES-GCM uses **12-byte nonce**. If you mix them up → wrong keystream.

### Detection
Read the **source code** of the challenge. Note:
- Which library?
- Which mode?
- What are the parameter sizes?
- How is the nonce generated?

### When to use
- **Always** — before writing any attack.

---

## 17. Case 14: Related-key attack (academic)

### Description
If an attacker knows AES under **two related keys** (`K` and `K ⊕ Δ`), they can recover the key faster than brute force (Biryukov–Khovratovich, 2009).

**Relevance:** **zero** for standard use (you never have related keys). **Academic only.**

### When to use
- **Not CTF**.

---

## 18. Quick reference: "I see AES — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Known key | decrypt | §4 |
| Short key (≤ 24 bits) | brute force | §5 |
| Prefix known | prefix brute | §6 |
| **Double AES + short keys** | **MITM** | **§7** |
| ECB mode | detect + byte-at-a-time | §8/§9 |
| CBC mode | bit-flipping / padding oracle | §10/§11 |
| **CTR + reused nonce** | **two-time pad** | **§12** |
| GCM + reused nonce | keystream + forgery | §13 |
| Weak KDF | wordlist | §14 |
| Side-channel | timing/cache | §15 |
| Library confusion | read code | §16 |

---

## 19. Mapping to session tasks

### Noncense (⭐ AES-CTR)

**What it is:**
- Server uses `AES-CTR` with **nonce reuse**.
- Two ciphertexts: `c_flag` and `c_known`.
- Known plaintext: the bee quote.

**Attack:**
- `p_flag = c_flag ⊕ c_known ⊕ known_pt` (Case 9).

**Script:** §12.

**Difficulty:** ⭐ easy (5 minutes).

---

### AES 2 demo (⭐ Double AES MITM)

**What it is:**
- Promo code encrypted with **double AES**: `C = AES(K2, AES(K1, P))`.
- `K1, K2` are **20-bit** (rest zero-padded).
- `enc.bmp` is a **BMP file** → known header structure.

**Attack:**
- MITM: 2²⁰ encryptions + 2²⁰ decryptions ≈ 2 minutes.
- Use **BMP header** as known plaintext (Case 4).

**Script:** §7.

**Difficulty:** ⭐⭐ medium (requires BMP header knowledge + MITM implementation).

**Key challenges:**
1. **BMP header guess** — first 16 bytes vary by file size, but structure is predictable.
2. **Byte order** — BMP uses **little-endian** for sizes.
3. **Correct plaintext block** — must be exactly 16 bytes for AES.

**BMP header structure (54-byte file header):**
```
Offset  Size  Field           Typical Value
0       2     "BM"            0x42 0x4D
2       4     File size       varies (little-endian)
6       2     Reserved1       0x00 0x00
8       2     Reserved2       0x00 0x00
10      4     Data offset     often 0x36 (54) for 24-bit BMP
14      4     DIB header size often 0x28 (40) for BITMAPINFOHEADER
18      4     Width           varies
22      4     Height          varies
26      2     Color planes    0x01 0x00
28      2     Bits per pixel  varies (24 = 0x18)
```

**First 16 bytes (common):**
```
42 4D <size_low:2> <size_high:2> 00 00 00 00 <offset:4> <dib:2>
```

Since `size` varies, you may need to **try multiple candidates** (different file sizes).

---

### Other session tasks (not AES)

| Task | Cipher | Relevance to AES |
|---|---|---|
| **Key standardisation** | DES | Same prefix-brute-force, but AES too slow |
| **Secure Bank** | Salsa20 | Different stream cipher |
| **Secure Bank 2** | SHA-256 truncated | Different primitive |
| **Better Hash** | Custom hash | Different primitive |
| **Security Cam** | RTSP/MD5 | Different primitive |
| **Signed, Sealed** | HMAC-SHA256 | Different primitive |
| **Token of Trust** | JWT | Different primitive |
| **Replanting** | LCG | Different primitive |
| **Dutch Exclusivity** | XOR | Different primitive |

**Only Noncense and AES 2 demo use AES.**

---

## 20. Defender perspective

| Mistake | Fix |
|---|---|
| ECB mode | **Use CBC/GCM** (never ECB for data) |
| Fixed IV/nonce | **Random IV per message** |
| IV reuse | Nonce must be **unique** per (key, message) |
| No integrity | **AES-GCM** or **AES-CCM** (AEAD) |
| Weak KDF | **Argon2, scrypt, PBKDF2** with 600k iterations |
| Short key | **AES-128** minimum; AES-256 for long-term |
| Library confusion | Pin library, read docs, verify nonce sizes |
| No padding validation | Use AEAD — no padding at all |
| Key derived from password | Use **PBKDF2/Argon2** with salt |
| Same key for encryption + MAC | **Separate keys** (HKDF) |

**NIST SP 800-38A/D:**
- ECB: **not recommended**.
- CBC: **acceptable** with random IV + HMAC.
- CTR: **acceptable** with unique nonce.
- GCM: **recommended** (AEAD).
- CCM: **acceptable** (AEAD).

**AES is secure** — just don't use it wrong.

---

## 21. Ready-to-use `aes_toolkit.py`?

Same structure as previous toolkits. Options:

- **A)** Build `aes_toolkit.py` with:
  ```
  - aes_encrypt(key, pt, mode, iv/nonce) / aes_decrypt(...)
  - brute_short_key(known_pt, known_ct, key_bits, prefix) -> key
  - mitm_double_aes(known_pt, known_ct, key_bits, key_len) -> (k1, k2)
  - detect_ecb(ct) -> bool
  - ecb_byte_at_a_time(oracle) -> plaintext
  - cbc_bitflip(ct, block_idx, p_old, p_new) -> new_ct
  - padding_oracle_attack(oracle, ct) -> plaintext
  - ctr_nonce_reuse(c1, c2, known_pt) -> plaintext
  - gcm_nonce_reuse(c1, c2, known_pt) -> plaintext
  - crack_weak_kdf(known_pt, known_ct, wordlist, derivation) -> (key, pw)
  ```
  + CLI:
  ```
  python aes_toolkit.py decrypt    --key hex --ct hex --mode ecb|cbc|ctr|gcm
  python aes_toolkit.py brute      --pt "..." --ct hex --bits 20 --prefix hex
  python aes_toolkit.py mitm       --pt "BM..." --ct hex --bits 20
  python aes_toolkit.py ecb-detect --ct hex
  python aes_toolkit.py ecb-bite   --oracle-url ... --prefix-len 0
  python aes_toolkit.py cbc-bite   --ct hex --old hex --new hex --block-idx 1
  python aes_toolkit.py nonce      --c1 c1.hex --c2 c2.hex --pt "According to..."
  python aes_toolkit.py wordlist   --pt "..." --ct hex --wordlist rockyou.txt --kdf md5
  ```
