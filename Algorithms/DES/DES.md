# DES: Theory, All Cases, Scripts

DES (Data Encryption Standard) is the **grandfather of modern block ciphers**. Designed by IBM (with NSA tweaks), standardized by NIST in 1977 as FIPS 46, and the de facto encryption standard until AES replaced it in 2001. It's **not cryptanalytically broken** (no practical attack better than brute force on full 16 rounds) — but its **56-bit key** makes brute force feasible on modern hardware.

This is the cipher behind **Key standardisation** (IOTDEV + 2 bytes prefix), and a foundational understanding for 3DES and AES.

---

## 1. What is DES (formally)

DES is a **block cipher** with:

| Parameter | Value |
|---|---|
| Block size | **64 bits (8 bytes)** |
| Key size | **64 bits (8 bytes)** — but **56 bits effective** (8 parity bits discarded) |
| Structure | **Feistel network** |
| Rounds | **16** |
| Round key size | 48 bits each (derived from 56-bit key) |
| Substitution | 8 S-boxes (6→4 bits each) |
| Permutation | Expansion, P-permutation, IP/FP |

### 1.1 High-level structure

```
Plaintext (64 bits)
       │
       ▼
  [Initial Permutation IP]
       │
       ▼
┌─────┴─────┐
│ L0 (32)   │ R0 (32)
└─────┬─────┘
       │
   ┌───┴───────────────────┐
   │  For i = 1..16:       │
   │    Li = R_{i-1}       │
   │    Ri = L_{i-1} ⊕ F(R_{i-1}, Ki)
   └───┬───────────────────┘
       │
       ▼
  [Swap L16, R16]
       │
       ▼
  [Final Permutation FP = IP⁻¹]
       │
       ▼
  Ciphertext (64 bits)
```

### 1.2 Feistel function `F(R, K)` (32 → 48 → 32 bits)

```
R (32 bits)
   │
   ▼
[Expansion E: 32→48 bits]
   │
   ▼
XOR with round key K (48 bits)
   │
   ▼
[8 S-boxes: 48→32 bits]
   │
   ▼
[P-permutation: 32→32 bits]
   │
   ▼
F(R, K) (32 bits)
```

**S-boxes** are the **only nonlinear component**. Without them, DES would be a linear (breakable) cipher.

### 1.3 Key schedule (56 → 16 × 48 bits)

```
Key (64 bits)
   │
   ▼
[PC-1: 64→56 bits, drops parity bits]
   │
   ▼
Split into C0, D0 (28 bits each)
   │
   ▼
For i = 1..16:
   - Left-rotate Ci, Di by 1 or 2 positions
   - [PC-2: 56→48 bits] → round key Ki
```

### 1.4 Decryption

**Decryption uses the same algorithm** as encryption, but with round keys in **reverse order** (`K16, K15, ..., K1`). This is a property of the **Feistel network** — very elegant.

### 1.5 Python implementation (PyCryptodome)

```python
from Crypto.Cipher import DES

key = b"8bytekey"           # 8 bytes
cipher = DES.new(key, DES.MODE_ECB)
ct = cipher.encrypt(b"plaintext...")          # length must be multiple of 8
pt = cipher.decrypt(ct)
```

**Note:** PyCryptodome doesn't do padding automatically for DES. You need `pad()` / `unpad()` from `Crypto.Util.Padding`, or handle it yourself.

---

## 2. Weak keys, semi-weak keys, and parity

### 2.1 Parity bits
- DES key is 64 bits, but only **56 bits are used**.
- The 8 least significant bits (bits 8, 16, 24, 32, 40, 48, 56, 64) are **parity bits** — discarded by PC-1.
- Some implementations accept `b"password"` and ignore parity; others require it.

### 2.2 Weak keys (4 total)
Keys that cause the round key schedule to be **self-inverse** or **all identical**:

| Weak key (hex) | Why |
|---|---|
| `0101010101010101` | All round keys identical |
| `FEFEFEFEFEFEFEFE` | All round keys identical (complement) |
| `E0E0E0E0F1F1F1F1` | Round keys alternate |
| `1F1F1F1F0E0E0E0E` | Round keys alternate |

For weak keys: `E(K, E(K, M)) = M` — i.e., **double encryption = identity**.

### 2.3 Semi-weak keys (12 total)
Pairs of keys `(K1, K2)` such that `E(K1, E(K2, M)) = M`. Rare but useful in theoretical attacks.

### 2.4 Detection
```python
WEAK_KEYS = [
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
]

def is_weak_key(key: bytes) -> bool:
    return key in WEAK_KEYS
```

### 2.5 When to use
- **Rare in CTF**, but check: if a challenge hints at "weak key" or "symmetric behavior", it might be one of these.
- More common: keys from **dictionary** (Case 3).

---

## 3. Security requirements — and where DES fails

DES was designed to be **secure for its era** (1970s). It failed only because of **Moore's law**, not cryptanalysis.

| Property | DES status | Why |
|---|---|---|
| Confusion | ✅ | S-boxes |
| Diffusion | ✅ | Expansion + P-permutation |
| Round count | ✅ | 16 rounds (best known attacks on full 16-round DES are impractical) |
| Key space | ❌ | **56 bits = 7.2 × 10¹⁶ keys** — brute-forcible |
| Block size | ⚠️ | 64 bits — vulnerable to birthday attacks (2³²) |
| ECB mode | ❌ | Deterministic — same block → same ciphertext |
| Weak keys | ⚠️ | 4 weak + 12 semi-weak |

**The only practical attack on full DES is brute force.** No better attack on the full 16-round cipher has been published (differential/linear cryptanalysis work on reduced-round variants only).

### 3.1 Brute force timeline
| Year | Hardware | Time |
|---|---|---|
| 1977 | Custom VLSI (est.) | 1 day |
| 1993 | 1000 CPUs (Wiener) | 1.5 hours (theoretical) |
| 1998 | EFF "Deep Crack" | **56 hours** |
| 2006 | COPACOBANA | 6.4 days (but reusable hardware) |
| 2012 | 48 FPGAs | ~40 hours |
| 2024 | Modest GPU cluster | **< 24 hours** |
| 2024 | RTX 4090 (est.) | ~10–15 days single GPU |

On AWS with a few thousand GPUs, **< 1 hour**. On a national lab, **minutes**. Full 2⁵⁶ brute force is achievable — just not free.

---

## 4. Attack taxonomy

| # | Attack | Input needed | Difficulty |
|---|---|---|---|
| 1 | **Known plaintext + brute force 2⁵⁶** | One `(p, c)` pair | Hours–weeks (with hardware) |
| 2 | **Partial key brute force** (known prefix) | Part of key known | **Seconds** |
| 3 | **Dictionary / wordlist attack** | Known plaintext + wordlist | Minutes |
| 4 | **Weak key attack** | Detection only | Trivial |
| 5 | **ECB mode detection** | Two ciphertexts | Trivial |
| 6 | **ECB byte-at-a-time** | Oracle access | Easy |
| 7 | **CBC bit-flipping** | Known plaintext + structure | Trivial |
| 8 | **CBC padding oracle** | Oracle + many ciphertexts | Medium |
| 9 | **CFB/OFB malleability** | Known plaintext | Trivial |
| 10 | **3DES meet-in-the-middle** | 2-key 3DES | Infeasible (2¹¹²) |
| 11 | **DES Crack / COPACOBANA** | Hardware | Not CTF |

Case 2 is the **Key standardisation** task.

---

## 5. Case 1: Full brute force 2⁵⁶ (theoretical, not CTF-friendly)

### Description
Try every possible 56-bit key until decryption yields valid plaintext.

### Reality
- Pure Python: **~10⁵ years** for 2⁵⁶.
- Optimized C: **~10⁴ years** on CPU.
- GPU cluster: **days–weeks**.
- ASIC/FPGA (Deep Crack): **hours**.

**Not practical in pure Python/CTF.**

### Script (theoretical)
```python
from Crypto.Cipher import DES

def brute_des(known_pt: bytes, known_ct: bytes) -> int:
    for k in range(1 << 56):                  # 2^56 = 7.2e16
        key = k.to_bytes(8, "big")
        if DES.new(key, DES.MODE_ECB).encrypt(known_pt) == known_ct:
            return k
    return -1
```

**In practice:** use `hashcat` mode 14000 or `john` — but only for weak/known-prefix keys.

---

## 6. Case 2: Partial key brute force (⭐ **Key standardisation**)

### Description
The key has a **known prefix or structure**:
```
key = b"IOTDEV" + unknown_2_bytes      → 2^16 = 65536 candidates
```
Or:
```
key = b"prefix" + n_bytes              → 2^(8n) candidates
```

For `n ≤ 4`, brute force is **seconds–minutes**. For `n = 4`, hours. For `n = 6`, weeks. For `n = 7`, infeasible.

### Key standardisation — full solve

**Task recap** (from the file):
```
{ "namespace": "IOTDEV", "message": "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac" }

# key = b"IOTDEV" + 2 bytes
```

**Full solve:**
```python
from Crypto.Cipher import DES

message = bytes.fromhex(
    "74eb40cf03b84d0bc4cd2c6e0fe97fb4"
    "e70546d3e09c530d35b344e530351bac"
)

# Only 2^16 = 65536 candidates
for i in range(65536):
    key = b"IOTDEV" + i.to_bytes(2, "big")   # 6 + 2 = 8 bytes
    try:
        pt = DES.new(key, DES.MODE_ECB).decrypt(message)
    except:
        continue
    if b"cns{" in pt:
        print(f"[+] FOUND key = {key!r}")
        print(f"[+] plaintext = {pt!r}")
        break
```

**Runtime:** ~5–15 seconds in pure Python (PyCryptodome).

### Variants

**Variant A: Known suffix**
```python
for i in range(65536):
    key = i.to_bytes(2, "big") + b"IOTDEV"
    ...
```

**Variant B: Known middle bytes**
```python
for i in range(1 << 24):          # 3 unknown bytes → 2^24, ~1 hour Python
    key = b"AB" + i.to_bytes(3, "big") + b"YZ"
    ...
```

**Variant C: Known pattern (e.g., `key = user_id || fixed_padding`)**
```python
for user_id in range(10000):
    key = user_id.to_bytes(4, "big") + b"\x00" * 4
    ...
```

**Variant D: Known prefix in different byte order**
```python
# Sometimes the prefix is at the END or interleaved
key = i.to_bytes(2, "big") + b"IOTDEV"
key = b"IO" + i.to_bytes(2, "big") + b"DEV"
# Try all permutations
```

### Optimization tips
1. **Early exit on known plaintext:**
   ```python
   # If you know plaintext starts with "cns{", check only the first block
   ct_first_block = message[:8]
   for i in range(65536):
       key = b"IOTDEV" + i.to_bytes(2, "big")
       pt_block = DES.new(key, DES.MODE_ECB).decrypt(ct_first_block)
       if b"cns{" in pt_block:
           # Full decrypt only on candidates
           ...
   ```
   This saves ~6× time if plaintext is 6 blocks.

2. **Multiprocessing** for larger keyspaces:
   ```python
   from multiprocessing import Pool

   def try_key_range(args):
       start, end = args
       for i in range(start, end):
           key = b"IOTDEV" + i.to_bytes(2, "big")
           pt = DES.new(key, DES.MODE_ECB).decrypt(message)
           if b"cns{" in pt:
               return key, pt
       return None

   with Pool(8) as p:
       results = p.map(try_key_range, [(i*8192, (i+1)*8192) for i in range(8)])
   ```

3. **Use `pycryptodome` `_raw` API** for speed:
   ```python
   from Crypto.Cipher import DES
   cipher = DES.new(key, DES.MODE_ECB)
   pt = cipher.decrypt(ct)
   ```

---

## 7. Case 3: Dictionary / wordlist attack

### Description
The key is a **word from a wordlist** (padded to 8 bytes with zeros/spaces, or exactly 8 chars).

### Script
```python
from Crypto.Cipher import DES

def crack_des_wordlist(known_pt: bytes, known_ct: bytes, wordlist: str) -> bytes | None:
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n").encode()
        if not pw or len(pw) > 8: continue
        # Try both padding styles
        for key in (pw.ljust(8, b"\x00"), pw.ljust(8, b" "), pw[:8]):
            if len(key) != 8: continue
            try:
                if DES.new(key, DES.MODE_ECB).decrypt(known_ct[:8]) == known_pt[:8]:
                    return key
            except:
                continue
    return None

# Usage
key = crack_des_wordlist(b"cns{", known_ct, "rockyou.txt")
print(f"Found key: {key!r}")
```

### When to use
- Challenge key is a **human password** (e.g., `b"password"`, `b"secret12"`).
- Combined with **known plaintext** (or format `cns{`).

### Variants
- **Key = PBKDF2(password, salt)**: use `hashlib.pbkdf2_hmac` to derive.
- **Key = MD5(password)[:8]**: use `hashlib.md5`.
- **Key = SHA-256(password)[:8]**: use `hashlib.sha256`.

**Example (key derived from password):**
```python
import hashlib

def crack_des_derived(known_pt, known_ct, wordlist, derivation="md5"):
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n")
        if derivation == "md5":
            key = hashlib.md5(pw.encode()).digest()[:8]
        elif derivation == "sha256":
            key = hashlib.sha256(pw.encode()).digest()[:8]
        elif derivation == "pbkdf2":
            key = hashlib.pbkdf2_hmac("sha256", pw.encode(), b"salt", 1000)[:8]
        else:
            key = pw.encode()[:8].ljust(8, b"\x00")

        if DES.new(key, DES.MODE_ECB).decrypt(known_ct[:8]) == known_pt[:8]:
            return key, pw
    return None, None
```

---

## 8. Case 4: ECB mode detection

### Description
ECB encrypts each 8-byte block **independently** with the same key. So:
- Same plaintext block → **same ciphertext block**.
- Patterns in plaintext **leak into ciphertext**.

### Detection
```python
def detect_ecb(ct: bytes, block_size=8) -> bool:
    """True if ciphertext has repeated 8-byte blocks (ECB)."""
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))
```

**Example:**
```
Plaintext:  "AAAAAAAAAAAAAAAA"   (16 bytes, 2 identical blocks)
ECB:        [XXXX][XXXX]        ← identical ciphertext blocks
CBC:        [YYYY][ZZZZ]        ← different ciphertext blocks
```

### When to use
- **Detect the mode** before attacking.
- Any "find the pattern in ciphertext" challenge.

### Extended detection
```python
def analyze_ecb(ct: bytes, block_size=8):
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    from collections import Counter
    counts = Counter(blocks)
    repeats = {b: n for b, n in counts.items() if n > 1}
    print(f"Total blocks: {len(blocks)}")
    print(f"Unique blocks: {len(set(blocks))}")
    print(f"Repeated: {len(repeats)}")
    return repeats
```

---

## 9. Case 5: ECB byte-at-a-time attack (⭐ advanced)

### Description
Classic CTF attack: **recover plaintext byte-by-byte** when:
1. You control **part** of the plaintext (prepended or appended).
2. The server encrypts with **ECB mode** and a **fixed key**.
3. You can observe the **ciphertext length**.

### Setup
```
Server: E(key, user_input || SECRET)
```
You want to recover `SECRET`.

### Algorithm
1. **Find block size**: send `A`, `AA`, `AAA`, ... until ciphertext length jumps.
2. **Detect ECB**: send `A"*16`, check for repeated blocks.
3. **Recover bytes one at a time**:
   - Make `user_input` such that the last byte of `SECRET` aligns with the end of a block.
   - Try all 256 possible last bytes; find the one that matches the ciphertext's first block.

### Script
```python
from Crypto.Cipher import DES

BLOCK_SIZE = 8

def ecb_byte_at_a_time(oracle, prefix_len=0):
    """
    oracle: function(user_input) -> ciphertext.
    prefix_len: length of known prefix before user_input (e.g., SECRET is before user_input).
    """
    recovered = b""
    while True:
        # Determine how much filler to align target byte at block boundary
        pad_len = (BLOCK_SIZE - 1 - (prefix_len + len(recovered)) % BLOCK_SIZE) % BLOCK_SIZE
        filler = b"A" * pad_len
        target_ct = oracle(filler)

        # The byte we're targeting is at position:
        block_idx = (prefix_len + len(recovered)) // BLOCK_SIZE

        # Try all 256 bytes
        for b in range(256):
            guess = filler + recovered + bytes([b])
            guess_ct = oracle(guess)
            if guess_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE] == \
               target_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]:
                recovered += bytes([b])
                break
        else:
            # No byte matched — end of secret or error
            return recovered

# Example usage
def local_oracle(user_input: bytes) -> bytes:
    secret = b"this_is_the_secret"
    return DES.new(b"8bytekey", DES.MODE_ECB).encrypt(pad(user_input + secret, 8))

recovered = ecb_byte_at_a_time(local_oracle)
print(recovered)   # b"this_is_the_secret"
```

### When to use
- Any challenge with **ECB oracle** (server-side encryption with appended secret).
- Similar attack works for **AES-ECB** (block size 16).

### Real-world CTF framing
```python
import requests

def oracle(user_input: bytes) -> bytes:
    r = requests.post("http://target/encrypt", data={"input": user_input.hex()})
    return bytes.fromhex(r.text)

recovered = ecb_byte_at_a_time(oracle)
print(recovered)
```

---

## 10. Case 6: CBC bit-flipping

### Description
In CBC mode:
```
C_i = E(P_i ⊕ C_{i-1}),   with C_0 = IV
```
So:
```
P_i = D(C_i) ⊕ C_{i-1}
```

**Bit-flipping**: modifying `C_{i-1}` modifies `P_i` predictably:
```
C'_{i-1} = C_{i-1} ⊕ (P_i ⊕ P'_i)  →  P'_i = P_i ⊕ (P_i ⊕ P'_i) = P'_i  ✓
```

But it **corrupts `P_{i-1}`** (because `C_{i-1}` also serves as input to `D` for `P_{i-1}`).

### Script
```python
def cbc_bitflip(ct: bytes, block_idx: int, p_old: bytes, p_new: bytes,
                block_size=8, iv_included=False) -> bytes:
    """Modify block (block_idx-1) to change block (block_idx) plaintext."""
    assert len(p_old) == len(p_new) == block_size
    out = bytearray(ct)
    target_start = block_idx * block_size
    prev_start = target_start - block_size
    if iv_included:
        prev_start += block_size   # if IV is prepended to ct, adjust

    for i in range(block_size):
        out[prev_start + i] ^= p_old[i] ^ p_new[i]
    return bytes(out)

# Example: change "guest" to "admin" in block 1, using block 0 as prev
new_ct = cbc_bitflip(ct, block_idx=1, p_old=b"guest...", p_new=b"admin...")
```

### When to use
- Cookie / token manipulation in CBC mode.
- Any "flip a byte in plaintext" challenge.
- **Not** Key standardisation (uses ECB).

---

## 11. Case 7: CBC padding oracle

### Description
If the server **leaks** whether decryption failed due to **padding error** vs **other error**, you can:
1. Recover plaintext byte-by-byte (from the end).
2. Forge valid ciphertexts.

### Classic attack
For a ciphertext `C = [IV][C_1][C_2]...`:
1. Modify `C_{i-1}` byte-by-byte from the end.
2. Find a value that makes padding valid (e.g., `0x01`, `0x02 0x02`, ...).
3. Recover `P_i` byte-by-byte.

### Script (simplified)
```python
def padding_oracle_attack(oracle, ct: bytes, block_size=8):
    """oracle: function(ct) -> True if padding valid, False otherwise."""
    pt = b""
    n_blocks = len(ct) // block_size
    prev_block = ct[:block_size]   # IV is first block (or prepended)

    for block_idx in range(1, n_blocks):
        current = bytearray(ct[block_idx*block_size : (block_idx+1)*block_size])
        recovered = bytearray(block_size)
        for byte_pos in range(block_size - 1, -1, -1):
            # Determine expected padding value
            pad_val = block_size - byte_pos

            # Set known bytes to produce correct padding
            for j in range(byte_pos + 1, block_size):
                current[j] ^= recovered[j] ^ pad_val

            # Try all 256 values for this byte
            for guess in range(256):
                test_prev = bytearray(prev_block)
                test_prev[byte_pos] ^= guess ^ pad_val
                test_ct = bytes(test_prev) + bytes(current) + ct[(block_idx+1)*block_size:]
                if oracle(test_ct):
                    if byte_pos == block_size - 1:
                        # Edge case: might be padding 0x02 0x02 instead of 0x01
                        # (try second value to confirm)
                        ...
                    recovered[byte_pos] = guess ^ pad_val
                    break
        pt = bytes(recovered) + pt
        prev_block = ct[block_idx*block_size : (block_idx+1)*block_size]
    return pt
```

**Note:** Padding oracle attacks on DES are **rare in CTF** because DES has been largely replaced by AES for this. But the principle applies.

### When to use
- Server distinguishes **padding errors** from other errors.
- CTF tasks explicitly labeled "padding oracle".

---

## 12. Case 8: CFB/OFB malleability

### Description
- **CFB**: `C_i = P_i ⊕ E(IV_{i-1})`, `IV_i = C_i`. Bit-flip `C_i` → changes `P_i` AND `P_{i+1}` (because `C_i` is next IV).
- **OFB**: `C_i = P_i ⊕ O_i`, `O_i = E(O_{i-1})`. Bit-flip `C_i` → changes `P_i` **only** (keystream independent of ciphertext).

### CFB bit-flip
```python
def cfb_bitflip(ct: bytes, pos: int, p_old: int, p_new: int) -> bytes:
    out = bytearray(ct)
    out[pos] ^= p_old ^ p_new
    return bytes(out)
```

### OFB bit-flip
Same as raw stream cipher.

### When to use
- Cookie manipulation in CFB/OFB mode.
- Rarer than CBC in CTF.

---

## 13. Case 9: Weak key attack

### Description
If a key is one of the 4 weak keys:
```
E(K, E(K, M)) = M
```

This means:
- Double encryption **does nothing**.
- In some protocols, a weak key can cause **catastrophic failure**.

### Script
```python
def detect_weak_key(ct: bytes, known_pt: bytes) -> bytes | None:
    """If E(K, ct) == known_pt for a weak key, we've found the key."""
    WEAK_KEYS = [
        bytes.fromhex("0101010101010101"),
        bytes.fromhex("FEFEFEFEFEFEFEFE"),
        bytes.fromhex("E0E0E0E0F1F1F1F1"),
        bytes.fromhex("1F1F1F1F0E0E0E0E"),
    ]
    for key in WEAK_KEYS:
        try:
            if DES.new(key, DES.MODE_ECB).encrypt(known_pt[:8]) == ct[:8]:
                return key
        except:
            continue
    return None
```

### When to use
- Challenge hints at "weak key".
- Rare but cheap to check.

---

## 14. DES in other modes (comparison table)

| Mode | Ciphertext = | IV reuse? | Bit-flip target |
|---|---|---|---|
| **ECB** | `E(P_i)` | N/A | Same block only |
| **CBC** | `E(P_i ⊕ C_{i-1})` | ❌ catastrophic | `C_{i-1}` → `P_i` (and corrupts `P_{i-1}`) |
| **CFB** | `P_i ⊕ E(C_{i-1})` | ❌ | `C_i` → `P_i` and `P_{i+1}` |
| **OFB** | `P_i ⊕ O_i`, `O_i = E(O_{i-1})` | ❌ | `C_i` → `P_i` only |
| **CTR** | `P_i ⊕ E(counter_i)` | ❌ | `C_i` → `P_i` only |

**Key standardisation** uses ECB — so no chaining issues, just plain brute force.

---

## 15. Comparison with 3DES and AES

| Aspect | DES | 3DES (2-key) | 3DES (3-key) | AES |
|---|---|---|---|---|
| Key bits | 56 | 112 | 168 | 128/192/256 |
| Block size | 64 | 64 | 64 | 128 |
| Rounds | 16 | 48 (3×16) | 48 | 10/12/14 |
| Speed (relative) | 1× | 3× slower | 3× slower | **~50× faster** |
| Brute force (2024) | Hours | Infeasible | Infeasible | Infeasible |
| Still secure? | ❌ | ⚠️ (retiring) | ✅ (but slow) | ✅ |
| Use case | Legacy | Legacy (EMV) | Legacy | **Modern standard** |

**Migration:** DES → 3DES → AES. If you see DES in 2024, it's either **legacy** or **CTF**.

---

## 16. Case 10: Related-key attacks (advanced, not practical)

### Description
If two keys differ by a **known small amount**, attacks improve. But practical DES related-key attacks are **theoretical**.

**Not CTF-relevant.** Skip unless explicitly hinted.

---

## 17. Mapping to session tasks

| Task | Cipher | DES-relevant? |
|---|---|---|
| **Key standardisation** | **DES-ECB** | ✅ **YES** — Case 2 (IOTDEV prefix brute force) |
| **Noncense** | AES-CTR | ❌ (uses AES) |
| **Secure Bank** | Salsa20 | ❌ |
| **Secure Bank 2** | Truncated SHA-256 | ❌ |
| **Security Cam** | RTSP/MD5 | ❌ (but RTSP Digest is MD5-based, not DES) |
| **Signed, Sealed** | HMAC-SHA256 | ❌ |
| **Token of Trust** | JWT | ❌ |
| **Replanting** | LCG | ❌ |

**Only Key standardisation uses DES.** The solve is in §6.

---

## 18. Tools for DES attacks

| Tool | Use case | Command |
|---|---|---|
| **PyCryptodome** | Custom scripts | `from Crypto.Cipher import DES` |
| **hashcat** | GPU brute force | `hashcat -m 14000 hash.txt wordlist.txt` |
| **john** | CPU + wordlist | `john --format=des hash.txt` |
| **aircrack-ng** | WEP only (RC4-based, not DES) | — |
| **COPACOBANA** | Full 2⁵⁶ (hardware) | — |
| **Custom GPU** | Full 2⁵⁶ | — |

For CTF, **always try in order:**
1. **Known prefix** (Key standardisation: `IOTDEV` + 2 bytes → 2¹⁶)
2. **Dictionary** (rockyou.txt)
3. **Weak keys**
4. **Derived key** (MD5/SHA256 of password)
5. **Full brute force** (only if challenge expects GPU/hardware — never pure Python)

---

## 19. Defender perspective

| Mistake | Fix |
|---|---|
| Using DES at all | **Migrate to AES** — DES is deprecated (NIST 2017) |
| Short key | ≥ 128 bits |
| Weak key | Never use `010101...`, `FEFEFE...`, etc. |
| ECB mode | Use **CBC/GCM** (or better, AEAD) |
| No IV/nonce | Always random IV |
| Key = password | Use **PBKDF2 / Argon2** to derive |
| Predictable key structure (prefix) | **Full 256-bit random key** from CSPRNG |
| No integrity | Use **AES-GCM** / **AES-CCM** (AEAD) |
| No key rotation | Rotate keys periodically |

**NIST SP 800-131A (2019):** DES and 2-key 3DES are **disallowed** for government use; 3-key 3DES is legacy. **AES is the only approved symmetric cipher.**

---

## 20. Ready-to-use `des_toolkit.py`?

Same structure as before. Options:

- **A)** Build `des_toolkit.py` with:
  ```
  - des_encrypt(key, pt) / des_decrypt(key, ct)
  - des_ecb_encrypt(key, pt) / des_ecb_decrypt(key, ct)
  - brute_prefix(known_pt, known_ct, prefix, suffix, n_unknown) -> key
  - crack_wordlist(known_pt, known_ct, wordlist) -> (key, pw)
  - crack_derived(known_pt, known_ct, wordlist, derivation) -> (key, pw)
  - detect_ecb(ct) -> bool
  - detect_weak_key(ct, known_pt) -> key | None
  - ecb_byte_at_a_time(oracle, block_size=8, prefix_len=0) -> plaintext
  - cbc_bitflip(ct, block_idx, p_old, p_new) -> new_ct
  ```
  + CLI:
  ```
  python des_toolkit.py decrypt   --key hex --ct hex
  python des_toolkit.py brute     --pt "..." --ct hex --prefix "IOTDEV" --unknown 2
  python des_toolkit.py wordlist  --pt "..." --ct hex --wordlist rockyou.txt
  python des_toolkit.py ecb-detect --ct hex
  python des_toolkit.py ecb-bite  --oracle-url ...
  python des_toolkit.py weak      --ct hex --pt "cns{"
  ```

