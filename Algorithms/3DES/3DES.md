# Triple DES (3DES): Theory, All Cases, Scripts

3DES (Triple DES, TDEA) is the **transitional cipher** between DES and AES. It was standardized in 1999 (ANSI X9.52, later NIST SP 800-67) to extend DES's life without breaking compatibility. It's **still secure** in its 3-key form, but **slow**, **deprecated**, and surrounded by **implementation pitfalls** that are great CTF material.

This section covers 3DES thoroughly — the mathematics, the security analysis, and every practical attack.

---

## 1. What is 3DES (formally)

3DES applies DES **three times** in an **Encrypt–Decrypt–Encrypt (EDE)** sequence. Two variants exist:

### 1.1 Two-key 3DES (2TDEA)

```
C = E(K1, D(K2, E(K1, P)))         ← K3 = K1
P = D(K1, E(K2, D(K1, C)))
```

- Keys: `K1, K2` (each 56 bits) → **112-bit effective key**
- Standard: NIST SP 800-67 (legacy)
- Used in: EMV (chip cards), older banking, legacy systems

### 1.2 Three-key 3DES (3TDEA)

```
C = E(K3, D(K2, E(K1, P)))
P = D(K3, E(K2, D(K1, C)))
```

- Keys: `K1, K2, K3` (each 56 bits) → **168-bit nominal key**
- **Effective security: 2¹¹²** (see §3)
- Standard: NIST SP 800-67 (legacy, retiring 2023)
- Used in: legacy enterprise, old VPNs, some payment systems

### 1.3 Why EDE, not EEE?

**Backward compatibility with DES.** If `K1 = K2 = K3 = K`, then:

```
E(K, D(K, E(K, P))) = E(K, P)       ← collapses to single DES
```

This means a 3DES device can **decrypt** single-DES ciphertext just by setting all keys equal. That's why the middle operation is **D**, not E — it's a deliberate design choice, not a security feature.

### 1.4 Key parameters

| Variant | Key bits (nominal) | Effective security | Block size | Rounds |
|---|---|---|---|---|
| DES | 56 | 2⁵⁶ (broken) | 64 bits | 16 |
| **2-key 3DES** | 112 | **2¹¹²** | 64 bits | 48 (3×16) |
| **3-key 3DES** | 168 | **2¹¹²** | 64 bits | 48 (3×16) |
| AES-128 | 128 | 2¹²⁸ | 128 bits | 10 |

**Key insight:** 3-key 3DES has a 168-bit **key**, but only **112-bit security** because of the meet-in-the-middle attack (van Oorschot–Wiener, 1990). NIST officially recognizes this: 3-key 3DES provides **112-bit security**, not 168.

### 1.5 Python implementation (PyCryptodome)

```python
from Crypto.Cipher import DES3

key = b"123456781234567812345678"   # 24 bytes (3 × 8)
cipher = DES3.new(key, DES3.MODE_ECB)
ct = cipher.encrypt(b"plaintext.......")
pt = cipher.decrypt(ct)
```

For **2-key** 3DES: PyCryptodome **rejects** keys where `K1 = K3` by default (because it's degenerate). You can pass `DES3.adjust_key_parity` or construct manually:

```python
from Crypto.Cipher import DES3
key_16 = b"1234567812345678"        # 16 bytes (2-key)
# DES3.new(key_16, ...) will fail
# Use raw DES composition instead:
from Crypto.Cipher import DES
def des3_2key_encrypt(k1: bytes, k2: bytes, pt: bytes) -> bytes:
    return DES.new(k1, DES.MODE_ECB).encrypt(
        DES.new(k2, DES.MODE_ECB).decrypt(
            DES.new(k1, DES.MODE_ECB).encrypt(pt)))
```

---

## 2. Weak keys and degenerate cases

### 2.1 Equal keys (collapse to DES)

| Condition | Result |
|---|---|
| `K1 = K2 = K3 = K` | **Single DES** with key `K` |
| `K1 = K2`, `K3` different | **Single DES** with key `K3` |
| `K2 = K3`, `K1` different | **Single DES** with key `K1` |
| `K1 = K3`, `K2` different | **2-key 3DES** with `(K1, K2)` |

**Why?**
```
E(K, D(K, E(K, P))) = E(K, P)    ← inner D(K, ·) cancels inner E(K, ·)
```

### 2.2 Weak DES keys (inherited)

Each of `K1, K2, K3` could be one of the **4 weak DES keys**:
```
0101010101010101
FEFEFEFEFEFEFEFE
E0E0E0E0F1F1F1F1
1F1F1F1F0E0E0E0E
```

If **any** of these appears in `K1, K2, K3` → reduced security.

### 2.3 Detection

```python
WEAK_DES_KEYS = {
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
}

def analyze_3des_key(k1: bytes, k2: bytes, k3: bytes) -> str:
    if k1 == k2 == k3:
        return "SINGLE DES (K1=K2=K3)"
    if k1 == k2:
        return f"SINGLE DES with K3={k3.hex()}"
    if k2 == k3:
        return f"SINGLE DES with K1={k1.hex()}"
    if k1 == k3:
        return "2-KEY 3DES (K1=K3)"
    weak = [i for i, k in enumerate([k1, k2, k3], 1) if k in WEAK_DES_KEYS]
    if weak:
        return f"WEAK DES KEYS at positions {weak}"
    return "Normal 3-key 3DES"
```

### 2.4 When to use
- **Always check first** — a "3DES challenge" with equal keys is just DES.
- In CTF, the challenge often says "3DES" but the key is degenerate (intentionally).

---

## 3. Effective security analysis (why 112 bits, not 168)

### 3.1 Meet-in-the-middle on 2-key 3DES

```
C = E(K1, D(K2, E(K1, P)))
```

Let `X = E(K1, P)`, `Y = D(K1, C)`. Then `Y = D(K2, X)` → `E(K2, Y) = X`.

```
Forward:  for each K1:  X = E(K1, P), Y = D(K1, C)  →  store (X, Y, K1)      [2⁵⁶]
Backward: for each K2:  check E(K2, Y) = X for any stored (X, Y, K1)          [2⁵⁶]
```

**Total time: 2⁵⁶ × 2⁵⁶ = 2¹¹².** Same as brute force — **no gain** for 2-key 3DES.

### 3.2 Van Oorschot–Wiener on 3-key 3DES

```
C = E(K3, D(K2, E(K1, P)))
```

**Naive brute force: 2¹⁶⁸.** The van Oorschot–Wiener attack (1990):

```
1. For each (K1, K2):  V = D(K2, E(K1, P))  →  store V → (K1, K2)          [2¹¹², too much memory]
2. For each K3:        W = D(K3, C)         →  check if W in table         [2⁵⁶ lookups]
```

With **memory-time tradeoff** (partial table):
```
1. For each K1:  store E(K1, P) in hash table                             [2⁵⁶]
2. For each (K2, K3):  compute E(K2, D(K3, C)) and check if in table       [2¹¹² lookups, 2⁵⁶ memory]
```

**Total time: 2¹¹², memory: 2⁵⁶.** So 3-key 3DES provides **only 112-bit security**, not 168.

### 3.3 Reduced-round / reduced-key

For **short keys** (CTF scenario), MITM is very effective:

| Key size (each) | Total brute force | MITM time | MITM memory |
|---|---|---|---|
| 2 × 20-bit (2-key) | 2⁴⁰ | **2⁴⁰** (no gain) | 2²⁰ |
| 2 × 24-bit (2-key) | 2⁴⁸ | 2⁴⁸ | 2²⁴ |
| 3 × 16-bit (3-key) | 2⁴⁸ | **2³²** (MITM helps) | 2¹⁶ |
| 3 × 20-bit (3-key) | 2⁶⁰ | **2⁴⁰** (van Oorschot-Wiener) | 2²⁰ |

**For 2-key**: MITM doesn't speed up brute force, but **reduces memory**.
**For 3-key**: MITM (or van Oorschot-Wiener) gives **huge speedup**.

### 3.4 What this means for CTF

- **2-key 3DES with full 112-bit key**: infeasible.
- **3-key 3DES with full 168-bit key**: infeasible (2¹¹² attack still infeasible).
- **Short keys (≤ 2⁴⁰ total)**: feasible with MITM or brute force.
- **Equal keys / weak keys**: reduces to DES → trivial.

---

## 4. Attack taxonomy

| # | Attack | Input needed | Difficulty |
|---|---|---|---|
| 1 | **Equal keys detection** | Key inspection | Trivial |
| 2 | **Weak DES keys** | Key inspection | Trivial |
| 3 | **Known plaintext → brute force 2⁵⁶** (if K1=K2=K3) | One (p, c) pair | Hours–days |
| 4 | **Known prefix + short unknown** | Partial key + (p,c) | Seconds–minutes |
| 5 | **Dictionary / wordlist** | (p, c) + wordlist | Minutes |
| 6 | **MITM on 3-key with short keys** | 3 × ≤ 20-bit keys | Minutes–hours |
| 7 | **ECB mode detection** | Two ciphertexts | Trivial |
| 8 | **ECB byte-at-a-time** | Oracle access | Easy |
| 9 | **CBC bit-flipping** | Structure + ciphertext | Trivial |
| 10 | **Padding oracle** | Oracle access | Medium |
| 11 | **CFB/OFB malleability** | Structure | Trivial |
| 12 | **Birthday attack on 8-byte blocks** | 2³² blocks | Medium (data) |

Cases 1–5 and 7–9 are CTF-relevant.

---

## 5. Case 1: Equal keys → DES (trivial)

### Description
If `K1 = K2 = K3` (or any two equal), 3DES collapses to single DES. This is the **first thing to check**.

### Detection script
```python
def is_degenerate(k1: bytes, k2: bytes, k3: bytes) -> str | None:
    if k1 == k2 == k3:
        return f"DES with K={k1.hex()}"
    if k1 == k2:
        return f"DES with K3={k3.hex()}"
    if k2 == k3:
        return f"DES with K1={k1.hex()}"
    if k1 == k3:
        return f"2-key 3DES with K1=K3={k1.hex()}"
    return None
```

### When to use
- Challenge gives you the "3DES key" — split into 3 parts, check equality.
- Sometimes the challenge uses `key = b"password" * 3` → all equal!

### Example
```python
key = b"password" * 3        # 24 bytes, but K1=K2=K3=b"password"
print(is_degenerate(key[:8], key[8:16], key[16:24]))
# → "DES with K=70617373776f7264"
```

---

## 6. Case 2: Weak DES keys

### Description
If any of `K1, K2, K3` is one of the **4 weak DES keys**, security is reduced.

### Script
```python
WEAK_DES_KEYS = {
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
}

def check_weak(k1: bytes, k2: bytes, k3: bytes) -> list[str]:
    issues = []
    for i, k in enumerate([k1, k2, k3], 1):
        if k in WEAK_DES_KEYS:
            issues.append(f"K{i} is weak: {k.hex()}")
    return issues
```

### When to use
- Rare, but cheap to check.
- If a challenge explicitly mentions "weak keys".

---

## 7. Case 3: Known plaintext → brute force (only if equal keys)

### Description
If equal keys reduce to DES, brute force `2⁵⁶` — same as DES attack.

### Script
```python
from Crypto.Cipher import DES

def brute_des_3des_equal(known_pt: bytes, known_ct: bytes) -> int:
    for k in range(1 << 56):          # 2^56, impractical in Python
        key = k.to_bytes(8, "big")
        if DES.new(key, DES.MODE_ECB).encrypt(known_pt[:8]) == known_ct[:8]:
            return k
    return -1
```

**Realistically:** use `hashcat -m 14000` or `john` for GPU speedup.

### When to use
- Only if you have GPU/hardware, or the key is short.
- In pure Python: **never** attempt full 2⁵⁶.

---

## 8. Case 4: Known prefix / short unknown (⭐ most likely CTF case)

### Description
The key has a **known structure**:
```
key = b"prefix" + unknown_bytes
```

For 3DES with **24-byte key**, if 18 bytes are known → 6 bytes unknown = 2⁴⁸ → too slow.
If **22 bytes** known → 2 bytes unknown = 2¹⁶ → **seconds**.

### Script: 3-key 3DES with known prefix
```python
from Crypto.Cipher import DES3

def brute_3des_prefix(known_pt: bytes, known_ct: bytes,
                       key_prefix: bytes, unknown_bytes: int) -> bytes | None:
    """Brute-force 3DES with known 24-byte prefix."""
    assert len(key_prefix) + unknown_bytes == 24
    for i in range(1 << (8 * unknown_bytes)):
        suffix = i.to_bytes(unknown_bytes, "big")
        key = key_prefix + suffix
        try:
            if DES3.new(key, DES3.MODE_ECB).encrypt(known_pt[:8]) == known_ct[:8]:
                return key
        except ValueError:      # PyCryptodome rejects degenerate keys
            continue
    return None
```

### Script: 2-key 3DES with known prefix
```python
from Crypto.Cipher import DES

def des3_2key_encrypt(k1: bytes, k2: bytes, pt: bytes) -> bytes:
    return DES.new(k1, DES.MODE_ECB).encrypt(
        DES.new(k2, DES.MODE_ECB).decrypt(
            DES.new(k1, DES.MODE_ECB).encrypt(pt)))

def brute_2des_prefix(known_pt, known_ct, k1_prefix, k2_prefix, unknown):
    """Brute-force 2-key 3DES with known prefixes for both keys."""
    for i in range(1 << (8 * unknown)):
        k1 = k1_prefix + i.to_bytes(unknown, "big")
        for j in range(1 << (8 * unknown)):
            k2 = k2_prefix + j.to_bytes(unknown, "big")
            if des3_2key_encrypt(k1, k2, known_pt[:8]) == known_ct[:8]:
                return k1, k2
    return None
```

**Warning:** for 2-key with 2 unknown bytes each → `2¹⁶ × 2¹⁶ = 2³²` iterations × 3 DES ops each = **way too slow**. Use MITM instead (Case 6).

### When to use
- Challenge gives a **fixed prefix** in the key.
- Key format is `b"COMPANY" + 2 bytes` → 2¹⁶.
- Key = `user_id.to_bytes(4) + b"\x00" * 20` → 2³², feasible with MITM.

---

## 9. Case 5: Dictionary / wordlist attack

### Description
The 3DES key is a **word from a wordlist** (padded / hashed to 24 bytes).

### Script
```python
from Crypto.Cipher import DES3
import hashlib

def crack_3des_wordlist(known_pt: bytes, known_ct: bytes,
                         wordlist: str, derivation: str = "raw") -> tuple[bytes, str] | None:
    """
    derivation options:
      - "raw": word padded with zeros to 24 bytes
      - "raw_pad_space": word padded with spaces
      - "repeat": word repeated 3 times (like DES3 with equal keys)
      - "md5": MD5(word) + MD5(word)[:8] + MD5(word)[:8] (24 bytes)
      - "sha256": SHA256(word)[:24]
    """
    for line in open(wordlist, errors="ignore"):
        pw = line.rstrip("\r\n")
        if not pw: continue
        
        if derivation == "raw":
            key = (pw.encode() + b"\x00" * 24)[:24]
        elif derivation == "raw_pad_space":
            key = (pw.encode() + b" " * 24)[:24]
        elif derivation == "repeat":
            part = (pw.encode() + b"\x00" * 8)[:8]
            key = part * 3
        elif derivation == "md5":
            h = hashlib.md5(pw.encode()).digest()    # 16 bytes
            key = h + h[:8]
        elif derivation == "sha256":
            key = hashlib.sha256(pw.encode()).digest()[:24]
        else:
            continue
        
        if len(key) != 24: continue
        try:
            if DES3.new(key, DES3.MODE_ECB).encrypt(known_pt[:8]) == known_ct[:8]:
                return key, pw
        except ValueError:
            continue
    return None
```

### When to use
- Challenge mentions "password" as key.
- **Check derivation** — challenge code usually reveals it.

---

## 10. Case 6: Meet-in-the-middle on 3-key with short keys (⭐ advanced)

### Description
If `K1, K2, K3` are **short** (e.g., 16 or 20 bits each), MITM is far faster than brute force.

**3-key MITM:**
```
C = E(K3, D(K2, E(K1, P)))
```

**Naive brute force:** `2^(3n)`.

**MITM (van Oorschot–Wiener):**
```
1. For each K1:  E(K1, P)  → store in table                       [2^n]
2. For each K2, K3:  compute E(K2, D(K3, C)) and look up         [2^(2n) lookups]
```

**Total time: max(2^n, 2^(2n)) = 2^(2n)** — huge improvement over `2^(3n)`.

For n = 16: `2^32` lookups ≈ minutes.
For n = 20: `2^40` lookups ≈ days (or use multi-processing).

### Script (n = 16 example)
```python
from Crypto.Cipher import DES

def des_e(k: bytes, pt: bytes) -> bytes: return DES.new(k, DES.MODE_ECB).encrypt(pt)
def des_d(k: bytes, ct: bytes) -> bytes: return DES.new(k, DES.MODE_ECB).decrypt(ct)

def mitm_3des_short(known_pt: bytes, known_ct: bytes,
                     n_bits: int = 16, k_prefix: bytes = b"") -> tuple[bytes, bytes, bytes] | None:
    """
    MITM attack on 3-key 3DES with n_bits unknown per key.
    Total key size = 3 * n_bits.
    """
    pt = known_pt[:8]
    ct = known_ct[:8]
    space = 1 << n_bits
    suffix_len = n_bits // 8

    # Step 1: for each K1, store E(K1, P)
    print("[*] Building table for K1...")
    table = {}
    for i in range(space):
        k1 = k_prefix + i.to_bytes(suffix_len, "big")
        if len(k1) < 8: k1 = k1.rjust(8, b"\x00")
        table[des_e(k1, pt)] = k1
    print(f"[+] Table size: {len(table)}")

    # Step 2: for each (K2, K3), check
    print("[*] Searching (K2, K3)...")
    for i2 in range(space):
        k2 = k_prefix + i2.to_bytes(suffix_len, "big")
        if len(k2) < 8: k2 = k2.rjust(8, b"\x00")
        for i3 in range(space):
            k3 = k_prefix + i3.to_bytes(suffix_len, "big")
            if len(k3) < 8: k3 = k3.rjust(8, b"\x00")
            # Compute: need E(K2, D(K3, C)) = E(K1, P)
            candidate = des_e(k2, des_d(k3, ct))
            if candidate in table:
                k1 = table[candidate]
                # Verify
                test = des_e(k3, des_d(k2, des_e(k1, pt)))
                if test == ct:
                    print(f"[+] Found: K1={k1.hex()} K2={k2.hex()} K3={k3.hex()}")
                    return k1, k2, k3
    return None
```

**Runtime:**
- n = 16: `2^16 + 2^32` ≈ **minutes** (mostly building the table + 2^32 lookups)
- n = 20: `2^20 + 2^40` ≈ **days** (parallelize with multiprocessing)
- n = 24: `2^24 + 2^48` ≈ **infeasible**

### 2-key MITM (no speedup, only memory reduction)

For 2-key with n-bit keys:
- **Direct brute force: 2^(2n)**
- **MITM: 2^(2n) with 2^n memory** (same time, less memory)

MITM on 2-key:
```
1. For each K1:  A = E(K1, P), B = D(K1, C). Store (A, B) → K1.    [2^n]
2. For each K2:  for each stored (A, B, K1):  check if E(K2, B) = A.  [2^n × 2^n = 2^(2n)]
```

**Not a time win** for balanced keys. Only useful if one half is much smaller.

### When to use
- 3-key with 16-bit keys → **2³² ≈ minutes**.
- 3-key with 20-bit keys → **2⁴⁰ ≈ hours** (with multiprocessing).
- 2-key with 20-bit keys → same as brute force `2⁴⁰`.

---

## 11. Case 7: ECB mode detection

### Description
Same as DES (8-byte blocks):
- Same plaintext block → same ciphertext block.
- Detect by looking for repeated 8-byte blocks.

### Script
```python
def detect_ecb(ct: bytes, block_size=8) -> bool:
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))
```

### When to use
- **Before** choosing between ECB/byte-at-a-time vs CBC/bit-flip.
- Same as DES.

---

## 12. Case 8: ECB byte-at-a-time (3DES oracle)

### Description
Same as DES ECB byte-at-a-time, but with 8-byte blocks.

### Script
```python
BLOCK_SIZE = 8

def ecb_byte_at_a_time_3des(oracle, prefix_len=0):
    recovered = b""
    while True:
        pad_len = (BLOCK_SIZE - 1 - (prefix_len + len(recovered)) % BLOCK_SIZE) % BLOCK_SIZE
        filler = b"A" * pad_len
        target_ct = oracle(filler)
        block_idx = (prefix_len + len(recovered)) // BLOCK_SIZE
        for b in range(256):
            guess = filler + recovered + bytes([b])
            guess_ct = oracle(guess)
            if guess_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE] == \
               target_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]:
                recovered += bytes([b])
                break
        else:
            return recovered
```

### When to use
- Server encrypts with 3DES-ECB and appends secret.
- Rare but possible in CTF.

---

## 13. Case 9: CBC bit-flipping (3DES)

### Description
Same as DES CBC bit-flipping (block size 8).

### Script
```python
def cbc_bitflip_3des(ct: bytes, block_idx: int, p_old: bytes, p_new: bytes,
                     block_size=8) -> bytes:
    """Change block (block_idx) plaintext by modifying block (block_idx-1) ciphertext."""
    assert len(p_old) == len(p_new) == block_size
    out = bytearray(ct)
    prev_start = (block_idx - 1) * block_size
    for i in range(block_size):
        out[prev_start + i] ^= p_old[i] ^ p_new[i]
    return bytes(out)
```

### When to use
- Cookie manipulation in 3DES-CBC.
- Same as DES.

---

## 14. Case 10: Padding oracle

### Description
Same as DES padding oracle, but for 8-byte blocks (3DES).

### Script (reuse from DES section)
```python
# Same as DES padding oracle — block_size = 8
def padding_oracle_attack_3des(oracle, ct, block_size=8):
    # (see DES section for full implementation)
    ...
```

### When to use
- Server distinguishes padding errors.
- Same as DES.

---

## 15. Case 11: CFB/OFB malleability

### Description
Same as DES (stream-like modes).

### Script
```python
def cfb_bitflip_3des(ct: bytes, pos: int, p_old: int, p_new: int) -> bytes:
    out = bytearray(ct)
    out[pos] ^= p_old ^ p_new
    return bytes(out)
```

### When to use
- Stream mode in 3DES — same as DES.

---

## 16. Case 12: Birthday attack on 8-byte blocks

### Description
64-bit block → after **2³² blocks** (= 32 GB), ciphertext blocks start colliding (birthday paradox). This is why **64-bit block ciphers are deprecated** (SWEET32 attack, 2016).

### Script (detection)
```python
def detect_cbc_collision(ct: bytes, block_size=8) -> bool:
    """If two blocks have the same ciphertext, birthday attack succeeded."""
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))

# In practice: watch for duplicate ciphertext blocks in a long stream
```

### When to use
- Long-lived connections with 3DES-CBC (TLS 1.0/1.1).
- **SWEET32**: 32 GB of data with same key/IV → collision.
- **Rare in CTF** (requires huge ciphertext).

---

## 17. Comparison: DES vs 3DES vs AES

| Aspect | DES | 2-key 3DES | 3-key 3DES | AES-128 |
|---|---|---|---|---|
| Key bits (nominal) | 56 | 112 | 168 | 128 |
| Effective security | 2⁵⁶ (broken) | 2¹¹² | **2¹¹²** | 2¹²⁸ |
| Block size | 64 | 64 | 64 | 128 |
| DES ops per block | 16 | 48 | 48 | ~10 (AES ops) |
| Speed (relative to DES) | 1× | 3× slower | 3× slower | **~50× faster** |
| Birthday attack (8-byte block) | 2³² | 2³² | 2³² | 2⁶⁴ |
| NIST status (2024) | **Disallowed** | **Disallowed** | **Disallowed** | **Approved** |
| CTF relevance | High | Medium | Medium | High |

**Why 2-key 3DES effective security = 3-key = 2¹¹²?**
- 2-key: MITM gives 2¹¹² (no win over brute force).
- 3-key: van Oorschot–Wiener gives 2¹¹² (win over brute-force 2¹⁶⁸).

So **both are 2¹¹² security** — the third key adds no effective security!

**This is why NIST is retiring 3DES entirely.** The recommended replacement is **AES** (or in legacy contexts, AES-128).

---

## 18. Mapping to session tasks

3DES is **not in any of the explicit session tasks**, but its principles appear:

| Task | Cipher | 3DES relevance |
|---|---|---|
| **Key standardisation** | DES-ECB | Same prefix-brute-force approach (§8) — 3DES variant if key is 24 bytes |
| **Noncense** | AES-CTR | Different cipher, same nonce-reuse principles |
| **Secure Bank** | Salsa20 | Different cipher |
| **Secure Bank 2** | SHA-256 truncated | Different primitive |
| **Better Hash** | Custom hash | Different primitive |
| **Security Cam** | RTSP/MD5 | Different primitive |
| **Signed, Sealed** | HMAC-SHA256 | Different primitive |
| **Token of Trust** | JWT | Different primitive |
| **Replanting** | LCG | Different primitive |

**If a 3DES challenge appears** (in future sessions or as a bonus), the approach is:

1. **Check equal keys** (Case 1) → DES.
2. **Check weak keys** (Case 2).
3. **Check prefix structure** (Case 4) → brute force short suffix.
4. **Check dictionary** (Case 5) → wordlist attack.
5. **Check mode** (Case 7/9/11) → ECB vs CBC vs CFB/OFB.
6. **MITM** (Case 6) only if 3 separate short keys.

---

## 19. Defender perspective

| Mistake | Fix |
|---|---|
| Using 3DES at all | **Migrate to AES** — NIST disallows 3DES (SP 800-131A Rev.2, 2019) |
| Equal keys (K1=K2=K3) | Never — degenerate to DES |
| Weak DES keys | Never — use **random 3-key 3DES** (if forced) or **AES** |
| 2-key 3DES | Deprecated — 112-bit security, birthday attack at 2³² blocks |
| 3-key 3DES | Deprecated — only 112-bit security (van Oorschot-Wiener) |
| ECB mode | Use **CBC/GCM** |
| No IV / fixed IV | Random IV per message |
| No integrity | **AES-GCM** or **AES-CCM** (AEAD) |
| Block size 64 bits | **AES has 128-bit blocks** — no birthday attack until 2⁶⁴ |
| Slow performance | **AES is 50× faster** — better for everything |

**NIST guidance (2024):**
- **2-key 3DES: disallowed** since 2019 (SP 800-131A).
- **3-key 3DES: legacy**, retiring by 2023 for government use.
- **AES: only approved** symmetric cipher.

**If you must use 3DES** (legacy system):
- 3-key (K1≠K2≠K3) — not 2-key, not equal keys.
- Random keys from CSPRNG — not derived from passwords.
- CBC or CTR mode with random IV.
- Add HMAC-SHA256 for integrity (encrypt-then-MAC).
- Rotate keys every 2³¹ blocks (to avoid birthday).

---

## 20. Ready-to-use `des3_toolkit.py`?

Same structure as previous toolkits. Options:

- **A)** Build `des3_toolkit.py` with:
  ```
  - des3_2key_encrypt(k1, k2, pt) / des3_2key_decrypt(k1, k2, ct)
  - des3_3key_encrypt(k1, k2, k3, pt) / des3_3key_decrypt(k1, k2, k3, ct)
  - analyze_key(k1, k2, k3) -> str             # detect equal/weak keys
  - brute_prefix_3des(known_pt, known_ct, prefix, n_unknown) -> key
  - crack_wordlist_3des(known_pt, known_ct, wordlist, derivation) -> (key, pw)
  - mitm_3des_short(known_pt, known_ct, n_bits) -> (k1, k2, k3)
  - detect_ecb(ct) -> bool
  - cbc_bitflip_3des(ct, block_idx, p_old, p_new) -> new_ct
  - ecb_byte_at_a_time_3des(oracle) -> plaintext
  ```
  + CLI:
  ```
  python des3_toolkit.py analyze    --key hex
  python des3_toolkit.py decrypt    --key hex --ct hex --variant 2key|3key
  python des3_toolkit.py brute      --pt "..." --ct hex --prefix hex --unknown 2
  python des3_toolkit.py wordlist   --pt "..." --ct hex --wordlist rockyou.txt --derivation md5
  python des3_toolkit.py mitm       --pt "..." --ct hex --n-bits 16
  python des3_toolkit.py ecb-detect --ct hex
  python des3_toolkit.py bitflip    --ct hex --old hex --new hex
  ```
