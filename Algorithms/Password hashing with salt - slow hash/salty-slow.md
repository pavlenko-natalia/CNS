# CCM / GCM (Authenticated Encryption): Theory, Every Attack Case, Ready-to-Use Scripts

CCM and GCM are the **two NIST-standardized AEAD modes** (Authenticated Encryption with Associated Data). They provide **confidentiality + integrity + authenticity in one primitive** — unlike AES-CTR/CBC/ECB, which need a separate MAC. They're the **modern default** in TLS 1.3, WPA2, IPSec, Bluetooth LE.

**For your session**: no explicit CCM/GCM task, but **Noncense** uses **AES-CTR** — the same nonce reuse attack applies, just without the MAC. And the **theory exam** has questions about AEAD orderings.

This section covers:
- CCM and GCM internals
- **The #1 attack: nonce reuse** (catastrophic for both)
- **GCM-specific: GHASH key recovery** → full forgery
- All other attacks
- Ready-to-run scripts
- Exam answers

---

## 1. What is AEAD (formally)

**AEAD** = **A**uthenticated **E**ncryption with **A**ssociated **D**ata.

A single algorithm that produces:
- **Ciphertext `C`** (encrypted plaintext `P`).
- **Authentication tag `T`** (integrity + authenticity of `C`, `P`, `AAD`).
- **AAD** (Additional Authenticated Data): **authenticated but NOT encrypted** — e.g., protocol headers.

### 1.1 API

```
(C, T) = AEAD_Encrypt(K, N, P, AAD)
P      = AEAD_Decrypt(K, N, C, T, AAD)   → raises/returns FAIL on tag mismatch
```

**Parameters:**
- `K` = key
- `N` = nonce (must be unique per key)
- `P` = plaintext
- `AAD` = associated data
- `T` = tag (`128` bits standard)

### 1.2 Properties (memorize)

| Property | CCM / GCM |
|---|---|
| Confidentiality | ✅ |
| Integrity (ciphertext) | ✅ (tag covers `C`) |
| Integrity (AAD) | ✅ (tag covers `AAD`) |
| **Nonce reuse** | ❌ **catastrophic** |
| **Malleability** | ❌ **blocked** (tag fails on any change) |
| **Length extension** | ❌ N/A (not a hash) |
| **Padding oracle** | ❌ N/A (no padding) |
| **Key recovery** | ❌ infeasible (2¹²⁸) |

**The only practical attack is nonce reuse** — everything else requires implementation bugs.

### 1.3 The two AEAD modes

| Aspect | CCM | GCM |
|---|---|---|
| Standard | NIST SP 800-38C | NIST SP 800-38D |
| Construction | CTR + CMAC | CTR + GHASH |
| Ordering | **Encrypt-and-MAC** | **Encrypt-then-MAC** |
| Passes over plaintext | **2** (CMAC + CTR) | 1 (CTR only, GHASH over ciphertext) |
| Parallelism | Encryption ✅ / CMAC ❌ | ✅ both |
| Speed (AES-NI) | Moderate | **Very fast** |
| Nonce size | 7–13 bytes | 12 bytes (recommended), 1–2¹⁶ arbitrary |
| Tag size | 4–16 bytes | 12–16 bytes (4, 8 allowed with restrictions) |
| Used by | WPA2, Bluetooth LE, Zigbee, TLS 1.2 (some) | **TLS 1.3**, IPSec, SSH, HTTPS |

**Rule of thumb:**
- **GCM** = default for new systems (fast, standardized).
- **CCM** = embedded / constrained (WPA2, IoT).

### 1.4 Standard Python usage

```python
from Crypto.Cipher import AES

# CCM
cipher = AES.new(key, AES.MODE_CCM, nonce=nonce_7_to_13, mac_len=16)
cipher.update(aad)
ct, tag = cipher.encrypt_and_digest(plaintext)

# GCM
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_12, mac_len=16)
cipher.update(aad)
ct, tag = cipher.encrypt_and_digest(plaintext)

# Decryption + verification (raises ValueError on tag mismatch)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_12, mac_len=16)
cipher.update(aad)
pt = cipher.decrypt_and_verify(ct, tag)
```

---

## 2. CCM — Counter with CBC-MAC

### 2.1 How CCM works

**CCM = CTR (encryption) + CMAC (authentication)** with **one key**.

**Input format:**
```
B_0 = nonce || AAD_length || P_length       (block with metadata)
B_i = AAD blocks (zero-padded to block)
B_j = P blocks
```

**Step 1: Compute CMAC over `B_0 || B_1 || ... || B_n`** → tag `T`.
**Step 2: Encrypt `P` with CTR mode starting at counter `A_0`** (different from `B_0`).
**Step 3: Encrypt tag `T` with CTR at counter `A_0`** → final `T_ct`.

**Output:** `(C = E_CTR(P), T_ct = E_CTR(T))`.

**Decryption:** reverse.

### 2.2 CCM parameters

| Parameter | Range | Notes |
|---|---|---|
| Nonce `N` | **7–13 bytes** | Tradeoff with `L` (message length field) |
| Tag `T` | **4–16 bytes** (even values) | 16 recommended |
| `L` = length field | `15 - len(N)` bytes | Encodes message length |
| Max message | `2^(8L) - 1` bytes | For nonce=12, L=3 → 16 MB |

**Nonce-length tradeoff:**
- **Longer nonce** → **shorter max message** (fewer length bytes).
- **Shorter nonce** → **larger max message** but **higher collision risk**.

**Recommended:** nonce = 12 bytes, L = 3 bytes, max message = 16 MB.

### 2.3 CCM-specific vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Nonce reuse** | Same as CTR — keystream reuse + same CMAC |
| 2 | **Short nonce (< 12 bytes)** | Higher collision probability |
| 3 | **Tag truncation** | Birthday attack on tag |
| 4 | **AAD length overflow** | Implementation bug |
| 5 | **Tag comparison non-constant-time** | Timing attack |

### 2.4 Full CCM script

```python
#!/usr/bin/env python3
"""CCM encrypt / decrypt + nonce reuse attack."""
from Crypto.Cipher import AES


def ccm_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                 aad: bytes = b"", tag_len: int = 16) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=tag_len)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def ccm_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes,
                 aad: bytes = b"") -> bytes:
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=len(tag))
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


# Nonce reuse attack on CCM (same as CTR for decryption)
def ccm_nonce_reuse_decrypt(c1: bytes, c2: bytes, known_pt: bytes) -> bytes:
    """CCM with reused nonce → keystream reuse → two-time pad."""
    ks = bytes(p ^ c for p, c in zip(known_pt, c1))
    return bytes(c ^ k for c, k in zip(c2, ks))


if __name__ == "__main__":
    key = bytes(16)
    nonce = bytes(12)
    aad = b"header"

    # Normal use
    pt = b"secret message"
    ct, tag = ccm_encrypt(key, nonce, pt, aad)
    print(f"[+] CT:  {ct.hex()}")
    print(f"[+] Tag: {tag.hex()}")
    print(f"[+] PT:  {ccm_decrypt(key, nonce, ct, tag, aad)}")

    # Nonce reuse demo
    c1, t1 = ccm_encrypt(key, nonce, b"ATTACK AT DAWN", aad)
    c2, t2 = ccm_encrypt(key, nonce, b"secret message", aad)
    print(f"\n[+] c1: {c1.hex()}")
    print(f"[+] c2: {c2.hex()}")
    # c1 ⊕ c2 = p1 ⊕ p2
    x = bytes(a ^ b for a, b in zip(c1, c2))
    print(f"[+] p1 ⊕ p2: {x.hex()}")
    # With known p1, recover p2
    p2 = ccm_nonce_reuse_decrypt(c1, c2, b"ATTACK AT DAWN")
    print(f"[+] p2: {p2}")
```

---

## 3. GCM — Galois/Counter Mode

### 3.1 How GCM works

**GCM = CTR (encryption) + GHASH (authentication)** with **one key**.

**Setup:**
- `H = E_K(0^128)` — the **hash key** (never reused)
- `J_0 = IV || 0^31 || 1` (for 96-bit IV) or `GHASH(IV)` — the pre-counter

**Step 1: Encrypt `P` with GCTR** starting at `inc(J_0)`:
```
C = GCTR_K(inc(J_0), P)        ← same as CTR
```

**Step 2: Compute GHASH over AAD || C || lengths:**
```
S = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
```
Where `GHASH_H(X)` = polynomial evaluation in `GF(2^128)`:
```
GHASH_H(X) = X_1 · H^m ⊕ X_2 · H^(m-1) ⊕ ... ⊕ X_m · H
```

**Step 3: Tag = `E_K(J_0) ⊕ S`:**
```
T = E_K(J_0) ⊕ GHASH_H(A || C || lengths)
```

**Output:** `(C, T)`.

**Decryption:** reverse + verify tag.

### 3.2 GCM parameters

| Parameter | Range | Recommended |
|---|---|---|
| Nonce `N` | **12 bytes** (96 bits) | ✅ |
| Nonce `N` (alternative) | 1–2⁶⁴ bytes | Any other size → `J_0` uses GHASH |
| Tag `T` | 16 bytes | ✅ (or 4, 8 with restrictions) |
| Max message | ~ 64 GB (per key/nonce) | 2³⁹ - 256 bits |

**⚠️ Counter limit:** 32-bit counter → **2³² blocks = 64 GB max per `(key, nonce)`**.

### 3.3 GCM-specific vulnerabilities

| # | Vulnerability | Impact |
|---|---|---|
| 1 | **Nonce reuse** | **Both** keystream reuse **AND** GHASH key recovery → **full forgery** |
| 2 | **Short nonce (< 12 bytes)** | `J_0` uses GHASH → slower, more collision risk |
| 3 | **Tag truncation** | Forgery via birthday (but `2^(t/2)` for `t`-bit tag) |
| 4 | **AAD not verified** | Implementation bug |
| 5 | **Counter overflow (> 64 GB)** | Keystream reuse |
| 6 | **GHASH timing** | Cache attacks on `H` |
| 7 | **Weak key** | Dictionary attack |

**The #1 practical attack: nonce reuse → GHASH key recovery.**

---

## 4. The catastrophic attack: nonce reuse in GCM ⭐⭐⭐

### 4.1 Why it's so bad

Nonce reuse in GCM:
1. **Breaks confidentiality** (keystream reuse → `c1 ⊕ c2 = p1 ⊕ p2`).
2. **Breaks authenticity** — because GHASH is **linear in H**, two tags with the same `E_K(J_0)` and different `(A, C)` give:
   ```
   T1 ⊕ T2 = GHASH_H(A1, C1) ⊕ GHASH_H(A2, C2)
   ```
   Since `GHASH_H(X)` is a polynomial in `H`, this is **one equation with one unknown `H`**.
3. Once `H` is recovered → forge **any tag** for **any message** → complete break.

### 4.2 Step-by-step attack

**Step 1: Recover keystream from known plaintext.**
```
keystream = p1 ⊕ c1
p2 = c2 ⊕ keystream
```

**Step 2: Recover `S_key = E_K(J_0)` from two tags:**
```
T1 = S_key ⊕ GHASH_H(A1, C1)
T2 = S_key ⊕ GHASH_H(A2, C2)
```
If `A1 = A2` (same AAD): `T1 ⊕ T2 = GHASH_H(C1) ⊕ GHASH_H(C2)`.

**Step 3: Solve for `H`:**
`GHASH_H(C1) ⊕ GHASH_H(C2)` is a **polynomial in `H`** of degree `m` (number of blocks). Solve in `GF(2^128)`.

**Step 4: Forge tags** for arbitrary `(A', C')`:
```
T' = S_key ⊕ GHASH_H(A', C')
```

**Step 5: Decrypt any ciphertext** with recovered keystream.

### 4.3 Full implementation

**Install `galois` first:** `pip install galois`

```python
#!/usr/bin/env python3
"""Full GCM nonce reuse attack — decrypt AND forge tags."""
import struct
from Crypto.Cipher import AES

try:
    import galois
    GF = galois.GF(2**128, irreducible_poly="x^128 + x^7 + x^2 + x + 1")
    HAS_GALOIS = True
except ImportError:
    print("[!] pip install galois (needed for GHASH key recovery)")
    HAS_GALOIS = False


# ============================================================
# GCM internals
# ============================================================

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def ghash(H: bytes, A: bytes, C: bytes) -> bytes:
    """Compute GHASH_H(A || 0^v || C || 0^u || len(A)||len(C))."""
    if not HAS_GALOIS:
        raise ImportError("pip install galois")
    
    # Pad A to 16-byte multiple
    A_pad = A + b"\x00" * ((16 - len(A) % 16) % 16)
    # Pad C to 16-byte multiple
    C_pad = C + b"\x00" * ((16 - len(C) % 16) % 16)
    
    # Lengths block
    len_block = struct.pack(">QQ", len(A) * 8, len(C) * 8)
    
    # Concatenate
    X = A_pad + C_pad + len_block
    
    # Convert H and X to GF(2^128) elements (big-endian per NIST)
    H_int = int.from_bytes(H, "big")
    y = 0
    for i in range(0, len(X), 16):
        block = int.from_bytes(X[i:i+16], "big")
        y = int(GF(y ^ block) * GF(H_int))
    
    return y.to_bytes(16, "big")


def recover_h_from_two_tags(A1: bytes, C1: bytes, T1: bytes,
                              A2: bytes, C2: bytes, T2: bytes) -> bytes:
    """
    Recover GHASH key H from two (A, C, T) triples with same nonce.
    Uses T1 ⊕ T2 = GHASH_H(A1, C1) ⊕ GHASH_H(A2, C2).
    """
    if not HAS_GALOIS:
        raise ImportError("pip install galois")
    
    # Build the polynomial in H:
    # GHASH_H(X) = X_1·H^m ⊕ X_2·H^(m-1) ⊕ ... ⊕ X_m·H
    # where X = A || 0^v || C || 0^u || len
    
    def poly_coeffs(A: bytes, C: bytes) -> list[int]:
        """Coefficients from MSB (H^m) to LSB (H^1)."""
        A_pad = A + b"\x00" * ((16 - len(A) % 16) % 16)
        C_pad = C + b"\x00" * ((16 - len(C) % 16) % 16)
        len_block = struct.pack(">QQ", len(A) * 8, len(C) * 8)
        X = A_pad + C_pad + len_block
        
        coeffs = []
        for i in range(0, len(X), 16):
            coeffs.append(int.from_bytes(X[i:i+16], "big"))
        return coeffs  # length m (number of blocks)
    
    c1 = poly_coeffs(A1, C1)
    c2 = poly_coeffs(A2, C2)
    
    # Pad shorter to same length (leading zeros)
    m = max(len(c1), len(c2))
    c1 = [0] * (m - len(c1)) + c1
    c2 = [0] * (m - len(c2)) + c2
    
    # Target = T1 ⊕ T2
    target = int.from_bytes(xor_bytes(T1, T2), "big")
    
    # Polynomial: sum (c1[i] ⊕ c2[i]) · H^(m - i) = target
    coeffs_int = [c1[i] ^ c2[i] for i in range(m)]
    
    # Build GF polynomial and find roots
    # Polynomial: target + sum coeffs[i] · x^(m-i) = 0
    poly_coeffs_gf = [GF(target)] + [GF(c) for c in coeffs_int]
    
    # Remove leading zeros
    while poly_coeffs_gf and poly_coeffs_gf[0] == 0:
        poly_coeffs_gf = poly_coeffs_gf[1:]
    
    if not poly_coeffs_gf:
        raise ValueError("Trivial polynomial — messages identical?")
    
    poly = galois.Poly(poly_coeffs_gf, field=GF)
    roots = poly.roots()
    
    # Filter to plausible H (should be the only root that's nonzero)
    for r in roots:
        h_bytes = int(r).to_bytes(16, "big")
        if h_bytes != b"\x00" * 16:
            return h_bytes
    
    raise ValueError(f"No valid H recovered, roots: {roots}")


def forge_gcm_tag(H: bytes, S_key: bytes, A: bytes, C: bytes) -> bytes:
    """Forge tag given recovered H and S_key = E_K(J_0)."""
    if not HAS_GALOIS:
        raise ImportError("pip install galois")
    return xor_bytes(S_key, ghash(H, A, C))


# ============================================================
# Attack driver
# ============================================================

def gcm_nonce_reuse_attack(
    nonce: bytes,
    A1: bytes, C1: bytes, T1: bytes,
    A2: bytes, C2: bytes, T2: bytes,
    known_pt1: bytes = None,
) -> dict:
    """
    Full GCM nonce reuse attack.
    
    Args:
        nonce: reused nonce
        A1, C1, T1: first (AAD, ciphertext, tag)
        A2, C2, T2: second (AAD, ciphertext, tag)
        known_pt1: optional known plaintext of first message
    
    Returns:
        dict with keys:
          - keystream: recovered keystream
          - p2: decrypted second plaintext (if known_pt1)
          - H: recovered GHASH key
          - S_key: E_K(J_0) recovered
          - can_forge: True (we can now forge any tag)
    """
    result = {}
    
    # Step 1: Recover keystream if known plaintext
    if known_pt1 and len(known_pt1) >= len(C1):
        keystream = xor_bytes(known_pt1[:len(C1)], C1)
        result["keystream"] = keystream
        result["p2"] = xor_bytes(C2[:len(keystream)], keystream[:len(C2)])
    
    # Step 2: Recover H
    if HAS_GALOIS:
        H = recover_h_from_two_tags(A1, C1, T1, A2, C2, T2)
        result["H"] = H
        
        # Step 3: Recover S_key
        S1 = ghash(H, A1, C1)
        S_key = xor_bytes(T1, S1)
        result["S_key"] = S_key
        result["can_forge"] = True
    
    return result


# ============================================================
# Demo
# ============================================================

if __name__ == "__main__":
    from Crypto.Cipher import AES

    key = bytes(16)
    nonce = bytes(12)

    # Encrypt two messages with SAME nonce (the bug)
    def gcm_encrypt(pt, aad=b""):
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        return c.encrypt_and_digest(pt)
    
    A1, pt1 = b"header", b"ATTACK AT DAWN"
    A2, pt2 = b"header", b"Secret message here"
    C1, T1 = gcm_encrypt(pt1, A1)
    C2, T2 = gcm_encrypt(pt2, A2)

    print("[+] Nonce reuse:")
    print(f"    C1: {C1.hex()}")
    print(f"    T1: {T1.hex()}")
    print(f"    C2: {C2.hex()}")
    print(f"    T2: {T2.hex()}")

    # Attack with known plaintext 1
    result = gcm_nonce_reuse_attack(
        nonce, A1, C1, T1, A2, C2, T2, known_pt1=pt1)

    if "keystream" in result:
        print(f"\n[+] Recovered keystream: {result['keystream'].hex()}")
        print(f"[+] Decrypted p2: {result['p2']}")
        print(f"[+] Should be:     {pt2}")

    if "H" in result:
        print(f"\n[+] Recovered H:  {result['H'].hex()}")
        print(f"[+] Recovered S_key: {result['S_key'].hex()}")

        # Forge a tag for a NEW message
        evil_pt = b"PAY BOB 1000000"
        evil_C = xor_bytes(evil_pt, result["keystream"][:len(evil_pt)])
        evil_A = b"header"
        evil_T = forge_gcm_tag(result["H"], result["S_key"], evil_A, evil_C)
        print(f"\n[+] Forged (C, T) for evil message:")
        print(f"    C: {evil_C.hex()}")
        print(f"    T: {evil_T.hex()}")

        # Verify forgery by decrypting with server
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(evil_A)
        try:
            dec = cipher.decrypt_and_verify(evil_C, evil_T)
            print(f"[+] Server accepts forged message: {dec}")
        except ValueError:
            print("[!] Forgery failed")
```

### 4.4 How the session task would look

If a GCM nonce reuse task appears:
1. Connect and get **two encrypted messages** with the **same nonce**.
2. Use `gcm_nonce_reuse_attack` with:
   - Known plaintext if available (e.g., a fixed message).
   - Or use **crib dragging** if no known plaintext.
3. Forge any message and submit.

**For Noncense**: uses **CTR** (not GCM) — simpler. Just `c1 ⊕ c2 ⊕ known_pt` (§8 of OTP). No GHASH needed.

---

## 5. Attack — keystream reuse (nonce reuse decryption, works for both CCM and GCM)

### 5.1 Simple script (no GHASH recovery)

```python
#!/usr/bin/env python3
"""CCM/GCM nonce reuse — decryption only (no tag forgery)."""
from Crypto.Cipher import AES


def nonce_reuse_decrypt(c1: bytes, c2: bytes, known_pt: bytes = None) -> bytes:
    """Given two ciphertexts with same nonce:
    - If known_pt: recover p2.
    - Otherwise: return p1 ⊕ p2 (crib drag).
    """
    if known_pt:
        ks = bytes(p ^ c for p, c in zip(known_pt, c1))
        return bytes(c ^ k for c, k in zip(c2, ks))
    return bytes(a ^ b for a, b in zip(c1, c2))


def crib_drag(x: bytes, crib: bytes):
    """x = p1 ⊕ p2, find where crib matches p1."""
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if all(32 <= b < 127 or b in (9, 10, 13) for b in guess):
            yield i, guess


# Session task: Noncense (AES-CTR, but same math)
def noncense_solve():
    c_flag  = bytes.fromhex("def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c")
    c_known = bytes.fromhex("fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a")
    known_pt = b"According to all known laws of aviation, there is no way a bee should be able to fly."
    
    n = len(c_flag)
    p_flag = bytes(a ^ b ^ c for a, b, c in zip(c_flag, c_known[:n], known_pt[:n]))
    return p_flag


if __name__ == "__main__":
    print(f"[+] Noncense flag: {noncense_solve()}")
```

**This is the actual attack for Noncense.** No GHASH, no forgery, just XOR.

---

## 6. Attack — weak key (wordlist)

### 6.1 Script

```python
#!/usr/bin/env python3
"""Crack CCM/GCM with weak key (wordlist)."""
from Crypto.Cipher import AES
import argparse


def crack_wordlist(ct: bytes, tag: bytes, nonce: bytes, aad: bytes,
                    wordlist: str, mode: str = "GCM",
                    key_len: int = 16, mac_len: int = 16) -> tuple[bytes, str] | None:
    """Try each password as AES key, verify tag."""
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            key = (pw + b"\x00" * key_len)[:key_len]
            
            try:
                if mode == "GCM":
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=mac_len)
                elif mode == "CCM":
                    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
                else:
                    continue
                cipher.update(aad)
                cipher.decrypt_and_verify(ct, tag)
                return key, pw.decode(errors="replace")
            except (ValueError, TypeError):
                continue
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ct", required=True, help="ciphertext (hex)")
    ap.add_argument("--tag", required=True, help="tag (hex)")
    ap.add_argument("--nonce", required=True, help="nonce (hex)")
    ap.add_argument("--aad", default="", help="AAD (hex)")
    ap.add_argument("--mode", default="GCM", choices=["GCM", "CCM"])
    ap.add_argument("--wordlist", default="rockyou.txt")
    ap.add_argument("--key-len", type=int, default=16)
    args = ap.parse_args()

    result = crack_wordlist(
        bytes.fromhex(args.ct), bytes.fromhex(args.tag),
        bytes.fromhex(args.nonce), bytes.fromhex(args.aad),
        args.wordlist, args.mode, args.key_len,
    )
    if result:
        key, pw = result
        print(f"[+] KEY: {key.hex()}")
        print(f"[+] PW:  {pw}")
    else:
        print("[!] Not found")
```

### 6.2 When to use

- **Weak password-derived key**.
- **Rare** — AEAD keys are typically proper random 128/256-bit.

---

## 7. Attack — tag truncation (birthday)

### 7.1 Description

If the server uses a **short tag** (e.g., 4 bytes = 32 bits), a **birthday attack** finds two messages with the same tag.

**CCM tag sizes:** 4, 6, 8, 10, 12, 14, 16 bytes.
**GCM tag sizes:** 4, 8, 12, 13, 14, 15, 16 bytes (4 and 8 discouraged).

### 7.2 Script

```python
#!/usr/bin/env python3
"""Birthday attack on truncated AEAD tag."""
import os
from Crypto.Cipher import AES


def find_tag_collision(key: bytes, nonce: bytes, aad: bytes = b"",
                        trunc_bytes: int = 4, mode: str = "GCM"):
    """Find two plaintexts with same truncated AEAD tag."""
    seen = {}
    for i in range(1 << 30):
        pt = os.urandom(8)
        if mode == "GCM":
            c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=trunc_bytes)
            c.update(aad)
            _, tag = c.encrypt_and_digest(pt)
        elif mode == "CCM":
            c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=trunc_bytes)
            c.update(aad)
            _, tag = c.encrypt_and_digest(pt)
        else:
            raise ValueError(mode)
        
        if tag in seen and seen[tag] != pt:
            return seen[tag], pt, tag
        seen[tag] = pt
    return None


if __name__ == "__main__":
    import time
    key = bytes(16)
    nonce = bytes(12)
    
    print("[*] Finding truncated AEAD tag collision (4 bytes)...")
    t0 = time.time()
    result = find_tag_collision(key, nonce, trunc_bytes=4)
    if result:
        pt1, pt2, tag = result
        print(f"[+] Collision after {time.time()-t0:.1f}s")
        print(f"    tag:  {tag.hex()}")
        print(f"    pt1:  {pt1.hex()}")
        print(f"    pt2:  {pt2.hex()}")
```

### 7.3 When to use

- Task uses `mac_len < 16`.
- **Rare** — most implementations use full 16-byte tags.

---

## 8. Attack — AAD not verified (implementation bug)

### 8.1 Description

Some implementations **forget to include AAD in the tag computation**:
```python
# BAD — AAD not authenticated!
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ct, tag = cipher.encrypt_and_digest(pt)
# AAD is never updated → attacker can change it freely
```

If the **AAD contains access control info** (e.g., `role=user`), you can **modify AAD without breaking the tag**.

### 8.2 Detection

```python
def detect_aad_not_verified(key: bytes, nonce: bytes,
                              ct: bytes, tag: bytes,
                              aad_original: bytes, aad_modified: bytes) -> bool:
    """
    True if server accepts modified AAD with original tag.
    (Indicates AAD was NOT authenticated during encryption.)
    """
    from Crypto.Cipher import AES
    
    # Try decrypting with modified AAD
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad_modified)   # DIFFERENT AAD
    try:
        cipher.decrypt_and_verify(ct, tag)
        return True   # AAD was not authenticated!
    except ValueError:
        return False  # AAD properly authenticated
```

### 8.3 Attack

If AAD is not authenticated:
- **Modify AAD freely** — e.g., change `role=user` to `role=admin`.
- **Keep the same tag** — server accepts.

### 8.4 When to use

- Read the source code — look for missing `cipher.update(aad)`.
- **Not in your session tasks** (all use standard libraries correctly).

---

## 9. Attack — nonce reuse in CCM (specifics)

### 9.1 Description

**CCM nonce reuse** is **similar** to GCM but **different** in impact:

**What breaks:**
1. **Confidentiality** — keystream reuse (`c1 ⊕ c2 = p1 ⊕ p2`).
2. **Integrity** — same CMAC for same plaintext, but **CMAC key cannot be recovered** from two tags (unlike GCM's GHASH).

**Why CCM is safer:**
- CMAC is **non-linear in the key** (uses AES encryption internally, not polynomial).
- Two tags with same key → **no algebraic shortcut** to recover the key.
- **You still need the actual key** to forge new tags.

**What you can do:**
- **Decrypt** with keystream reuse (same as GCM).
- **Forge messages** only if you know plaintext structure (bit-flipping, but the tag must match).
- **Cannot forge arbitrary tags** without key.

### 9.2 Detection

**CCM vs GCM nonce reuse:**
- **CCM:** recover plaintext but **not tag forgery**.
- **GCM:** recover plaintext **AND forge tags** (via GHASH key recovery).

**For the session:** if a task says "CCM" and nonce reuse → **decrypt only**. If "GCM" → **decrypt + forge**.

---

## 10. Attack — GCM counter overflow (> 64 GB)

### 10.1 Description

GCM's counter is **32 bits**. After **2³² blocks = 64 GB** with the same `(key, nonce)`, the counter **wraps around to 0** → **keystream repeats**.

**In practice:**
- Servers rarely encrypt 64 GB with one nonce.
- But **long-lived TLS sessions** or **file encryption** could hit it.
- **NIST recommends** rotating keys before 64 GB.

### 10.2 Detection

```python
def detect_counter_overflow(total_encrypted: int, nonce_reuse: bool) -> bool:
    """If > 64 GB with same nonce, counter overflow."""
    max_per_nonce = 2**32 * 16   # 2^32 blocks × 16 bytes = 64 GB
    return total_encrypted > max_per_nonce
```

### 10.3 When to use

- **Very rare in CTF** — requires 64 GB of data.
- **Not in your session tasks.**

---

## 11. Attack — library misuse / mode confusion

### 11.1 Common mistakes

| Bug | Example | Impact |
|---|---|---|
| **Wrong nonce length** | GCM with 16-byte nonce (should be 12) | `J_0` uses GHASH → slower, still secure |
| **CCM with 16-byte nonce** | Nonce = 16 bytes | **Error** (CCM max 13) |
| **Short tag not checked** | `mac_len=4` but server compares full | Tampering works |
| **Nonce from user input** | `nonce = request.args["nonce"]` | **Full break** — attacker chooses nonce |
| **Nonce counter reset** | Server restarts → nonce=0 | Two-time pad |

### 11.2 Detection

```python
def audit_aead_usage(code: str) -> list[str]:
    """Check for common AEAD misuse patterns."""
    issues = []
    if "MODE_GCM" in code and "nonce=" not in code:
        issues.append("GCM without explicit nonce")
    if "nonce=request" in code or "nonce=params" in code:
        issues.append("Attacker-controlled nonce — CATASTROPHIC")
    if "mac_len=4" in code or "mac_len=8" in code:
        issues.append("Short tag — birthday attack possible")
    if "secrets.token_bytes(8)" in code and "MODE_GCM" in code:
        issues.append("8-byte nonce for GCM — weaker than 12")
    return issues
```

### 11.3 When to use

- **Always** — read the code first.
- **If nonce is user-controlled → instant break** (choose nonce = `\x00\x00...\x00` for both encrypt and decrypt).

---

## 12. Quick reference: "I see CCM/GCM — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Known plaintext + same nonce | **Keystream recovery** | §5 |
| Two ciphertexts, same nonce (GCM) | **Keystream + GHASH key recovery** | §4 |
| Two ciphertexts, same nonce (CCM) | **Keystream only** (no forgery) | §5 |
| Weak key | Wordlist | §6 |
| Short tag (`mac_len < 16`) | Birthday | §7 |
| AAD not verified | Modify AAD | §8 |
| Counter > 64 GB | Overflow | §10 |
| Nonce user-controlled | Instant break | §11 |
| Tag verification non-constant-time | Timing | — |

---

## 13. Mapping to session tasks

| Task | Uses AEAD? | Attack |
|---|---|---|
| **Noncense** | ❌ **AES-CTR** (not AEAD) | §5 (nonce reuse, decryption only) |
| **Secure Bank** | ❌ Salsa20 (not AEAD) | Malleability |
| **Secure Bank 2** | ❌ SHA-256 truncated | Birthday |
| **Signed, Sealed** | ❌ HMAC-SHA256 | JSON canonicalization |
| **Token of Trust** | ❌ JWT HS256 | alg:none / weak secret |
| **Security Cam** | ❌ MD5 Digest | Dictionary |
| **Better Hash** | ❌ Custom hash | Reverse |
| **Key standardisation** | ❌ DES | Prefix brute |
| **Replanting** | ❌ LCG | Seed brute |
| **Dutch Exclusivity** | ❌ XOR | Known key |
| **AES 2 demo** | ❌ AES double | MITM |

**No session task uses AEAD directly.** But:
- **Noncense** is **AES-CTR nonce reuse** — same math as **GCM/CCM nonce reuse** (§5).
- **If a GCM task appears** (in a bonus or future session) → §4 (full attack).
- **Exam material** — §14.

---

## 14. The exam answers (memorize these)

### Q1: "What are the four authenticated-encryption orderings, and which are secure?"

**A:**

| Ordering | Formula | Secure? | Used by |
|---|---|---|---|
| **H → E** | `C = E(K, M \|\| H(M))` | ❌ **Broken** | WEP |
| **A → E** | `C = E(K2, M \|\| MAC(K1, M))` | ⚠️ **Padding oracle** | SSL/TLS 1.0 |
| **E → A** | `C = E(K2, M), T = MAC(K1, C)` | ✅ **Correct** | IPSec |
| **E + A** | `C = E(K2, M), T = MAC(K1, M)` | ✅ **Correct** | SSH |

**Golden rule:** **Encrypt-then-MAC (E → A)** — verify before decrypt, no padding oracle.

- **CCM** uses **A → E** (MAC-then-encrypt) — but **no padding** (CTR), so safe.
- **GCM** uses **E → A** (encrypt-then-MAC, GHASH over ciphertext) — safe.

### Q2: "How does CCM combine CTR and CMAC?"

**A:** CCM uses **one key `K`** for both:
1. Build **authentication blocks** `B_0` (nonce + lengths), `B_i` (AAD), `B_j` (plaintext).
2. **CMAC** over all blocks → tag `T`.
3. **CTR encryption** of plaintext starting at counter `A_0`.
4. **CTR encryption** of tag → final tag.

**Two passes over plaintext:** one for CMAC, one for CTR. **Slower than GCM** but simpler.

### Q3: "Why is GCM faster than CCM?"

**A:**
- **GCM:** GHASH is **parallelizable** (polynomial multiplication) and **hardware-accelerated** (PCLMULQDQ on x86). Only **one pass** over plaintext (GHASH over ciphertext while CTR encrypts).
- **CCM:** CMAC is **sequential** (CBC-mode, no parallelism). **Two passes** over plaintext (CMAC then CTR).

**For large messages, GCM is ~3–5× faster than CCM.**

### Q4: "What happens if a nonce is reused in GCM?"

**A:** **Catastrophic** — both confidentiality and authenticity break:
1. **Confidentiality:** keystream reuse → `c1 ⊕ c2 = p1 ⊕ p2` (two-time pad).
2. **Authenticity:** GHASH is **linear in `H`**. Two tags with the same `E_K(J_0)` give:
   ```
   T1 ⊕ T2 = GHASH_H(A1, C1) ⊕ GHASH_H(A2, C2)
   ```
   This is **one equation in `H`** (polynomial over `GF(2^128)`). Solve → recover `H`.
3. **Full forgery:** with `H` and `E_K(J_0)` recovered, forge **any tag** for **any message**.

**GCM nonce reuse = complete break.** CCM nonce reuse is less severe (no algebraic recovery of `H`), but still breaks confidentiality.

### Q5: "What is the nonce-size tradeoff in CCM?"

**A:** CCM's nonce length `N` determines `L = 15 - N`, the **length field size**:
- **Longer nonce** (`N=13`) → **shorter L** (`2 bytes`) → **max message = 64 KB**.
- **Shorter nonce** (`N=7`) → **longer L** (`8 bytes`) → **max message = 2⁶⁴**.
- **NIST recommends** `N=12`, `L=3` → **max message 16 MB**.

**Tradeoff:** longer nonce = better collision resistance but smaller max message. For a given application, choose `N` based on max message size.

### Q6: "Why is MAC-then-Encrypt (A → E) risky?"

**A:** **Padding oracle attacks** (Vaudenay 2002). If the decryption step returns **distinguishable errors** for:
- "padding error" (before MAC check)
- "MAC error" (after padding check)

...the attacker can **recover plaintext byte-by-byte** without breaking encryption.

**SSL/TLS 1.0** used A → E → **BEAST**, **POODLE** attacks.
**Fix:** use **E → A** (encrypt-then-MAC). **CCM** is A → E, but **no padding** (CTR mode) → **safe**. **GCM** is E → A.

**For new systems: always E → A, or use AEAD (GCM/CCM/ChaCha20-Poly1305).**
