# MAC (Message Authentication Code): Theory, Every Attack Case, Ready-to-Use Scripts

MAC is the **general concept** behind HMAC, CMAC, Poly1305, GMAC, and every "authentication tag" you've ever seen. **You've already seen the specific implementations** (HMAC-SHA256 in Signed Sealed + Token of Trust, CMAC inside CCM, Salsa20-Poly1305 if AEAD). This section is the **umbrella**: what MAC is, how it fails, and the **exam questions** from the slides.

It's the **last algorithmic topic** and the **capstone** — the "why does all this matter" section.

---

## 1. What is a MAC (formally)

A **Message Authentication Code (MAC)** is a function:

```
MAC: K × M → T
MAC(K, M) = T
```

Where:
- `K` = secret key (shared between sender and receiver)
- `M` = arbitrary-length message
- `T` = fixed-length **tag** (also called **authenticator**, **checksum**)

**Properties:**
- **Deterministic** (same `K, M` → same `T`).
- **Fixed-size output** (`n` bits, independent of `|M|`).
- **Not reversible** — you can't recover `K` or `M` from `T`.

### 1.1 Three categories (from the slides)

| Class | Construction | Example |
|---|---|---|
| **Hash-based** | `H(K, M)` or `HMAC(K, M)` | HMAC-SHA256, HMAC-MD5 |
| **Block-cipher-based** | CBC-MAC, CMAC, GMAC | CMAC-AES, AES-GCM (GHASH) |
| **Encryption-based** | Entire ciphertext as authenticator | AES-CBC full message |
| **Universal hash** | Poly1305, UMAC | ChaCha20-Poly1305 |
| **Keccak-based** | KMAC (SP 800-185) | KMAC256 |

**From the slides:** the **three classes** are:
1. **Hash function** — fixed-length hash value as authenticator.
2. **Message encryption** — ciphertext as authenticator.
3. **MAC** — fixed-length value from message + secret key.

### 1.2 MAC vs Hash vs Digital Signature (memorize)

| Aspect | Hash | MAC | Digital Signature |
|---|---|---|---|
| **Key** | None (public) | **Symmetric** (shared secret) | **Asymmetric** (private key sign, public key verify) |
| **Integrity** | ✅ | ✅ | ✅ |
| **Authenticity** | ❌ (anyone can compute) | ✅ (only key-holders) | ✅ (only signer) |
| **Non-repudiation** | ❌ | ❌ **(both parties can forge)** | ✅ (only signer can sign) |
| **Speed** | Fast | Fast | Slow |
| **Example** | SHA-256 | HMAC-SHA256 | RSA-PSS, ECDSA |

**Key distinction:** **MAC cannot replace digital signatures** — because **both sender and receiver share the key**, either could have created the MAC. **No non-repudiation.**

### 1.3 Standard Python usage

```python
# HMAC (hash-based)
import hmac, hashlib
tag = hmac.new(key, message, hashlib.sha256).digest()

# CMAC (block-cipher-based)
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
tag = CMAC.new(key, ciphermod=AES).update(message).digest()

# Poly1305 (universal hash, AEAD)
from Crypto.Cipher import ChaCha20_Poly1305
# (usually used with ChaCha20 in ChaCha20-Poly1305)
```

---

## 2. The exam question: "Can a MAC be used as a digital signature?"

### 2.1 Answer: **NO** (from slides)

**Rationale (from the slides):**

> "The security of a MAC requires a **shared secret key** between sender and receiver. Both parties can generate the same MAC. Therefore, a **MAC does not provide non-repudiation** — if Alice sends a MAC and Bob claims it's fraudulent, Alice can say **'you could have made it too'**."

**Digital signature** requires:
- **Asymmetric keys** (private + public).
- **Only the signer** holds the private key.
- **Anyone** can verify with the public key.
- **Non-repudiation** — signer cannot deny signing.

**MAC** provides:
- **Message authentication** (data integrity + sender identity assumed via key).
- **NOT non-repudiation** (either party could have created the MAC).

### 2.2 Additional considerations

- **Some use cases require non-repudiation** (contracts, financial transactions, legal evidence) → **must use digital signatures**.
- **Some use cases don't** (session tokens, API auth, TLS) → **MAC is fine**.
- **MAC is much faster** than digital signatures (symmetric vs asymmetric).
- **MAC** is the right choice for **high-throughput** and **symmetric trust** scenarios.

---

## 3. MAC security requirements (from slides)

### 3.1 Three requirements for MAC security

From the slides:

**Requirement 1:** Given `M` and `MAC(K, M)`, infeasible to construct `M' ≠ M` such that `MAC(K, M') = MAC(K, M)`.

**Requirement 2:** Given two randomly chosen messages `M, M'`, `Pr[MAC(K, M) = MAC(K, M')] = 2^(-n)` (for an `n`-bit tag).

**Requirement 3:** If `M' = f(M)` is a **known transformation** of `M`, then `Pr[MAC(K, M) = MAC(K, M')] = 2^(-n)`.

### 3.2 What each requirement prevents

| Requirement | Prevents |
|---|---|
| 1 | **Existential forgery** (constructing new message matching old tag) |
| 2 | **Brute-force tag guessing** (random message gives random tag) |
| 3 | **Structural weakness** (some parts of message less protected than others) |

**From the slides:**

> "The first requirement avoids attacks in which an opponent is able to construct a new message to match a given tag, even though the opponent does not know and does not learn the key."
> 
> "The second requirement deals with the need to thwart a brute-force attack based on chosen plaintext."
> 
> "The final requirement dictates that the authentication algorithm should not be weaker with respect to certain parts or bits of the message than others."

### 3.3 MAC brute-force effort (from slides)

**Question:** Given MAC with key size `k` bits and code size `n` (`< k`) bits, brute-force effort from one `(M, T)` pair?

**Answer:** **`2^k` attempts, but key cannot be unambiguously determined.**

**Why?** Because `n < k`, there are `2^(k-n) > 1` keys that produce the same `(M, T)`. Brute force finds a **set** of candidate keys, not a unique one.

**To narrow down:** need `ceil(k/n)` message-code pairs on average.

**Concrete example (from slides):** `k = 24`, `n = 16` → `ceil(24/16) = 2` pairs on average.

**From the slides:** *"because of the mathematical properties of the authentication function, it is less vulnerable to being broken than encryption."*

**Reason:** encryption has a **1:1 correspondence** between key and ciphertext (each key → unique ciphertext). MAC has a **many-to-one** correspondence (`2^k` keys → `2^n` tags). So finding **a** matching key is easier than finding **the** key.

---

## 4. Attack taxonomy — MAC as a concept

| # | Attack | Applies to | Session relevance |
|---|---|---|---|
| 1 | **Weak key (wordlist/brute)** | All MACs | Token of Trust |
| 2 | **Length extension** | Only `H(K \|\| M)` (NOT HMAC) | Not HMAC (blocked) |
| 3 | **Tag truncation** | `T[:N]` | Secure Bank 2 (SHA-256 trunc) |
| 4 | **Nonce reuse (AEAD)** | ChaCha20-Poly1305, GCM, CCM | Noncense (CTR) |
| 5 | **Timing attack** | Non-constant-time compare | Rare |
| 6 | **MAC-then-encrypt (padding oracle)** | MAC inside ciphertext | Theoretical |
| 7 | **Key reuse (MAC + enc)** | Same key for both | CCM (safe by design) |
| 8 | **Collision (tag collision)** | Truncated tag | Birthday |
| 9 | **Existential forgery** | Weak MAC | Any weak construction |
| 10 | **Key recovery via chosen messages** | Weak MAC | Any weak construction |
| 11 | **Length extension** on HMAC | — | ❌ **Blocked** |
| 12 | **Digital signature confusion** | Wrong primitive used | Design bug |

**Cases 1–4 and 6 are the ones you've seen.**

---

## 5. The 4 authenticated-encryption orderings (from slides)

This is **explicitly in the slides** and a **classic exam question**.

### 5.1 The four orderings

| Ordering | Formula | Security | Used by |
|---|---|---|---|
| **H → E** (hash then encrypt) | `C = E(K, M \|\| H(M))` | ❌ **Fundamentally broken** | **WEP** |
| **A → E** (MAC then encrypt) | `C = E(K2, M \|\| MAC(K1, M))` | ⚠️ **Padding oracle risk** | **SSL/TLS 1.0** |
| **E → A** (encrypt then MAC) | `C = E(K2, M), T = MAC(K1, C)` | ✅ **Correct** | **IPSec** |
| **E + A** (encrypt AND MAC) | `C = E(K2, M), T = MAC(K1, M)` | ✅ **Correct** | **SSH** |

**From the slides:**
> "Both decryption and verification are straightforward for each approach. For H→E, A→E, and E+A, decrypt first, then verify. For E→A, verify first, then decrypt. There are security vulnerabilities with all of these approaches. The H→E approach is used in WEP to protect WiFi networks. This approach had fundamental weaknesses and led to the replacement of WEP."

### 5.2 Why each ordering is (in)secure

**H → E (broken — WEP):**

- The hash is **unkeyed** — anyone can compute `H(M)`.
- An attacker can **flip bits** in `M` and **recompute `H(M')`** to match.
- **No secret** in the hash → no integrity.
- **WEP's CRC32 was the "hash"** — a linear function, trivially breakable.
- **Impact:** bit-flipping attacks on WEP traffic.

**A → E (padding oracle — SSL/TLS 1.0):**

- MAC is **inside** the ciphertext.
- Decrypt, then verify MAC.
- **If decryption fails with a distinguishable "padding error"**, attacker learns info about plaintext.
- **Vaudenay (2002)** — padding oracle attack.
- **Impact:** SSL/TLS 1.0 exploited (POODLE, BEAST).
- **Fix:** use **E → A** (encrypt-then-MAC) in TLS 1.2+.

**E → A (correct — IPSec):**

- Ciphertext is authenticated **before** decryption.
- **Any tampering** → MAC check fails → no decryption attempted.
- **No padding oracle** (attacker never sees decryption failures on tampered ciphertext).
- **Correct order:** **verify, then decrypt**.
- **Impact:** IPSec uses this. **Correct.**

**E + A (correct — SSH):**

- MAC over **plaintext**, ciphertext over plaintext.
- Verify MAC, then decrypt (or vice versa — both work).
- **Correct** if the MAC is **over plaintext** (proves authenticity of plaintext).
- **Different from E → A**: MAC over `M` vs MAC over `C`.
- **Impact:** SSH uses this. **Correct.**

### 5.3 The rule

**Golden rule:** **Encrypt-then-MAC (E → A)** — always.

**Why?**
- Authentication **before** decryption → tampered data rejected early.
- No padding oracle.
- No plaintext leak.
- Attacker can't modify ciphertext without detection.

**Never use MAC-then-Encrypt (A → E)** for new systems — padding oracle risk.

**Never use Hash-then-Encrypt (H → E)** — unkeyed hash doesn't authenticate.

---

## 6. Attack 1 — Weak key (wordlist)

### 6.1 Description

If MAC key is a dictionary word, brute force.

### 6.2 Universal script (any MAC)

```python
#!/usr/bin/env python3
"""Crack any MAC with weak key from wordlist."""
import hmac, hashlib, argparse
from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def derive_key(password: bytes, key_len: int, mode: str = "raw") -> bytes:
    if mode == "raw":
        return (password + b"\x00" * key_len)[:key_len]
    if mode == "md5":
        h = hashlib.md5(password).digest()
        return (h * ((key_len // 16) + 1))[:key_len]
    if mode == "sha256":
        h = hashlib.sha256(password).digest()
        return (h * ((key_len // 32) + 1))[:key_len]
    raise ValueError(mode)


def crack_mac(msg: bytes, target_tag: bytes, wordlist: str,
               mac_type: str = "hmac_sha256", key_len: int = 32,
               derivation: str = "raw") -> tuple[bytes, bytes] | None:
    """Try every password as MAC key."""
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw:
                continue
            try:
                key = derive_key(pw, key_len, derivation)
                if mac_type == "hmac_sha256":
                    tag = hmac.new(key, msg, hashlib.sha256).digest()
                elif mac_type == "hmac_md5":
                    tag = hmac.new(key, msg, hashlib.md5).digest()
                elif mac_type == "cmac_aes":
                    c = CMAC.new(key, ciphermod=AES)
                    c.update(msg)
                    tag = c.digest()
                else:
                    continue

                if hmac.compare_digest(tag, target_tag):
                    return key, pw
            except Exception:
                continue
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--msg", required=True)
    ap.add_argument("--tag", required=True, help="MAC tag (hex)")
    ap.add_argument("--wordlist", default="rockyou.txt")
    ap.add_argument("--mac", default="hmac_sha256",
                    choices=["hmac_sha256", "hmac_md5", "cmac_aes"])
    ap.add_argument("--key-len", type=int, default=32)
    ap.add_argument("--derivation", default="raw",
                    choices=["raw", "md5", "sha256"])
    ap.add_argument("--hex", action="store_true")
    args = ap.parse_args()

    msg = bytes.fromhex(args.msg) if args.hex else args.msg.encode()
    tag = bytes.fromhex(args.tag)

    print(f"[*] Cracking {args.mac} with {args.wordlist}...")
    result = crack_mac(msg, tag, args.wordlist, args.mac, args.key_len, args.derivation)
    if result:
        key, pw = result
        print(f"[+] PASSWORD: {pw!r}")
        print(f"[+] KEY:      {key.hex()}")
    else:
        print("[!] Not found")
```

### 6.3 Usage

```bash
# HMAC-SHA256 with password-derived key
python crack_mac.py --msg "payload" --tag "..." \
  --mac hmac_sha256 --key-len 32 --derivation raw

# CMAC-AES with password-derived key
python crack_mac.py --msg "payload" --tag "..." \
  --mac cmac_aes --key-len 16 --derivation raw
```

**Session relevance:** **Token of Trust** (JWT HS256) and **Signed, Sealed** (HMAC-SHA256 JSON).

---

## 7. Attack 2 — Length extension (⚠️ only for `H(K || M)` — NOT HMAC)

### 7.1 Description

If the MAC is **`SHA256(secret || message)`** (the **wrong construction**), length extension works. **If it's HMAC**, length extension is blocked.

### 7.2 Detection

```python
def is_length_extensible(code: str) -> bool:
    """
    Read the code. Look for:
    - hashlib.sha256(SECRET + message)       → VULNERABLE
    - hashlib.md5(SECRET + message)           → VULNERABLE
    - hashlib.sha1(SECRET + message)          → VULNERABLE
    - hmac.new(SECRET, message, hashlib.sha256) → SAFE
    - hashlib.sha3_256(SECRET + message)     → SAFE (sponge)
    """
    import re
    # Naive detection from source code
    if re.search(r'hmac\.new\s*\(', code):
        return False   # HMAC → safe
    if 'sha3' in code.lower() or 'sha256' in code.lower():
        if re.search(r'(sha256|sha1|md5)\s*\(\s*\w+\s*\+', code):
            return True   # H(secret + msg) → vulnerable
    return False
```

### 7.3 Full length extension script

See **SHA-2 §6** for the full implementation. For **SHA-1**, use **SHA-1 §6** (same structure). For **MD5**, use **MD5 §6** (same structure).

### 7.4 When to use

- **Server uses `SHA256(secret || msg)`** as MAC — vulnerable.
- **Server uses HMAC-SHA256** — not vulnerable.
- **Server uses SHA3** — not vulnerable (sponge).

**Session tasks:** **Signed, Sealed** and **Token of Trust** use HMAC → **safe from length extension**. **Don't waste time** trying it there.

---

## 8. Attack 3 — Tag truncation (birthday)

### 8.1 Description

If server uses `tag[:N]` (first N bytes as "short MAC"), birthday attack finds **two messages with same short tag**.

### 8.2 Full script

```python
#!/usr/bin/env python3
"""Birthday attack on truncated MAC."""
import hmac, hashlib, os


def find_tag_collision(key: bytes, trunc_bytes: int = 4,
                        mac_type: str = "hmac_sha256") -> tuple[bytes, bytes, bytes]:
    """
    Find two messages with the same truncated tag.
    - trunc_bytes: how many bytes the server uses
    - mac_type: hmac_sha256, hmac_md5, cmac_aes
    """
    seen = {}
    for i in range(1 << 30):
        msg = os.urandom(8)
        if mac_type == "hmac_sha256":
            tag = hmac.new(key, msg, hashlib.sha256).digest()
        elif mac_type == "hmac_md5":
            tag = hmac.new(key, msg, hashlib.md5).digest()
        else:
            raise ValueError(mac_type)

        short = tag[:trunc_bytes]
        if short in seen and seen[short] != msg:
            return seen[short], msg, short
        seen[short] = msg
    return None


if __name__ == "__main__":
    import time
    key = b"YELLOW_SUBMARINE"[:16]
    print("[*] Finding truncated HMAC-SHA256 collision (4 bytes)...")
    t0 = time.time()
    a, b, tag = find_tag_collision(key, trunc_bytes=4)
    print(f"[+] Collision after {time.time()-t0:.1f}s")
    print(f"    short tag: {tag.hex()}")
    print(f"    msg1:      {a.hex()}")
    print(f"    msg2:      {b.hex()}")
```

### 8.3 Feasibility

| Truncation | Tries | Python time |
|---|---|---|
| 2 bytes (16 bits) | 256 | instant |
| 3 bytes (24 bits) | 4096 | instant |
| 4 bytes (32 bits) | 65,536 | seconds |
| 5 bytes (40 bits) | 1,048,576 | minutes |
| 6 bytes (48 bits) | 16,777,216 | hours |

### 8.4 When to use

- **Secure Bank 2** (SHA-256 truncated fingerprint) — same principle.
- **Any task with "short tag" / "fingerprint" / "checksum"**.
- **Not Signed Sealed or Token of Trust** (full-length tags).

---

## 9. Attack 4 — Nonce reuse (AEAD MAC)

### 9.1 Description

In **AEAD modes** (GCM, CCM, ChaCha20-Poly1305), the **MAC is coupled to encryption** via a **nonce**. If nonce is reused:

1. **Confidentiality breaks** (keystream reuse → `c1 ⊕ c2 = p1 ⊕ p2`).
2. **Authenticity breaks** (Poly1305/GHASH key recovery → forgery).

### 9.2 Full script (decryption only)

```python
#!/usr/bin/env python3
"""AEAD nonce reuse — decrypt ciphertexts with reused nonce."""
import hmac, hashlib


def aead_nonce_reuse_decrypt(c1: bytes, c2: bytes,
                               known_pt: bytes = None) -> bytes:
    """
    Two AEAD ciphertexts with same nonce.
    - If known_pt (of c1): recover p2.
    - Otherwise: return p1 ⊕ p2 (crib drag).
    """
    if known_pt:
        ks = bytes(p ^ c for p, c in zip(known_pt, c1))
        return bytes(c ^ k for c, k in zip(c2, ks))
    return bytes(a ^ b for a, b in zip(c1, c2))


# Example
c1 = bytes.fromhex("...")   # first ciphertext
c2 = bytes.fromhex("...")   # second ciphertext with same nonce
known_pt = b"known prefix here"
p2 = aead_nonce_reuse_decrypt(c1, c2, known_pt)
print(p2)
```

### 9.3 Session relevance

- **Noncense** (AES-CTR) — **exactly this**, but with CTR not GCM. Same math.
- **If a GCM/CCM task appears** — same attack, plus advanced forgery (GHASH/Poly1305 key recovery).

---

## 10. Attack 5 — Timing (non-constant-time compare)

### 10.1 Description

If server compares MAC tags with `==` (early exit), timing leaks the correct prefix.

### 10.2 Script

```python
import time
import requests


def timing_attack_mac(url: str, header: str = "X-Signature",
                       known_prefix: str = "", samples: int = 50,
                       tag_len: int = 64) -> str:
    """
    Recover MAC tag byte-by-byte via timing.
    - tag_len: 32 (16 bytes) for CMAC-AES, 64 (32 bytes) for HMAC-SHA256
    """
    hex_chars = "0123456789abcdef"
    recovered = known_prefix

    while len(recovered) < tag_len:
        best_char, best_time = None, 0
        for c in hex_chars:
            trial = recovered + c
            times = []
            for _ in range(samples):
                t0 = time.perf_counter()
                requests.post(url, headers={header: trial})
                times.append(time.perf_counter() - t0)
            avg = sum(times) / len(times)
            if avg > best_time:
                best_time, best_char = avg, c

        recovered += best_char
        print(f"[+] {len(recovered)}/{tag_len}: {recovered} ({best_time*1000:.2f}ms)")

    return recovered
```

### 10.3 When to use

- **Very rare** — most servers use `hmac.compare_digest` or library equivalent.
- **Only if you suspect** a hand-rolled MAC comparator.

---

## 11. Attack 6 — MAC-then-encrypt (padding oracle)

### 11.1 Description

If **MAC is inside the ciphertext** (A → E), and the server returns **distinct errors** for "padding error" vs "MAC error", you can:

1. **Decrypt** plaintext byte-by-byte (padding oracle).
2. **Leak** plaintext without knowing the key.

### 11.2 Detection

```python
def detect_padding_oracle(url: str, ct_hex: str) -> bool:
    """
    Try sending ciphertext with modified last block.
    If server returns DIFFERENT error for "padding" vs "MAC", it's vulnerable.
    """
    import requests
    ct = bytes.fromhex(ct_hex)

    # Tamper with last block
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    r = requests.post(url, data=tampered.hex())

    # Tamper with first block
    tampered2 = bytes([ct[0] ^ 1]) + ct[1:]
    r2 = requests.post(url, data=tampered2.hex())

    # If different error messages → padding oracle
    return r.text != r2.text
```

### 11.3 Full attack

See **AES §11** for the full **CBC padding oracle** implementation — it's the same attack.

### 11.4 Session relevance

- **SSL/TLS 1.0** used MAC-then-encrypt → padding oracle (BEAST, POODLE).
- **Not in your session tasks** — but if a task has **CBC + HMAC** and distinct errors, this is the attack.

---

## 12. Attack 7 — Key reuse (MAC + encryption)

### 12.1 Description

If the **same key** is used for both encryption and MAC (like in **CCM**, **GCM**), it's **safe by design** — because the two uses are **domain-separated**:

- **CCM:** CTR mode uses **counter blocks**; CMAC uses **`B_0` block with nonce + lengths**.
- **GCM:** CTR uses **`J_0` counter**; GHASH uses the ciphertext + AAD with a **hash key `H = E(K, 0)`**.

**The key is the same, but the inputs are disjoint** — no attack.

### 12.2 Exception: bad domain separation

If the mode **doesn't** domain-separate properly (e.g., **reuses the same counter/nonce for both MAC and CTR**) → collision.

**Rare** — modern AEAD modes are designed correctly.

### 12.3 When to use

- **Not exploitable** for CCM/GCM/ChaCha20-Poly1305.
- **Only if the challenge has a custom AEAD** with bad design → read the code.

---

## 13. Attack 8 — Key recovery via chosen messages

### 13.1 Description

Some **weak MAC constructions** leak key information when the attacker controls message selection.

**Examples:**
- **CBC-MAC without proper subkeys** — length extension.
- **`H(K || M)` with a weak hash** — length extension.
- **XOR-based MAC** — `MAC = K ⊕ H(M)` → recover `K = MAC ⊕ H(M)`.
- **Unkeyed polynomial MAC** — if the polynomial coefficients can be recovered.

### 13.2 Script — XOR-MAC attack

```python
import hashlib


def xor_mac(key: bytes, msg: bytes) -> bytes:
    """Weak XOR-based MAC. DO NOT USE — for demonstration only."""
    return bytes(a ^ b for a, b in zip(
        key,
        hashlib.sha256(msg).digest()[:len(key)]
    ))


def recover_xor_key(known_msg: bytes, known_tag: bytes) -> bytes:
    """Recover XOR-MAC key from one (msg, tag) pair."""
    h = hashlib.sha256(known_msg).digest()[:len(known_tag)]
    return bytes(a ^ b for a, b in zip(known_tag, h))


# Demo
key = b"SECRETKEY12345"
msg = b"attack at dawn"
tag = xor_mac(key, msg)
recovered = recover_xor_key(msg, tag)
print(f"[+] Key recovered: {recovered}")
print(f"[+] Match: {recovered == key}")
```

### 13.3 When to use

- **Very rare** — but if a task has a **custom/weak MAC**, look for:
  - XOR-based construction.
  - Weak key derivation.
  - Unkeyed polynomial hash.
  - **`MAC(K, M) = H(K) || H(M)`** type constructions.

---

## 14. Attack 9 — Tag collision via birthday (general MAC)

### 14.1 Description

Same as truncated MAC (§8) — but if the **MAC algorithm itself** has a **birthday attack** (rare for strong MACs, but possible for weak constructions).

### 14.2 When to use

- **Truncated tags** — §8 covers this.
- **Weak MAC constructions** — read the code.
- **Strong MACs** — no practical collision attack.

---

## 15. Full attack script — universal MAC attack

Consolidate all attacks into one script that tries them in order:

```python
#!/usr/bin/env python3
"""Universal MAC attack — try in order."""
import hmac, hashlib, requests, json
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


def universal_mac_attack(msg: bytes, tag: bytes, wordlist: str,
                          mac_type: str = "hmac_sha256",
                          key_len: int = 32,
                          server_url: str = None,
                          header: str = "X-Signature") -> dict:
    """
    Try multiple MAC attacks. Returns first success.
    """
    results = {}

    # 1) Weak key wordlist
    print("[*] Attack 1: Weak key wordlist...")
    key = crack_wordlist_mac(msg, tag, wordlist, mac_type, key_len)
    if key:
        return {"attack": "weak_key", "key": key}

    # 2) Length extension (only for H(K||M))
    print("[*] Attack 2: Length extension...")
    # (Skipped — requires knowing construction)

    # 3) Truncated birthday (only if tag < full length)
    if len(tag) < 32:  # less than 256 bits
        print(f"[*] Attack 3: Truncated birthday ({len(tag)*8}-bit tag)...")
        collision = find_mac_collision(key_len, len(tag))
        if collision:
            return {"attack": "birthday", "collision": collision}

    # 4) Timing (requires server)
    if server_url:
        print("[*] Attack 4: Timing...")
        # (Skipped — needs server interaction)

    return {"attack": "none", "results": results}


def crack_wordlist_mac(msg, tag, wordlist, mac_type, key_len):
    """Subroutine: wordlist attack on MAC."""
    with open(wordlist, "rb") as f:
        for line in f:
            pw = line.rstrip(b"\r\n")
            if not pw: continue
            key = (pw + b"\x00" * key_len)[:key_len]

            if mac_type == "hmac_sha256":
                computed = hmac.new(key, msg, hashlib.sha256).digest()
            elif mac_type == "cmac_aes":
                c = CMAC.new(key, ciphermod=AES)
                c.update(msg)
                computed = c.digest()
            else:
                continue

            if hmac.compare_digest(computed, tag):
                return key
    return None


def find_mac_collision(key_len, trunc_bytes, max_tries=1<<30):
    """Subroutine: truncated MAC birthday."""
    import os
    seen = {}
    key = b"\x00" * key_len
    for i in range(max_tries):
        msg = os.urandom(8)
        tag = hmac.new(key, msg, hashlib.sha256).digest()[:trunc_bytes]
        if tag in seen and seen[tag] != msg:
            return seen[tag], msg, tag
        seen[tag] = msg
    return None


# Usage
if __name__ == "__main__":
    msg = b"known message"
    tag = bytes.fromhex("...")
    result = universal_mac_attack(
        msg, tag, "rockyou.txt",
        mac_type="hmac_sha256",
        key_len=32,
    )
    print(result)
```

---

## 16. Quick reference: "I see a MAC — what do I do?"

| Situation | Attack | Script |
|---|---|---|
| Weak key | Dictionary | §6 |
| `H(K \|\| M)` (not HMAC) | Length extension | SHA-2 §6 |
| `HMAC(K, M)` | ❌ not vulnerable | — |
| Truncated tag | Birthday | §8 |
| Nonce reuse (AEAD) | Two-time pad | §9 |
| Timing leak | Timing | §10 |
| MAC-then-encrypt + padding errors | Padding oracle | §11 |
| Key reuse (CCM/GCM) | Safe by design | — |
| Weak construction | Read code | — |
| **Digital signature needed?** | **Use signature, not MAC** | §2 |

---

## 17. Mapping to session tasks

| Task | MAC used | Attack |
|---|---|---|
| **Signed, Sealed** | **HMAC-SHA256** | §6 (weak key), JSON canonicalization |
| **Token of Trust** | **HMAC-SHA256 (JWT HS256)** | §6 (weak key), JWT alg:none, confusion |
| **Secure Bank 2** | SHA-256 truncated (not MAC, but same birthday principle) | §8 (birthday) |
| **Noncense** | AES-CTR (no MAC) | §9 (nonce reuse, but no MAC) |
| **Secure Bank** | Salsa20 (no MAC) | Malleability |
| **Security Cam** | MD5 Digest (not MAC) | Dictionary |
| **Better Hash** | Custom hash (not MAC) | Reverse |
| **Key standardisation** | DES (not MAC) | Brute force |
| **Replanting** | LCG (not MAC) | Seed brute |
| **Dutch Exclusivity** | XOR (not MAC) | Known key |
| **AES 2 demo** | AES (not MAC) | MITM |

**Two session tasks use MAC: Signed Sealed and Token of Trust.**

---

## 18. The exam answers (memorize these)

### Q1: "Can a MAC be used as a digital signature?"

**A:** **No.** A MAC uses a **shared secret key** — both sender and receiver can generate it. Therefore, **MAC does not provide non-repudiation**: if Alice sends a MAC and Bob claims it's fraudulent, Alice can say "you could have made it too". **Digital signatures** use **asymmetric keys** (only the signer has the private key) and provide non-repudiation. **Use signatures** when non-repudiation is required; **use MAC** for symmetric trust scenarios (faster, simpler).

### Q2: "Three requirements for MAC security?"

**A:**

1. **Given `(M, MAC(K, M))`**, infeasible to construct `M' ≠ M` with `MAC(K, M') = MAC(K, M)`.
2. **For random `M, M'`**, `Pr[MAC(K, M) = MAC(K, M')] = 2^(-n)`.
3. **For known `M' = f(M)`**, `Pr[MAC(K, M) = MAC(K, M')] = 2^(-n)`.

These prevent existential forgery, brute-force tag guessing, and structural weakness respectively.

### Q3: "Brute-force effort for MAC with key size k, code size n < k?"

**A:** **`2^k` attempts, but key cannot be unambiguously determined.** Because `n < k`, there are `2^(k-n)` keys producing the same `(M, T)`. Brute force finds a **set** of candidate keys, not one. Need **`ceil(k / n)` message-code pairs** on average for unique key. **Concrete:** `k=24, n=16` → `ceil(24/16) = 2` pairs.

### Q4: "Why is MAC less vulnerable than encryption?"

**A:** Encryption has a **1:1 correspondence** between key and ciphertext (each key → unique ciphertext). MAC has a **many-to-one** correspondence (`2^k` keys → `2^n` tags). So finding **a** matching key is easier, but finding **the** key requires more pairs. **On average, MAC needs `k/n` pairs, encryption needs 1 ciphertext but with the right key.**

### Q5: "Order of encryption and MAC — which is correct?"

**A:** **Encrypt-then-MAC (E → A)** is correct.

- **H → E** (WEP): broken — unkeyed hash, bit-flipping.
- **A → E** (SSL/TLS 1.0): padding oracle risk.
- **E → A** (IPSec): correct — verify first, decrypt second.
- **E + A** (SSH): correct — MAC over plaintext.

**Golden rule:** Encrypt-then-MAC. **Never** MAC-then-Encrypt for new systems.

### Q6: "Why are two subkeys K1 and K2 needed in CMAC?"

**A:** CMAC handles **aligned** (multiple of block size) and **padded** (last block partial) messages. Using **different subkeys** for each case ensures **domain separation**: an attacker cannot construct a **collision** between an aligned and a padded message. Without it, CBC-MAC-style length extension attacks work (as in DAA). **K1 and K2 are derived from the cipher itself** (`L = E(K, 0)`; `K1 = L·x`; `K2 = L·x²`).

---

## 19. Summary: MAC's role in the session

| Task | What you need from this section |
|---|---|
| **Signed, Sealed** | §6 (weak key), §11 (JSON canonicalization — in HMAC §5) |
| **Token of Trust** | §6 (weak key), §18 (JWT attacks — in HMAC §6–§10) |
| **Secure Bank 2** | §8 (birthday — same math) |
| **Noncense** | §9 (nonce reuse) |
| **Theory exam** | **All of §18** |

**The exam answers (§18) are the most valuable** — they directly address the slides' explicit questions.
