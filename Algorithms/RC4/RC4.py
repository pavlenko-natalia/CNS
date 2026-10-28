# RC4: Theory, All Cases, Scripts

# RC4 is the most famous "broken but still around" stream cipher. Designed by Ron Rivest in 1987,
# kept as a trade secret until it was anonymously leaked in 1994, standardized everywhere (WEP, WPA-TKIP, SSL/TLS, SSH, Kerberos),
# then **completely broken** by 2015. It's a perfect CTF target: small, simple, with several well-documented attack classes.


## 1. What is RC4 (formally)

# RC4 is a **byte-oriented stream cipher** with a **256-byte internal state** `S`. It consists of two algorithms:

### 1.1 Key Scheduling Algorithm (KSA)

# Takes a key `K` (1–256 bytes) and initializes the permutation `S` of `0..255`:

def KSA(key: bytes) -> list[int]:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

### 1.2 Pseudo-Random Generation Algorithm (PRGA)

# Generates keystream bytes one at a time:

def PRGA(S: list[int], n: int) -> bytes:
    i = j = 0
    out = bytearray()
    for _ in range(n):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

### 1.3 Full RC4

def rc4(key: bytes, data: bytes) -> bytes:
    S = KSA(key)
    ks = PRGA(S, len(data))
    return bytes(p ^ k for p, k in zip(data, ks))

# **Encryption = decryption** (XOR property). Stream cipher — no padding, same length in/out.

### 1.4 Variants you might see
# - **RC4-drop-n**: discard first `n` keystream bytes (usually `n = 256` or `n = 768`)
# to avoid the worst biases. WEP used `n = 0`; WPA-TKIP used `n = 0` too; many libraries use `drop 768`.
# - **RC4A**: two parallel PRGAs (an academic variant).
# - **Spritz**: a 2014 redesign that fixes RC4's biases (not standard, rarely seen).
#
# ---

## 2. Security requirements — and where RC4 fails

# For a stream cipher to be secure, the keystream must be **indistinguishable from random** and **unpredictable**. RC4 fails on both, in several measurable ways.
#
# | Property | RC4 status | Why |
# |---|---|---|
# | Unpredictability | ❌ | Keystream biases, key correlation |
# | Statistical randomness | ❌ | Second byte, first 256 bytes, long-term biases |
# | Key independence | ❌ | First bytes correlate with key |
# | Nonce support | ❌ (in design) | No built-in nonce — caller must handle; most callers did it wrong |
# | Integrity | ❌ | No MAC — malleable |
# | Resistance to reuse | ❌ | Key/nonce reuse = catastrophic |
#
# RC4 is essentially an **LCG-level PRNG** in terms of security: fine for scrambling, useless for protection.
#
# ---

## 3. Attack taxonomy

# | # | Attack | Input needed | Difficulty |
# |---|---|---|---|
# | 1 | **Key recovery via KSA inversion** | Full keystream + known key length | Easy if key weak |
# | 2 | **Known plaintext → keystream** | One `(p, c)` pair | Trivial |
# | 3 | **Key reuse (two-time pad)** | Two ciphertexts, same key | Easy |
# | 4 | **Nonce reuse (WEP-style)** | Two ciphertexts, same `(key, IV)` | Easy |
# | 5 | **Second-byte bias** | Many samples with same key structure | Easy (statistical) |
# | 6 | **First-256-bytes correlation** | Keystream + many keys | Medium (FMS attack) |
# | 7 | **NOMORE / Fluhrer–McGrew** | ~10⁹ ciphertexts of same plaintext | Hard (2014, requires specific conditions) |
# | 8 | **Malleability** | One ciphertext + structure | Trivial |
# | 9 | **Weak key detection** | Structural analysis of keystream | Easy |
#
# Each has a dedicated script below.
#
# ---

## 4. Case 1: Known plaintext → keystream recovery

### Description
# If you know **any** plaintext fragment `p` and its ciphertext `c`:
# ```
# keystream = p ⊕ c
# ```
#
# Then:
# - Decrypt **other** ciphertexts with the same key/IV (Case 3/4).
# - Feed the keystream into **key recovery** (Case 1, 5, 6).
# - **Predict future bytes** if RC4's state can be reconstructed.

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
# - Any challenge with `known plaintext` file.
# - **Noncense**-style tasks (though that's AES-CTR, same principle).
# - Combined with Case 3/4.
#
# ### Limitation
# Only works up to `len(known_pt)`. For the rest — key recovery.
#
# ---

## 5. Case 2: Key/nonce reuse (two-time pad)

### Description
# RC4 itself has **no nonce**. Protocols use `(key, IV)` as `K || IV` (or `IV || K`) — if two messages share both key and IV, they share the keystream:
# ```
# c1 = p1 ⊕ ks
# c2 = p2 ⊕ ks
# c1 ⊕ c2 = p1 ⊕ p2
# ```
#
# Same as OTP key reuse.

### Script

def xor_two(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

x = xor_two(c1, c2)    # p1 ⊕ p2
# Then crib dragging (from OTP section)


### When to use
# - WEP: IV is 24 bits, sent in cleartext, **reused after ~16M packets**. Classic.
# - Any challenge with "two ciphertexts, same key".
# - **Bonus**: if `p1` is known/guessable → `ks = p1 ⊕ c1` → decrypt `c2`.

### Full two-time pad (with crib)
def crib_drag(x: bytes, crib: bytes):
    """x = p1 ⊕ p2; find where crib matches p1."""
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if all(32 <= b < 127 or b in (9, 10, 13) for b in guess):
            yield i, guess

for pos, p2_frag in crib_drag(x, b"cns{"):
    print(f"pos {pos}: p1[{pos}:]=...{p2_frag!r}")


## 6. Case 3: WEP-style key recovery (FMS attack) — advanced

### Description
# The classic **Fluhrer–Mantin–Shamir (FMS)** attack on WEP (2001). Relies on:
# 1. IV prepended to key: `K_eff = IV || K_secret`.
# 2. IV chosen by attacker (or predictable).
# 3. First keystream byte `b0` leaks info about `S[1]` after KSA.
#
# By collecting many `(IV, b0)` pairs and exploiting the non-uniformity of KSA, recover the secret key byte by byte. It's the reason WEP is dead.
#
# ### Status
# - **Not typically in CTF** unless the challenge is explicitly WEP/pcap-based (then use `aircrack-ng`).
# - Requires **millions of IVs** in practice.
# - Modern `aircrack-ng -z` handles it.

### Script (simplified for one key byte)
def fms_recover_first_byte(samples: list[tuple[bytes, int]]) -> int:
    """
    samples: list of (IV, first_keystream_byte) pairs.
    Returns best guess for K[0].
    """
    from collections import Counter
    votes = Counter()
    for iv, b0 in samples:
        # KSA for the first few steps
        S = list(range(256))
        j = 0
        K = list(iv) + [0]  # placeholder for K[0]
        for i in range(3):
            j = (j + S[i] + K[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
        # If S[0]+S[1] gives b0, and S[1] is in a specific known state,
        # then K[0] is constrained
        if S[0] + S[1] == b0:
            votes[S[1]] += 1
    return votes.most_common(1)[0][0] if votes else -1

### When to use
# - Capture of WEP traffic (`.pcap`) → `aircrack-ng`.
# - Old Wi-Fi challenges.
# - **Not** a general RC4 CTF task.
#
# ---

## 7. Case 4: Second-byte bias (Mantin–Shamir)

### Description
# RC4's second keystream byte is **more likely to be 0x00** than random:
# ```
# P(ks[1] = 0) ≈ 2/256 ≈ 1/128  (vs 1/256 for random)
# ```
#
# Additionally:
# ```
# P(ks[1] = 1) = 0
# ```
# i.e., the second byte is **never 1**. This is a hard constraint.
#
# ### Detection
# Given `N` samples of `ks[1]` from **different keys** (or different messages with different keys):
#

from collections import Counter

def detect_rc4_second_byte(second_bytes: list[int]) -> bool:
    c = Counter(second_bytes)
    n = len(second_bytes)
    # bias check
    zero_rate = c.get(0, 0) / n
    one_rate  = c.get(1, 0) / n
    print(f"P(0)={zero_rate:.4f}  P(1)={one_rate:.4f}")
    return zero_rate > 1/200 and one_rate < 1/1000

samples = [rc4(bytes([i & 0xFF]) * 16, b"X")[1] for i in range(100000)]
print(detect_rc4_second_byte(samples))
# P(0)≈0.0078 (1/128)  P(1)≈0.0000  → True

### When to use
# - **Fingerprinting** an unknown stream cipher as RC4.
# - Exploiting **the second byte only** in some challenges (rare).
# - Combined with `drop-768`: if RC4 uses `drop 768`, the bias is on byte 768 instead of 1.
#
# ---

## 8. Case 5: First-256-bytes key correlation (Roos/Mantin–Shamir)

### Description
# First few keystream bytes are **directly correlated with key bytes**:
# - `ks[0]` often equals `K[0]` or `K[0] + something`.
# - `ks[1]` is biased toward `K[0] + K[1]` in some conditions.
# - The first 256 bytes have measurable bias for **single-byte keys** (see `rc4-single-byte` attacks).

### Script: brute-force single-byte key with keystream

def crack_single_byte_rc4(known_ks: bytes) -> int:
    """Brute-force a 1-byte RC4 key against known keystream."""
    for k in range(256):
        if rc4(bytes([k]), b"\x00" * len(known_ks)) == known_ks:
            return k
    return -1


### Script: brute-force short keys (e.g., `password` dictionary)
def crack_rc4_wordlist(known_ks: bytes, wordlist_path: str) -> bytes | None:
    for line in open(wordlist_path, errors="ignore"):
        key = line.rstrip("\r\n").encode()
        if not key or len(key) > 256: continue
        if rc4(key, b"\x00" * len(known_ks)) == known_ks:
            return key
    return None

### When to use
# - Short / dictionary key.
# - WEP (3-byte IV + short key).
# - Any "weak key" scenario.
#
# ---

## 9. Case 6: Malleability (bit-flipping)

### Description
# Same as any stream cipher:
# ```
# c' = c ⊕ (p ⊕ p')  →  decrypts to p'
# ```

### Script
def bitflip(ct: bytes, p_old: bytes, p_new: bytes, offset: int = 0) -> bytes:
    assert len(p_old) == len(p_new)
    out = bytearray(ct)
    for i, (a, b) in enumerate(zip(p_old, p_new)):
        out[offset + i] ^= a ^ b
    return bytes(out)

# Example: change "guest" to "admin"
new_ct = bitflip(ct, b"guest", b"admin", offset=16)

### When to use
# - Authentication cookie / token in ciphertext.
# - Any RC4-encrypted message with a known structure.
#
# ---

## 10. Case 7: RC4 detection / fingerprinting

### Description
# Given an unknown keystream, how do you know it's RC4?
#
# **Signals:**
# 1. **Second byte = 0 more often than 1/256** (Case 4).
# 2. **Second byte ≠ 1** (hard constraint).
# 3. **Keystream has biases at specific positions** (positions 1–256).
# 4. **Keystream is byte-aligned** (not block-aligned).
# 5. **Length = plaintext length** (no padding).

### Script
def fingerprint_rc4(keystream_samples: list[bytes]) -> str:
    """
    keystream_samples: list of keystreams from DIFFERENT keys.
    Returns 'rc4' or 'unknown'.
    """
    from collections import Counter
    if not keystream_samples: return "unknown"
    second = [ks[1] for ks in keystream_samples if len(ks) > 1]
    c = Counter(second)
    n = len(second)

    p0 = c.get(0, 0) / n
    p1 = c.get(1, 0) / n

    if p0 > 0.006 and p1 < 0.001:
        return "rc4"
    return "unknown"

### When to use
# - "We intercepted traffic; identify the cipher."
# - Combined with Wireshark / pcap analysis.
#
# ---

## 11. Case 8: RC4-drop-768

### Description
# Some implementations discard the first `n` keystream bytes (`n = 256` or `768`) to avoid biases.
# **This does NOT make RC4 secure** — it only removes the *easiest* biases; long-term biases (NOMORE) still apply.

### Script
def rc4_drop(key: bytes, data: bytes, drop: int = 768) -> bytes:
    S = KSA(key)
    PRGA(S, drop)                      # discard first `drop` bytes
    ks = PRGA(S, len(data))
    return bytes(p ^ k for p, k in zip(data, ks))

### When to use
# - If the challenge code calls `rc4.drop(key, data, 768)`.
# - Or if your keystream looks random in the first bytes but the cipher is labeled RC4.
#
# ---

## 12. Case 9: Counter / IV in WEP

### Description
# WEP uses `IV || K` as the RC4 key, with **24-bit IV in cleartext** prepended to the ciphertext. The IV is **incremented** in many implementations, so it repeats every 2²⁴ ≈ 16.7M packets. **The keystream repeats** → two-time pad.

### Parse WEP-like packet
def parse_wep_packet(packet: bytes) -> tuple[bytes, bytes]:
    """WEP: [3-byte IV][ciphertext]."""
    iv = packet[:3]
    ct = packet[3:]
    return iv, ct

### Recover plaintext via IV reuse
# Given many packets, group by IV. Two packets with same IV = two-time pad.
from collections import defaultdict
by_iv = defaultdict(list)
for pkt in packets:
    iv, ct = parse_wep_packet(pkt)
    by_iv[iv].append(ct)

for iv, cts in by_iv.items():
    if len(cts) >= 2:
        c1, c2 = cts[0], cts[1]
        x = bytes(a ^ b for a, b in zip(c1, c2))    # p1 ⊕ p2
        print(f"IV {iv.hex()}: p1 ⊕ p2 = {x.hex()}")

### When to use
# - WEP capture (`.pcap` / `.cap`).
# - `aircrack-ng`, `airdecap-ng` do this automatically; write your own for CTF if you need control.
#
# ---

## 13. Case 10: RC4 in WPA-TKIP

### Description
# WPA-TKIP uses `K = K_master || IV` with `IV = (TSC_high, TSC_low)` — same structural issue as WEP, but slower. **NOMORE attack** (Vanhoef–Piessens, 2014) recovers plaintext from ~9M packets.

### Status
# - **Not CTF-friendly** (huge data requirements).
# - Use `aircrack-ng` / `tkiptun-ng` if needed.
#
# ---

## 14. Case 11: Stream cipher identification (debugging)

### Description
# If you have a `.pcap` and don't know what's inside, use `tshark`:
#
# ```bash
# tshark -r capture.pcap -Y "tcp.port==50002" -T fields -e data.data
# ```
#
# Or filter for **RTSP** (as in **Security Cam**), **HTTP**, **WEP** (`wlan.fc.protected == 1` and `wlan.key`).
#
# ### Fingerprint RC4 in pcap
# Look for:
# - Byte-aligned ciphertext (no block structure).
# - Constant first bytes (if IV is prepended).
# - Statistical biases (Case 4).
#
# ---

## 15. Quick reference: "I see RC4 — what do I do?"
#
# | Situation | Attack | Script |
# |---|---|---|
# | Known plaintext | keystream recovery | §4 |
# | Two ciphertexts, same key | `c1 ⊕ c2 = p1 ⊕ p2` | §5 |
# | Same `(key, IV)` in WEP | two-time pad | §5, §12 |
# | Short / weak key | brute force | §8 |
# | Many samples, unknown cipher | second-byte bias fingerprint | §10 |
# | Bit-flipping needed | malleability | §9 |
# | WEP `.pcap` | `aircrack-ng` or your own parser | §12 |
# | WPA-TKIP | `tkiptun-ng` (huge data) | §13 |
# | Unknown stream cipher | fingerprint + Wireshark | §11, §14 |
