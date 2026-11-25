## 1. What is a PRG/PRNG (formally)

# **Definition:** a deterministic function
# ```
# G: {0,1}^s → {0,1}^n,   with n ≫ s
# ```
# takes a short random **seed** `K ∈ {0,1}^s` and outputs a long **keystream** `G(K) ∈ {0,1}^n`.
#
# **In a stream cipher:**
# ```
# c = p ⊕ G(K)        (or G(K, nonce) — see below)
# p = c ⊕ G(K)
# ```
#
# **Key point:** determinism is the feature *and* the bug.
# Given the same seed, the output is identical — so recovering the seed (or any internal state) breaks everything.
#
# ---

## 2. Security requirements

# A PRG is **cryptographically secure** (CSPRNG) if it satisfies:
#
# | Property | Meaning |
# |---|---|
# | **Unpredictability** | Given `G(K)[0..i]`, no efficient algorithm predicts `G(K)[i+1]` with non-negligible advantage |
# | **Next-bit test** | Equivalent to unpredictability (Yao's theorem) |
# | **Statistical randomness** | Passes statistical tests (chi-square, runs, etc.) — *necessary but not sufficient* |
# | **Resistance to state recovery** | Given `n` output bits, recovering internal state is infeasible |
#
# **Critical distinction:**
# - **Statistical randomness ≠ cryptographic security.** An LCG can look statistically fine but is algebraically solvable.
# RC4 has biases. Mersenne Twister is statistically excellent but fully recoverable from 624 outputs.
#
# ---

## 3. Why PRNGs fail: the attack taxonomy

# | # | Attack | Target PRNGs | Input needed |
# |---|---|---|---|
# | 1 | **Known plaintext → keystream** | All stream ciphers | One `(p, c)` pair |
# | 2 | **Small seed brute force** | LCG, any `≤ 2²⁴` seed | A few keystream bytes |
# | 3 | **Algebraic state recovery** | LCG, Java Random | 3–6 consecutive outputs |
# | 4 | **Full state recovery** | Mersenne Twister, PHP `mt_rand` | 624 consecutive 32-bit outputs |
# | 5 | **Nonce / counter reuse** | ChaCha20, Salsa20, AES-CTR, GCM, CCM | Two ciphertexts with same nonce |
# | 6 | **Statistical bias** | RC4, older PRNGs | Many samples |
# | 7 | **Time-based seed** | `srand(time(NULL))`, `random.seed(time())` | Approximate timestamp |
# | 8 | **Fork / snapshot reuse** | VM snapshots, `fork()` without reseeding | Two processes from same seed |
# | 9 | **Truncated output recovery** | `rand() % 256`, `random.randrange(1<<20)` | Enough truncated samples |
#
# Each has a dedicated script below.
#
# ---

## 4. Case 1: Known plaintext → keystream recovery

### Description
# If you know any plaintext fragment `p` and its ciphertext `c`:
# ```
# keystream = p ⊕ c
# ```
# Now you have `keystream[0..len(p)]`. You can:
# - **Decrypt other ciphertexts** with the same keystream (same seed/nonce).
# - **Feed it into seed recovery** (Cases 2–4).
# - **Extend it** if the PRG is predictable.
#
# ### Script

def recover_keystream(known_pt: bytes, known_ct: bytes) -> bytes:
    """keystream = p ⊕ c."""
    assert len(known_pt) <= len(known_ct)
    return bytes(p ^ c for p, c in zip(known_pt, known_ct))

def decrypt_with_keystream(ct: bytes, ks: bytes) -> bytes:
    """Use recovered keystream to decrypt another ciphertext."""
    return bytes(c ^ ks[i] if i < len(ks) else c
                 for i, c in enumerate(ct))

# Example
ks = recover_keystream(b"STATUS: SERVER ONLINE", known_ct)
print(decrypt_with_keystream(secret_ct, ks))


# ### When to use
# - **Replanting**: `STATUS: SERVER ONLINE` → keystream → decrypt `secret.txt`.
# - **Noncense**: known bee quote → keystream → decrypt flag.
# - Any stream cipher task with a `known plaintext` file.
#
# ### Limitation
# Keystream only known up to `len(known_pt)`. If the secret is longer, you need **seed recovery** (Case 2/3/4) or **crib dragging** (two-time pad).
#

## 5. Case 2: Small seed → brute force

### Description
# If the seed space is small (`2^s` with `s ≤ 24`), brute-force all seeds and match against known keystream.
#
# **Classic examples:**
# - C `srand(time(NULL))` → seed is a Unix timestamp (seconds) → `~2³¹` range, but usually narrowed to a window of days/hours → `~10⁵`–`10⁶`.
# - Custom LCG with `seed < 2²⁴`.
# - **Replanting**: `seed mod 2²⁴ = 16,777,216` candidates.

### Script (generic)

def brute_seed(known_ks: bytes, gen_fn, seed_range, verbose=True):
    """
    known_ks  : observed keystream bytes
    gen_fn    : function seed -> keystream bytes (must match length)
    seed_range: iterable of candidate seeds
    """
    for seed in seed_range:
        if gen_fn(seed, len(known_ks)) == known_ks:
            if verbose:
                print(f"[+] seed found: {seed} (0x{seed:x})")
            return seed
    return None

# Example for Replanting / LCG
A, C, M = 1103515245, 12345, 2**31

def lcg_keystream(seed: int, n: int) -> bytes:
    s = seed
    out = bytearray()
    for _ in range(n):
        s = (A*s + C) % M
        out.append((s >> 16) & 0xff)
    return bytes(out)

ks = recover_keystream(b"STATUS: SERVER ONLINE", known_ct)
seed = brute_seed(ks, lcg_keystream, range(1 << 24))

### Optimization for Replanting
# The LCG keystream byte is `(state >> 16) & 0xff`, i.e., bits `16..23` of `state`.
# Since `M = 2³¹`, the low 24 bits of `state` depend **only** on the low 24 bits of `seed`.
# So brute-forcing `seed mod 2²⁴ = 16,777,216` is sufficient. In practice:

def find_lcg_seed_low24(ks: bytes) -> int:
    """Fast: first byte filters 255/256, then verify rest."""
    A, C, M = 1103515245, 12345, 2**31
    k0 = ks[0]
    rest = ks[1:]
    for seed in range(1 << 24):
        s = (A * seed + C) & (M - 1)
        if ((s >> 16) & 0xff) != k0:
            continue
        ok = True
        for k in rest:
            s = (A * s + C) & (M - 1)
            if ((s >> 16) & 0xff) != k:
                ok = False
                break
        if ok:
            return seed
    return None

# Runtime: **~30–60 s** in pure Python for 16.7M candidates. Acceptable on lab machines.

### Time-based seed (C `srand(time(NULL))` / Python `random.seed(int(time.time()))`)
import time
from datetime import datetime

def time_seed_bruteforce(known_ks: bytes, gen_fn,
                         start: datetime, end: datetime):
    """Try every second in [start, end] as seed."""
    t = int(start.timestamp())
    t_end = int(end.timestamp())
    while t <= t_end:
        if gen_fn(t, len(known_ks)) == known_ks:
            return t
        t += 1
    return None

# Narrow `start`/`end` to ±1 day of file creation time (check file mtime, `stat`, or challenge publish time).

## 6. Case 3: LCG algebraic state recovery

### Description
# LCG: `s_{n+1} = (A·s_n + C) mod M`. If you know **consecutive states** `s_0, s_1, s_2, ...`, you can solve for `A, C, M` algebraically without brute force.
#
# Math:
# ```
# t_i = s_{i+1} - s_i           (mod M)
# t_{i+1} = A · t_i              (mod M)
# => A = t_{i+1} · t_i^{-1}     (mod M)
# => C = s_1 - A · s_0          (mod M)
# ```
#
# For **M**: use the fact that `M` divides `t_{i+1}·t_{i-1} - t_i²` for all `i`. Take `gcd` of these differences.

### Script (state recovery)
from math import gcd

def recover_lcg_params(states: list[int]) -> tuple[int, int, int]:
    """
    states: at least 4 consecutive LCG states.
    Returns (A, C, M).
    """
    assert len(states) >= 4
    diffs = [(states[i+1] - states[i]) for i in range(len(states)-1)]
    # M divides (t_{i+1}*t_{i-1} - t_i^2)
    candidates = []
    for i in range(1, len(diffs)-1):
        candidates.append(abs(diffs[i+1]*diffs[i-1] - diffs[i]*diffs[i]))
    M = 0
    for c in candidates:
        M = gcd(M, c)
    # try multipliers of M as well (some tasks use a multiple)
    for mult in range(1, 10):
        if M % mult == 0:
            M_try = M // mult
            A = (diffs[1] * pow(diffs[0], -1, M_try)) % M_try
            C = (states[1] - A * states[0]) % M_try
            if all((A*states[i] + C) % M_try == states[i+1]
                   for i in range(len(states)-1)):
                return A, C, M_try
    A = (diffs[1] * pow(diffs[0], -1, M)) % M
    C = (states[1] - A * states[0]) % M
    return A, C, M

# Example
states = [s0, s1, s2, s3]
A, C, M = recover_lcg_params(states)
print(f"A={A} C={C} M={M}")
# Predict future states:
next_state = (A * states[-1] + C) % M

### When to use
# - **Not** Replanting (there the seed is hidden and only keystream bytes are exposed).
# - Custom LCG tasks where full states are exposed.
# - Any task where the "random" values are printed directly (e.g., `rand()` output without truncation).
#
# ---

## 7. Case 4: Mersenne Twister full state recovery

### Description
# **Mersenne Twister** is the default in **Python's `random`**, **PHP's `mt_rand`**, **Ruby's `rand`**, and many C/C++ libraries.
# Internal state: **624 × 32-bit words = 19,937 bits**.
#
# **Critical vulnerability:** MT is **not** cryptographically secure.
# Observing **624 consecutive 32-bit outputs** lets you reconstruct the entire state and predict **all** future (and past) outputs.

### Script (Python `random` recovery — the classic)
def untemper(y: int) -> int:
    """Invert MT19937 tempering."""
    # Undo y ^= y >> 18
    y ^= y >> 18
    # Undo y ^= (y << 15) & 0xefc60000
    y ^= (y << 15) & 0xefc60000
    # Undo y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 7) & 0x9d2c5680  # repeated (bit-by-bit inversion)
    # Undo y ^= y >> 11
    y ^= y >> 11
    y ^= y >> 11
    return y & 0xffffffff

def recover_mt_state(outputs: list[int]) -> list[int]:
    """outputs: 624 consecutive 32-bit values from random.getrandbits(32)."""
    assert len(outputs) >= 624
    return [untemper(o) for o in outputs[:624]]

# Practical use with Python's random:
import random
# Given 624 observed getrandbits(32) outputs -> clone the RNG
# (use the `randcrack` library for simplicity: pip install randcrack)

# **Easiest way (use a library):**
# pip install randcrack
from randcrack import RandCrack

rc = RandCrack()
for _ in range(624):
    rc.submit(observed_32bit_value)
next_value = rc.predict_getrandbits(32)

### When to use
# - **Python `random`** used for security (e.g., tokens, `random.randint` for OTP keys) — broken.
# - **PHP `mt_rand()`** — same recovery, but PHP's variant discards some bits; check specific variant.
# - Any task exposing enough raw 32-bit outputs.
#
# **Note:** if the task exposes `random.randint(0, 255)` (bytes), you need **624 × 32** bits, i.e., 2496 byte outputs — still feasible if the task leaks long keystream.
#
# ---

## 8. Case 5: Java `Random` (48-bit LCG)

### Description
# `java.util.Random` uses a 48-bit LCG:
# ```
# seed = (seed * 0x5DEECE66D + 0xB) & ((1<<48) - 1)
# next(bits) = seed >> (48 - bits)
# ```
#
# **Vulnerability:** observing **two consecutive `nextInt()` outputs** is enough to recover the full 48-bit state (via lattice reduction, or `2¹⁶` brute force on the low bits).

### Script (brute-force variant — simpler, works for CTF)
MULT = 0x5DEECE66D
ADD  = 0xB
MASK = (1 << 48) - 1

def java_next_int(seed: int) -> int:
    seed = (seed * MULT + ADD) & MASK
    return seed >> 16, seed       # (output, new_state)

def recover_java_seed(out1: int, out2: int) -> int:
    """
    Given two consecutive nextInt() outputs, recover the state.
    Brute force low 16 bits of intermediate state.
    """
    for low in range(1 << 16):
        # state after first nextInt
        candidate = (out1 << 16) | low
        out2_check, _ = java_next_int(candidate)
        if out2_check == out2:
            return candidate
    return None

### When to use
# - Java-based challenge (login tokens, session IDs, shuffle order).
# - Any task leaking two `nextInt()` outputs.
#
# ---

## 9. Case 6: Nonce / counter reuse (ChaCha20, Salsa20, AES-CTR, GCM, CCM)

### Description
# Strictly, this is a **stream cipher misuse**, not a PRG bug. But functionally identical to OTP key reuse: the same nonce → same keystream → `c1 ⊕ c2 = p1 ⊕ p2`.
#
# **Nonce sizes:**
# | Cipher | Nonce | Counter |
# |---|---|---|
# | Salsa20 (Snuffle) | 64-bit | 64-bit |
# | ChaCha20 (IETF) | 96-bit | 32-bit |
# | AES-CTR | IV (usually 128-bit) | counter |
# | AES-GCM | 96-bit (recommended) | 32-bit |
# | AES-CCM | 7–13 bytes | varies |

### Script (universal)
def nonce_reuse_xor(c1: bytes, c2: bytes) -> bytes:
    """c1 ⊕ c2 = p1 ⊕ p2 — use with crib dragging or known plaintext."""
    return bytes(a ^ b for a, b in zip(c1, c2))

def nonce_reuse_with_known(c1, c2, known_pt_of_c1):
    """If p1 is partially known, recover p2."""
    ks = bytes(p ^ c for p, c in zip(known_pt_of_c1, c1))
    return bytes(c ^ k for c, k in zip(c2, ks))

# ### When to use
# - **Noncense**: AES-CTR with reused nonce → known bee quote → keystream → flag.
# - **GCM / CCM nonce reuse**: also recovers the GHASH key `H` (advanced, needs GF(2¹²⁸) algebra).
# - Any "two ciphertexts, one nonce" challenge.

### GCM nonce reuse (bonus — forgery)
# Two (ciphertext, tag) pairs with the same nonce let you **forge new valid tags**. Requires solving a polynomial in GF(2¹²⁸).
# For most CTFs, if the challenge is "decrypt", the keystream recovery above is enough.
# If the challenge is "forge", you need the full attack — rare, and usually a library like `galois` helps.


## 10. Case 7: RC4 biases (advanced)

### Description
# RC4's keystream has statistical biases:
# - **Second byte** has probability `~1/128` of being `0x00` (vs `1/256` random).
# - **First ~256 bytes** correlate with the key.
# - **Long-term biases** allow plaintext recovery from many encryptions of the same message (NOMORE attack).

### Script (detect RC4 from bias)
from collections import Counter
from Crypto.Cipher import ARC4

def detect_rc4(second_bytes: list[int]) -> bool:
    c = Counter(second_bytes)
    # if second byte is 0x00 way more often than 1/256, it's RC4
    return c.get(0x00, 0) / len(second_bytes) > 1/150

# Example: collect second-byte outputs from many encryptions
samples = [ARC4.new(b"anykey").encrypt(b"X")[1] for _ in range(100000)]
print(detect_rc4(samples))   # True

### When to use
# - Identifying an unknown stream cipher as RC4.
# - Recovering plaintext from many ciphertexts (need ~10⁶ samples — rare in CTF).


## 11. Case 8: Fork / VM snapshot reuse

### Description
# Some PRNGs don't reseed on `fork()` or VM snapshot. Two processes from the same snapshot get **identical** keystreams.
#
# **Classic:** OpenSSL `RAND` pre-1.0.0, PHP-FPM forked workers, old Java `SecureRandom` on Linux.

### Script
# Same as nonce reuse — if two ciphertexts were produced from a forked process, `c1 ⊕ c2 = p1 ⊕ p2`.

x = bytes(a ^ b for a, b in zip(c1, c2))    # p1 ⊕ p2
# Then crib dragging, or known plaintext

### When to use
# - Multi-worker web challenges (session tokens, CSRF).
# - Docker/VM snapshot scenarios.

## 12. Case 9: Truncated / modulus output recovery

### Description
# If the PRNG output is **truncated** — e.g., `rand() % 256`, `random.randrange(1000)`,
# `getrandbits(8)` from MT — the full state recovery (Case 4) needs more samples. Each output has `log2(N)` bits;
# collect `19937 / log2(N)` samples, then solve the linear system (or use `randcrack` with byte-level submission).

### Script (with `randcrack` for truncated MT)
# pip install randcrack
from randcrack import RandCrack

rc = RandCrack()
# Each submission is 32 bits; if you only have 8-bit outputs:
for byte_val in observed_bytes:
    # Combine 4 consecutive bytes into one 32-bit value
    ...
    # Or use rc.submit(byte_val) — randcrack handles <32-bit too
    rc.submit(byte_val)

next_byte = rc.predict_getrandbits(8)


### When to use
# - Task exposes `random.randint(0, 255)` as keystream.
# - Task exposes `rand() % M` with small `M`.
#

## 13. Quick reference: "I see a PRNG — what do I do?"
#
# | What you have                           | Attack                                | Script    |
# |---                                      |---                                    |---        |
# | `p` + `c` (known plaintext)             | keystream recovery                    | §4        |
# | Keystream + short seed space            | brute-force seed                      | §5        |
# | Consecutive raw states (no truncation)  | algebraic LCG recovery                | §6        |
# | 624 × 32-bit outputs                    | Mersenne Twister recovery             | §7 (`randcrack`) |
# | 2 × `nextInt()` from Java               | Java `Random` recovery                | §8        |
# | Two ciphertexts, same nonce/IV          | `c1 ⊕ c2 = p1 ⊕ p2`                   | §9        |
# | Many ciphertexts, RC4                   | bias / NOMORE                         | §10       |
# | Forked/snapshot ciphertexts             | keystream reuse                       | §11       |
# | Truncated outputs                       | collect more + solve linear system    | §12       |
#