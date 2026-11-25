# Description
#
# c = p ⊕ k, where |k| = |p|, k is truly random and used only once. The only absolutely secure cipher (Shannon).
#
# Vulnerabilities
#
# Key reuse (double use) → c₁ ⊕ c₂ = p₁ ⊕ p₂ — the main attack.
# Crib dragging: if we know part of p1, we can obtain the corresponding part of p2.
# Malleability: XOR modification of the ciphertext.
# In practice, OTPs are almost never implemented correctly; they are usually stream ciphers with a poor PRG.
#-------------------------------------------------------------
# Опис
#
# c = p ⊕ k, де |k| = |p|, k — істинно випадковий, використовується один раз. Єдиний безумовно стійкий шифр (Shannon).
#
# Вразливості
#
# Key reuse (двократне використання) → c1⊕c2 = p1⊕p2 — основна атака.
# Crib dragging: якщо знаємо частину p1 — отримуємо відповідну частину p2.
# Malleability: XOR-модифікація ciphertext.
# Практично OTP майже ніколи не реалізують коректно; зазвичай це stream cipher з поганим PRG.
#-------------------------------------------------------------

# (a) Key reuse (two-time pad)

def crib_drag(x: bytes, crib: bytes, printable_only=True):
    """
    x = p1 ⊕ p2
    crib — відомий фрагмент p1 (або p2)
    Шукаємо всі позиції, де crib дає читабельний p2.
    """
    results = []
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if printable_only:
            if all(32 <= b < 127 or b in (9, 10, 13) for b in guess):
                results.append((i, guess))
        else:
            results.append((i, guess))
    return results

# example
x = xor_bytes(c1, c2)      # = p1 ⊕ p2
for pos, frag in crib_drag(x, b"cns{"):
    print(f"pos {pos}: якщо p1[{pos}:{pos+4}]==b'cns{{', то p2[{pos}:{pos+4}]=={frag!r}")

# When we have many pieces of p1, we can reconstruct the whole of p1, then k = c1 ⊕ p1, and then p2 = c2 ⊕ k. Strategy:
def recover_two_time_pad(c1: bytes, c2: bytes, known_fragments: dict):
    """
    known_fragments: {position: b'fragment'} — known parts p1 (or p2).
    return (p1, p2).
    """
    x = bytes(a ^ b for a, b in zip(c1, c2))   # p1 ⊕ p2
    n = len(x)
    p1 = bytearray(n)
    p2 = bytearray(n)
    known_p1 = bytearray(n)   # 1, if p1[i] known
    known_p2 = bytearray(n)

    # 1) Fill known parts
    for pos, frag in known_fragments.items():
        for j, b in enumerate(frag):
            p1[pos + j] = b
            known_p1[pos + j] = 1
            # find p2 the same way
            p2[pos + j] = x[pos + j] ^ b
            known_p2[pos + j] = 1

    # 2) Expand: where p2 is known → p1 = x ⊕ p2 (and vice versa)
    changed = True
    while changed:
        changed = False
        for i in range(n):
            if known_p1[i] and not known_p2[i]:
                p2[i] = x[i] ^ p1[i]
                known_p2[i] = 1
                changed = True
            elif known_p2[i] and not known_p1[i]:
                p1[i] = x[i] ^ p2[i]
                known_p1[i] = 1
                changed = True

    return bytes(p1), bytes(p2), bytes(known_p1), bytes(known_p2)

# (b) Many-time pad

# same key for c_i = p_i ⊕ k,   i = 1..N

from collections import Counter

ENG_FREQ = {
    ' ': 12.7, 'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0,
    'u': 2.8, 'c': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0,
    'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15,
    'x': 0.15, 'q': 0.10, 'z': 0.07, '\n': 0.5, '\r': 0.1, '\t': 0.1,
}

def score_byte(b: int) -> float:
    return ENG_FREQ.get(chr(b).lower(), -3.0)

def crack_many_time_pad(ciphertexts: list[bytes], max_len=None) -> bytes:
    """
    ciphertexts: list ciphertext.
    returns key (or None for the position where its not enought data to recoer).
    """
    max_len = max_len or max(len(c) for c in ciphertexts)
    key = bytearray()
    for t in range(max_len):
        col = [c[t] for c in ciphertexts if t < len(c)]
        if not col:
            key.append(0); continue
        # fpr each candidate k[t] — decode column i and score
        best_k, best_score = 0, -1e18
        for cand in range(256):
            s = sum(score_byte(b ^ cand) for b in col)
            if s > best_score:
                best_score, best_k = s, cand
        key.append(best_k)
    return bytes(key)

# usage
key = crack_many_time_pad(ciphertexts)
for c in ciphertexts:
    print(bytes(a ^ b for a, b in zip(c, key)))

# Same but for long messages
def crack_many_time_pad_fast(ciphertexts, max_len=None):
    max_len = max_len or max(len(c) for c in ciphertexts)
    key = bytearray()
    for t in range(max_len):
        col = [c[t] for c in ciphertexts if t < len(c)]
        if not col:
            key.append(0); continue
        # assume that space is the most frequent symbol in column
        most_common, _ = Counter(col).most_common(1)[0]
        key.append(most_common ^ 0x20)
    return bytes(key)

# (c) Known plaintext → keystream recovery

def recover_keystream(known_pt: bytes, known_ct: bytes) -> bytes:
    assert len(known_pt) <= len(known_ct)
    return bytes(p ^ c for p, c in zip(known_pt, known_ct))

def decrypt_with_keystream(ct: bytes, ks: bytes) -> bytes:
    return bytes(c ^ ks[i] if i < len(ks) else 0
                 for i, c in enumerate(ct))

# usage: Replanting / Noncense
ks = recover_keystream(b"STATUS: SERVER ONLINE", known_ct)
secret_pt = decrypt_with_keystream(secret_ct, ks)

# (d) «OTP» actually repeating-key XOR - same as 3 step attack in XOR

# (e) «OTP» using pseudorandom key (PRG instead of TRNG)
# Instead of a truly random k, a PRG is used: k = PRG(seed). This is not an OTP (perfect secrecy is lost), but a stream cipher.
# If the PRG is weak (LCG), the seed can be reconstructed.

# LCG: s_{n+1} = (A*s_n + C) mod M
A, C, M = 1103515245, 12345, 2**31

def gen_keystream(seed: int, n: int) -> bytes:
    s = seed
    out = bytearray()
    for _ in range(n):
        s = (A*s + C) % M
        out.append((s >> 16) & 0xff)
    return bytes(out)

def recover_lcg_seed(known_ks: bytes) -> int:
    """
    The keystream bytes depend solely on the seed mod 2^24, because
    (s >> 16) & 0xff depends only on bits 16–23 of the state,
    whilst the least significant 24 bits of s are determined by the least significant 24 bits of the seed.
    """
    for low in range(1 << 24):
        if gen_keystream(low, len(known_ks)) == known_ks:
            return low
    return None

# known keystream bytes from known_pt ⊕ known_ct
known_ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))
seed = recover_lcg_seed(known_ks)
# Now we can decrypt anything by generating a keystream from a seed

# (f) Biased key

#The key is not uniform (for example, only “a”–'z', or biased towards 0). Perfect secrecy is lost.

import itertools

def crack_biased_key(ct: bytes, alphabet: bytes, max_len: int = 4):
    for klen in range(1, max_len + 1):
        for key_tuple in itertools.product(alphabet, repeat=klen):
            key = bytes(key_tuple)
            pt = bytes(c ^ key[i % klen] for i, c in enumerate(ct))
            # score for known structures
            if b"cns{" in pt or b" the " in pt:
                print(f"klen={klen}  key={key!r}  pt={pt!r}")


# (g) Comparison of several ‘OTP’s’ with different keys (triangular attack)
#
# Let c1 = p1 ⊕ k1, c2 = p2 ⊕ k2, c3 = p3 ⊕ k3, … Sometimes the keys are related (for example, k2 = k1 ⊕ Δ, where Δ is known/small).
# Then:
# c1 ⊕ c2 = (p1 ⊕ k1) ⊕ (p2 ⊕ k1 ⊕ Δ) = p1 ⊕ p2 ⊕ Δ
# If Δ is known → the same as a two-time pad.

def xor_three(a: bytes, b: bytes, delta: bytes) -> bytes:
    """c1 ⊕ c2 ⊕ Δ = p1 ⊕ p2, if k2 = k1 ⊕ Δ."""
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, delta))
