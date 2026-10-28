# Опис
#
# s_{n+1} = (A·s_n + C) mod M. Класичний непридатний PRG: лінійний за модулем.
#
# Вразливості
#
# Передбачуваність з кількох виходів. Якщо відомі послідовні s_i, параметри A, C, M можна розв'язати алгебраїчно:
#
# s_{i+1} - s_i = A·(s_i - s_{i-1}) mod M → A = (s_{i+2}-s_{i+1}) / (s_{i+1}-s_i) mod M (за наявності оберненого елемента).
# Seed відновлюється brute force, якщо ключовий простір малий (тут 2^24 через молодші біти).
# Молодші/середні біти мають малий період — state >> 16 & 0xff залежить лише від seed mod 2^24.
# Скрипти
#
# (a) Known keystream → brute force low 24 bits seed (Replanting)

A, C, M = 1103515245, 12345, 2**31
ks = bytes.fromhex("...")

# байти keystream = (state >> 16) & 0xff; вони залежать лише від seed mod 2^24
def gen(seed, n):
    s = seed; out = bytearray()
    for _ in range(n):
        s = (A*s + C) % M
        out.append((s >> 16) & 0xff)
    return bytes(out)

for seed in range(1 << 24):
    if gen(seed, len(ks)) == ks:
        print("FOUND seed mod 2^24:", seed); break

# (b) Відомі стани → розв'язати A, C, M

from math import gcd
states = [s0, s1, s2, s3]  # відомі послідовні стани

# t_i = s_{i+1} - s_i mod M
t = [(states[i+1] - states[i]) for i in range(len(states)-1)]
# A = t_{i+1} / t_i mod M
# C = s_{i+1} - A*s_i mod M
# M ділить t_{i+1}*t_{i-1} - t_i^2 → знаходимо через gcd різниць
diffs = [t[i+1]*t[i-1] - t[i]*t[i] for i in range(1, len(t)-1)]
M = gcd(*diffs) if len(diffs) > 1 else diffs[0]
print("M =", M)
A = (t[1] * pow(t[0], -1, M)) % M
C = (states[1] - A*states[0]) % M
print("A,C,M =", A, C, M)

# (c) Передбачення наступного стану, коли відомий A, C, M

def next_state(s, A, C, M): return (A*s + C) % M
def next_byte(s, A, C, M):
    s = next_state(s, A, C, M)
    return (s >> 16) & 0xff, s

# Коли що: у нас cipher.py і відомий фрагмент plaintext → (a). Якщо відомі самі стани (наприклад, з іншого завдання) → (b). Коли просто треба продовжити — (c).
#
# RC4
# Salsa20
# ChaCha20
# DES
# Triple DES / 3DES
# AES (AES-128/192/256)
# AES modes: ECB, CBC, CFB, OFB, CTR, XTS-AES
# Salsa20/ChaCha20 nonce/counter
# MD5
# SHA-1
# SHA-2 (SHA-256 etc.)
# SHA-3 / Keccak
# Custom “Better Hash”
# HMAC
# CMAC
# MAC
# CCM / GCM (authenticated encryption)
# Password hashing with salt / slow hash
# GF(2⁸) arithmetic
# Extended Euclidean algorithm