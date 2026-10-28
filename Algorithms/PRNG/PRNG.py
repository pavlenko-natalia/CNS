# Опис
#
# keystream = PRG(seed); c = p ⊕ keystream. Реальний stream cipher — це «OTP з псевдовипадковим ключем». Приклади: RC4, Salsa20/ChaCha20, LCG-based.
#
# Вразливості
#
# Known plaintext → миттєво відновлюємо keystream: ks = p ⊕ c. Далі — розшифровуємо інші повідомлення з тим самим keystream або шукаємо seed.
# Nonce/IV reuse (CTR, Salsa20/ChaCha20) → той самий ефект, що key reuse в OTP: c1⊕c2 = p1⊕p2.
# PRG не unpredictable (LCG, лінійні конгруенції) → можна відновити seed або передбачити наступні байти.
# Bias у keystream (RC4) → статистичні атаки.
# Скрипти
#
# (a) Known plaintext → keystream → розшифрувати інше

known_pt = b"STATUS: SERVER ONLINE"
known_ct = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f")
ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))
print("keystream:", ks.hex())

secret_ct = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b0...")
# якщо secret_ct коротший або рівний — просто XOR
# якщо довший — треба знайти seed (див. (b))

# (b) LCG: known keystream → brute force seed

# параметри з умови Replanting / cipher.py
A, C, M = 1103515245, 12345, 2**31
def gen(seed, n):
    s = seed; out = bytearray()
    for _ in range(n):
        s = (A*s + C) % M
        out.append((s >> 16) & 0xff)
    return bytes(out)

ks = bytes.fromhex("...")   # відомі байти keystream
# оскільки байти беруться з бітів 16..23, seed mod 2^24 = 16 777 216 варіантів
for low in range(1 << 24):
    if gen(low, len(ks)) == ks:
        print("seed mod 2^24:", low); break

# (c) Nonce reuse в CTR / Salsa20 / ChaCha20

c1 = bytes.fromhex("...")
c2 = bytes.fromhex("...")
# та сама nonce → keystream однаковий → c1 ^ c2 = p1 ^ p2
print(bytes(a ^ b for a, b in zip(c1, c2)))
# + crib dragging з відомим фрагментом

# Коли що: маєш known plaintext і треба лише інше повідомлення (Replanting) → (a). Треба весь keystream для довшого secret → (b). Nonce reuse → (c).