# Потоковий шифр, дизайн ARX (add-rotate-XOR). Внутрішній стан — 4×4 матриця 32-бітних слів; 20 раундів (10 double-rounds).
# Ключ 256 біт (або 128), nonce 64 біт, counter 64 біт. Належить до сімейства Snuffle.
#
# Вразливості
#
# Nonce reuse: якщо той самий ключ і nonce використано двічі → однаковий keystream → c1⊕c2 = p1⊕p2.
# Malleability (без MAC).
# Повторне використання ключа з різними nonce безпечне, але повторне використання nonce — катастрофа.
# Відомі атаки на зменшену кількість раундів (8 раундів ламаються за ~2²⁵⁰).
# Скрипти

# (a) Salsa20 encryption/decryption

from Crypto.Cipher import Salsa20

def salsa20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)

# приклад
key = bytes.fromhex("...")   # 32 байти
nonce = bytes.fromhex("...") # 8 байт
ct = bytes.fromhex("...")
print(salsa20_crypt(key, nonce, ct))

# (b) Nonce reuse → відновлення keystream і розшифрування

# c1 = p1 ⊕ ks, c2 = p2 ⊕ ks  →  ks = p1 ⊕ c1
known_pt = b"known plaintext here"
known_ct = bytes.fromhex("...")
ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))

secret_ct = bytes.fromhex("...")
secret_pt = bytes(c ^ k for c, k in zip(secret_ct, ks))
print(secret_pt)

# (c) Nonce reuse без known plaintext → c1 ⊕ c2 = p1 ⊕ p2 + crib dragging

c1 = bytes.fromhex("...")
c2 = bytes.fromhex("...")
x = bytes(a ^ b for a, b in zip(c1, c2))
# шукаємо відомий фрагмент (cns{, the, http) у x за допомогою crib dragging

# Коли що: є ключ/nonce → (a). Є known plaintext і secret ciphertext → (b). Є два ciphertext без known plaintext → (c).