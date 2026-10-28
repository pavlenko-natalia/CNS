# Потоковий шифр з байт-орієнтованим PRG, що підтримує внутрішній стан S[256] та генерує keystream байт за байтом. Історично використовувався у WEP, WPA-TKIP, SSL/TLS, SSH. Ключ — від 1 до 256 байт.
#
# Вразливості
#
# Статистичні біаси keystream: другий байт виходу зміщений до 0x00 з імовірністю 1/128 (замість 1/256); перші кілька байт сильно корелюють з ключем.
# Відсутність nonce → повторне використання ключа дає однаковий keystream для різних повідомлень.
# Malleability: як і всі потокові шифри без MAC, XOR-модифікація ciphertext змінює plaintext.
# Практичні атаки (NOMORE, 2014) відновлюють plaintext з HTTPS/WPA-TKIP за статистичними біасами.
# Скрипти
#
# (a) RC4 encryption/decryption (якщо ключ відомий)

from Crypto.Cipher import ARC4

def rc4_crypt(key: bytes, data: bytes) -> bytes:
    return ARC4.new(key).encrypt(data)

# приклад
key = b"secretkey"
ct = bytes.fromhex("...")
print(rc4_crypt(key, ct))


# (b) Виявлення RC4 за біасом другого байта

from Crypto.Cipher import ARC4
from collections import Counter

def detect_rc4(samples):
    """samples: список ciphertext-байтів (другий байт кожного)"""
    c = Counter(samples)
    # якщо ймовірність 0x00 ≈ 1/128 → це RC4
    return c.get(0x00, 0) / len(samples) > 1/200

# збираємо другі байти з багатьох шифрувань
samples = [ARC4.new(b"test").encrypt(b"A")[1] for _ in range(100000)]
print(detect_rc4(samples))

# (c) Відновлення plaintext через повторне використання ключа (keystream reuse)

# c1 ⊕ c2 = p1 ⊕ p2  (якщо ключ той самий)
c1 = bytes.fromhex("...")
c2 = bytes.fromhex("...")
x = bytes(a ^ b for a, b in zip(c1, c2))
print(x)   # p1 ⊕ p2 — далі crib dragging

# Коли що: ключ відомий → (a). Треба підтвердити, що це RC4 → (b). Є два ciphertext з тим самим ключем → (c).