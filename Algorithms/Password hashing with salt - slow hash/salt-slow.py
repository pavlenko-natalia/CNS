# Опис
#
# Зберігати не сам пароль, а H(salt || password) або slow_hash(salt || password).
# Сіль — псевдовипадкова, унікальна для кожного користувача.
# "Повільні" хеші (bcrypt, scrypt, Argon2, PBKDF2) ускладнюють brute force.
#
# Вразливості
#
# Без солі: однакові паролі → однакові хеші, rainbow tables працюють.
# Швидкий хеш (SHA-256, MD5) → мільярди спроб/сек на GPU.
# Мала кількість ітерацій (наприклад, PBKDF2 з 1000 ітерацій) — сучасно недостатньо.
# Сіль коротка (8 біт) → rainbow tables знову стають ефективними.
# Сіль = user ID (детермінована) — передбачувано, але не катастрофа.
# Timing attack на порівняння хешів (якщо не constant-time).
# Скрипти

# (a) Правильне хешування пароля (PBKDF2)

import hashlib, os
def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return salt + h       # зберігаємо разом

# (b) Верифікація

def verify_password(password: str, stored: bytes) -> bool:
    salt, h = stored[:16], stored[16:]
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return hmac.compare_digest(calc, h)

# (c) Сучасні "повільні" хеші

# pip install argon2-cffi bcrypt
from argon2 import PasswordHasher
ph = PasswordHasher()
h = ph.hash("hunter2")
ph.verify(h, "hunter2")     # True

import bcrypt
h = bcrypt.hashpw(b"hunter2", bcrypt.gensalt(rounds=12))
bcrypt.checkpw(b"hunter2", h)

# (d) Dictionary attack на швидкий хеш

import hashlib
target_salt = bytes.fromhex("aabbcc...")
target_hash = bytes.fromhex("ddeeff...")
for pw in open("rockyou.txt", errors="ignore"):
    pw = pw.rstrip("\r\n")
    calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), target_salt, 1)
    if calc == target_hash:
        print("FOUND:", pw); break

# (e) Оцінка розміру rainbow table (для політів)

# для N паролів, m-бітного хешу, без солі:
N = 10**9           # 1 млрд паролів
m = 256             # SHA3-256
# розмір = N * (m/8) байт
print(f"{(N * m) // 8 // 10**9} GB")   # ≈ 32 GB

# з 16-бітною сіллю: множимо на 2^16
print(f"{(N * m * (1<<16)) // 8 // 10**12} TB")   # ≈ 2 TB

# Коли що: завдання "зламати пароль" → (d). "Порахувати розмір rainbow table" → (e). "Показати правильну реалізацію" → (a)+(b)+(c).