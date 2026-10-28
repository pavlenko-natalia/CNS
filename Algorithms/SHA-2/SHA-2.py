# (SHA-256, SHA-512, ...)
#
# Опис
#
# Родина хешів: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256. Merkle–Damgård, 64 або 80 раундів. Стандарт де-факто для HMAC, TLS, підписів, JWT.
#
# Вразливості
#
# Сам по собі — стійкий. Атаки — на застосування.
# Length extension (Merkle–Damgård), якщо використовувати H(K||M) як MAC.
# Truncation: якщо зберігають лише перші N біт → birthday attack на N біт.
# JSON canonicalization в HMAC (див. нижче) → підписується одна форма, перевіряється інша.
# Скрипти

# (a) SHA-256 обчислення

import hashlib
print(hashlib.sha256(b"hello").hexdigest())

# (b) Length extension (SHA-256)

import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="...", old_msg="...", append_data="admin=1", key_len=16
)

# (c) Birthday attack на truncated SHA-256 (Secure Bank 2)

import hashlib, os
def truncated_hash(payment_json, bits=32):
    return hashlib.sha256(payment_json).digest()[:bits//8]

# генеруємо багато валідних payment records, шукаємо колізію
seen = {}
while True:
    record = make_valid_payment()       # генеруємо валідний запис
    h = truncated_hash(record)
    if h in seen and seen[h] != record:
        print("COLLISION:", seen[h], record)
        break
    seen[h] = record
    
# Коли що: звичайний хеш → (a). Length extension → (b). Truncated → (c).