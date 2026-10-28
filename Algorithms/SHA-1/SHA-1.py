# Опис
#
# 160-бітний хеш, Merkle–Damgård, дизайн MD4/MD5. Оголошений небезпечним з 2005 (NIST), але досі в легасі-системах і CTF.
#
# Вразливості
#
# Практичні колізії: SHAttered (Google + CWI, 2017) — 2 різних PDF з однаковим SHA-1. Атака за 2⁶³ операцій.
# Length extension — те саме, що MD5.
# Відсутність солі у password storage — класичний LinkedIn 2012.
# Скрипти

# (a) SHA-1 обчислення

import hashlib
print(hashlib.sha1(b"hello").hexdigest())

# (b) Length extension (той самий принцип, що для MD5)

import hashpumpy
new_hash, new_msg = hashpumpy.hashpump(
    old_hash="...", old_msg="...", append_data="&admin=1", key_len=16
)

# (c) Детектор unsalted SHA-1 (за статистикою спільних хешів)

# якщо два користувачі мають однаковий пароль → однаковий хеш
# → підтвердження, що сіль не використовується
# Коли що: аналогічно MD5; SHA-1 у CTF частіше для length extension, ніж для прямих колізій.