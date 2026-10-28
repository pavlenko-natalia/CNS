# Опис
#
# 128-бітний хеш, Merkle–Damgård, розроблений Rivest (1991). Досі широко зустрічається в CTF, легасі-системах, RTSP/HTTP Digest, де є альтернативи. У курсі — приклад "чому не можна використовувати MD5".
#
# Вразливості
#
# Колапси: з 2004 року (Wang et al.), практичний collision за секунди → SHAttered (2017) ще більше.
# Length extension: через Merkle–Damgård — H(K||M) вразливий, якщо використовувати як MAC.
# Відсутність солі → rainbow tables, dictionary attack. Класичний приклад — LinkedIn 2012 (SHA-1 без солі, але тут той самий принцип).
# RTSP Digest Authentication використовує MD5 — це атака на протокол, а не на MD5 (словник паролів).
# Скрипти

# (a) Обчислення MD5 (потрібно для верифікації)

import hashlib
print(hashlib.md5(b"hello").hexdigest())

# (b) Length extension для MD5 (демонстрація)

# H(K||M) → H(K||M||pad||M') без знання K
# потребує hashpumpy або власної реалізації MD5
try:
    import hashpumpy
    new_hash, new_msg = hashpumpy.hashpump(
        old_hash="...", old_msg="...", append_data="&admin=1", key_len=16
    )
    print(new_hash, new_msg)
except ImportError:
    print("pip install hashpumpy")

# (c) RTSP Digest response (Security Cam)

import hashlib
def md5(s): return hashlib.md5(s.encode()).hexdigest()

def rtsp_digest(user, realm, password, method, uri, nonce):
    ha1 = md5(f"{user}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{nonce}:{ha2}")

# для кожного слова з rockyou.txt → порівняти з expected response
# (d) Dictionary attack на збережений MD5-хеш

import hashlib
target = "5d41402abc4b2a76b9719d911017c592"   # "hello"
for pw in open("rockyou.txt", errors="ignore"):
    pw = pw.rstrip("\r\n")
    if hashlib.md5(pw.encode()).hexdigest() == target:
        print("FOUND:", pw); break
        
# Коли що: перевірка хешу → (a). Length extension → (b). Security Cam → (c). CTF-словник → (d).