# Опис
#
# Будь-який механізм автентифікації повідомлення з секретним ключем: HMAC, CMAC, Poly1305, UMAC, MAC-then-encrypt. Дає integrity + authenticity (не confidentiality).
#
# Вразливості (загальні)
#
# Length extension — якщо H(K||M) замість HMAC.
# MAC-then-encrypt (SSL/TLS 1.0) → padding oracle (Vaudenay). Encrypt-then-MAC — правильний порядок.
# Encrypt-and-MAC (SSH) — не стандартизовано для AE.
# Не constant-time порівняння → timing attack.
# Truncated MAC → birthday attack на N біт.
# Key reuse між різними алгоритмами.
# Скрипт: MAC-then-encrypt vs Encrypt-then-MAC (ілюстрація)

import hmac, hashlib, os
from Crypto.Cipher import AES

def mac_then_encrypt(k_enc, k_mac, m):
    tag = hmac.new(k_mac, m, hashlib.sha256).digest()
    return AES.new(k_enc, AES.MODE_CBC, iv=os.urandom(16)).encrypt(m + tag)

def encrypt_then_mac(k_enc, k_mac, m):
    iv = os.urandom(16)
    c = AES.new(k_enc, AES.MODE_CBC, iv=iv).encrypt(m)   # (з padding)
    tag = hmac.new(k_mac, iv + c, hashlib.sha256).digest()
    return iv + c + tag

# Коли що: у завданнях рідко треба "ламати" MAC; частіше — обійти його через implementation-баг (як у HMAC-завданнях).