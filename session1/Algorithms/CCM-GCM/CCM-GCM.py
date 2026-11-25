# Опис
#
# CCM = CTR + CBC-MAC. NIST SP 800-38C. Один ключ для шифрування і MAC, nonce обов'язковий.
# GCM = CTR + GHASH (множення в GF(2¹²⁸)). NIST SP 800-38D. Дуже швидкий (паралелізм), використовується в TLS 1.3.
# GMAC = GCM без шифрування (тільки MAC).
# Вразливості
#
# Nonce reuse — катастрофа для обох: повторне використання nonce → відновлення автентифікаційного ключа GHASH і keystream.
# Tag truncation: занадто короткий тег → forgery.
# GHASH weakness: якщо nonce повторюється, можна відновити H (hash key) з двох (c, tag) пар.
# CCM — двопрохідний (повільніший за GCM).
# Скрипти

# (a) GCM шифрування / дешифрування

from Crypto.Cipher import AES

def gcm_encrypt(key, nonce, plaintext, aad=b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)   # (ct, tag)

def gcm_decrypt(key, nonce, ct, tag, aad=b""):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)

# (b) CCM

def ccm_encrypt(key, nonce, plaintext, aad=b""):
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)

# (c) GCM nonce reuse → keystream recovery

# c1 = p1 ⊕ ks, c2 = p2 ⊕ ks
# c1 ⊕ c2 = p1 ⊕ p2
# якщо відомий p1 → отримуємо p2
def gcm_nonce_reuse(c1, c2, known_pt):
    ks = bytes(a ^ b for a, b in zip(c1, known_pt))
    return bytes(c ^ k for c, k in zip(c2, ks))
# (d) GCM nonce reuse → forgery (відновлення H)
# Це математично складніше; на CTF зазвичай дають готовий solve.
# Ідея: tag = E_K(J0) ⊕ GHASH_H(A,C), де GHASH_H(X) = X_1·H^m ⊕ ... ⊕ X_m·H.
# Два повідомлення з тим самим nonce дають два рівняння на H — розв'язуємо в GF(2¹²⁸).
#
# (e) CCM — той самий принцип: якщо nonce повторюється, автентифікація ламається.
#
# Коли що: у завданні є GCM/CCM — перевіряй nonce в першу чергу.