# Опис: режим для disk encryption. Використовує два AES-ключі (подвійна довжина) і tweak (номер сектора). Кожен блок шифрується незалежно, але tweak гарантує, що однакові блоки в різних позиціях дають різний ciphertext.
#
# Вразливості:
#
# Складність: потребує 256/512-бітного ключа; не підтримує AES-192.
# Tweak reuse (якщо той самий tweak для різних даних) → детермінованість.
# Side-channel (як у звичайного AES).
# Скрипт: XTS encryption (приклад)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def xts_encrypt(key: bytes, tweak: bytes, data: bytes):
    # key = Key1 || Key2 (32 або 64 байти)
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()