#  (AES-128/192/256)
#
# Опис
#
# Блоковий шифр, 128-бітний блок. Ключ 128/192/256 біт → 10/12/14 раундів. Раунди: SubBytes, ShiftRows, MixColumns, AddRoundKey. Фінальний раунд без MixColumns. Використовує GF(2⁸).
#
# Вразливості
#
# Сам AES стійкий; атаки — на режими та реалізації.
# Side-channel (timing, power) — поза межами більшості CTF.
# ECB → детермінований, однакові блоки → однаковий ciphertext.
# CBC → bit-flipping, padding oracle.
# CTR → nonce reuse → keystream reuse.
# XTS → потребує двох ключів; використовується для disk encryption.
# Скрипти

# (a) AES encryption/decryption (усі ключі)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def aes_crypt(key: bytes, data: bytes, mode=AES.MODE_ECB, iv=None):
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
        return cipher.encrypt(pad(data, 16))
    cipher = AES.new(key, mode, iv=iv)
    return cipher.encrypt(pad(data, 16))

# (b) AES key recovery через MITM для подвійного AES з короткими ключами (AES 2 demo)

from Crypto.Cipher import AES

def mitm_double_aes(known_pt, known_ct, key_bits=20):
    # K1 = k1_small || 0... , K2 = k2_small || 0...
    table = {}
    for k1 in range(1 << key_bits):
        key1 = k1.to_bytes(3, "big") + b"\x00" * 13
        ct1 = AES.new(key1, AES.MODE_ECB).encrypt(known_pt)
        table[ct1] = key1
    for k2 in range(1 << key_bits):
        key2 = k2.to_bytes(3, "big") + b"\x00" * 13
        mid = AES.new(key2, AES.MODE_ECB).decrypt(known_ct)
        if mid in table:
            return table[mid], key2

# Коли що: звичайне шифрування → (a). Подвійний AES з короткими ключами → (b).

