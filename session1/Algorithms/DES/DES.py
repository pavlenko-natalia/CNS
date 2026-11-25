# Блоковий шифр, 64-бітний блок, 56-бітний ефективний ключ, 16 раундів, структура Фейстеля. Застарілий, але досі зустрічається в CTF та легасі-системах.
#
# Вразливості
#
# Brute force 2⁵⁶: на сучасному обладнанні — години; у CTF часто ключ ще коротший (наприклад, IOTDEV + 2 байти = 2¹⁶).
# Слабкі/напівслабкі ключі (4 слабкі, 12 напівслабких).
# ECB-режим → однакові блоки → однаковий ciphertext.
# Meet-in-the-middle для 2DES/3DES (див. нижче).
# Скрипти

# (a) Brute force DES з відомим префіксом ключа (Key standardisation)

from Crypto.Cipher import DES

message = bytes.fromhex("...")
for i in range(65536):
    key = b"IOTDEV" + i.to_bytes(2, "big")
    pt = DES.new(key, DES.MODE_ECB).decrypt(message)
    if b"cns{" in pt:
        print(f"FOUND key={key!r}  pt={pt!r}")
        break

# (b) Повний brute force 2⁵⁶ (дуже повільно, але можливо з оптимізацією)

from Crypto.Cipher import DES
import itertools

def brute_des(known_pt, known_ct, prefix=b""):
    for i in range(1 << 16):
        key = prefix + i.to_bytes(8 - len(prefix), "big")
        if DES.new(key, DES.MODE_ECB).encrypt(known_pt) == known_ct:
            return key
    return None

# (c) ECB detection (однакові блоки)

def detect_ecb(ct: bytes, block_size=8) -> bool:
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    return len(blocks) != len(set(blocks))

# Коли що: відомий формат ключа → (a). Загальний випадок → (b) (повільно). Треба визначити режим → (c).

