# C = E(K3, D(K2, E(K1, P))). 2-key variant (K1=K3) → 112-бітний ключ; 3-key → 168-бітний.
# Використовується у легасі-системах, але поступово виводиться.
#
# Вразливості
#
# Meet-in-the-middle на 2-key 3DES: складність ~2¹¹² (замість 2¹¹²? насправді для 2-key 3DES — 2¹¹², для 3-key — 2¹⁶⁸;
# MITM на 3DES не дає виграшу через потрійне шифрування).
# Слабкі ключі: якщо K1=K2=K3 → DES.
# ECB-режим → ті самі проблеми, що й у DES.
# Скрипти

# (a) 3DES encryption/decryption

from Crypto.Cipher import DES3

def des3_crypt(key: bytes, data: bytes, mode=DES3.MODE_ECB, iv=None):
    if mode == DES3.MODE_ECB:
        return DES3.new(key, mode).encrypt(data)
    return DES3.new(key, mode, iv=iv).encrypt(data)

# (b) Meet-in-the-middle для 2-key 3DES (концептуально)

from Crypto.Cipher import DES
from tqdm import tqdm

def mitm_2des(known_pt, known_ct):
    # таблиця для k1
    table = {}
    for k1 in tqdm(range(1 << 56)):
        k1_bytes = k1.to_bytes(8, "big")
        table[DES.new(k1_bytes, DES.MODE_ECB).encrypt(known_pt)] = k1_bytes
    # перебір k2
    for k2 in range(1 << 56):
        k2_bytes = k2.to_bytes(8, "big")
        mid = DES.new(k2_bytes, DES.MODE_ECB).decrypt(known_ct)
        if mid in table:
            return table[mid], k2_bytes

# (У реальному CTF 2⁵⁶ не перебирають; швидше за все, ключі коротші або є витік.)

# (c) Виявлення 3DES за допомогою MITM на зменшеному ключовому просторі

# якщо ключі 20-бітні (як в "AES 2 demo"), MITM працює за 2^20

# Коли що: ключ відомий → (a). Треба ламати 2-key 3DES → (b) (повільно). Ключі короткі → (c).