# (Cipher Block Chaining)
#
# Опис: C_i = E(P_i ⊕ C_{i-1}), IV для першого блоку. Вразливості:
#
# Bit-flipping: зміна байта в C_{i-1} змінює відповідний байт P_i (але псує P_{i-1}).
# IV manipulation: якщо IV контролюється, можна змінити перший блок без псування попереднього.
# Padding oracle (якщо сервер розкриває інформацію про валідність padding).
# Скрипт: CBC bit-flipping

def cbc_bitflip(blob: bytearray, pos: int, cur: int, target: int, bs: int = 16):
    """pos — абсолютна позиція plaintext; редагуємо блок на bs раніше."""
    flip_pos = pos - bs
    blob[flip_pos] ^= cur ^ target
    return blob

# приклад: змінити 'guest' → 'admin' у IV+C0
blob = bytearray(iv + c0 + c1)
for k, (have, want) in enumerate(zip(b'guest', b'admin')):
    cbc_bitflip(blob, 16 + 16 + 6 + k, have, want)

# Скрипт: padding oracle (спрощено)

def padding_oracle_attack(oracle, ct, block_size=16):
    """oracle: функція, що повертає True/False за валідність padding."""
    pt = b""
    prev = ct[:block_size]
    for i in range(len(ct)//block_size - 1, 0, -1):
        # підбір байтів з кінця
        ...
    return pt

# (Повний padding oracle досить об'ємний; на сесії краще мати готовий шаблон.)