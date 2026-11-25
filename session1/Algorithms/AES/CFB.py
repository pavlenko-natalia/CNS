# (Cipher Feedback)
#
# Опис: перетворює блоковий шифр у потоковий. C_i = P_i ⊕ MSB_s(E(IV_{i-1})). Вразливості:
#
# Bit-flipping аналогічно CBC (але без padding).
# Поширення помилок: помилка в C_i впливає на наступні блоки.
# IV reuse → детермінованість.
# Скрипт: CFB bit-flipping

# у CFB зміна байта ciphertext впливає на відповідний байт plaintext
# (без псування попереднього блоку, на відміну від CBC)
def cfb_bitflip(ct: bytearray, pos: int, cur: int, target: int):
    ct[pos] ^= cur ^ target
    return ct