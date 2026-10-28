# Опис: keystream генерується повторним шифруванням IV. Вразливості:
#
# Malleability (як у потокового шифру).
# IV reuse → однаковий keystream.
# Bit-flipping без поширення помилок (на відміну від CFB).
# Скрипт: OFB malleability

def ofb_xor_attack(ct: bytes, original: bytes, target: bytes) -> bytes:
    delta = bytes(a ^ b for a, b in zip(original, target))
    return bytes(c ^ d for c, d in zip(ct, delta))