# Ключові факти
#
# Salsa20: nonce 64 біт, counter 64 біт. Nonce мусить бути унікальним для кожного повідомлення з тим самим ключем.
# ChaCha20 (IETF): nonce 96 біт, counter 32 біт. Ще чутливіший до повторного використання nonce через менший простір.
# Повторне використання nonce → ідентичний keystream → c1⊕c2 = p1⊕p2.
# Counter переповнення: якщо counter повторюється (наприклад, після 2³² блоків), keystream повторюється.
# Скрипт: ChaCha20 nonce reuse → keystream recovery

def chacha_nonce_reuse(known_pt, known_ct, secret_ct):
    ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))
    return bytes(c ^ k for c, k in zip(secret_ct, ks))

# Скрипт: Salsa20 nonce reuse без known plaintext (crib dragging)

def crib_drag(x: bytes, crib: bytes):
    """x = p1 ⊕ p2; crib — відомий фрагмент p1 або p2."""
    results = []
    for i in range(len(x) - len(crib) + 1):
        candidate = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        results.append((i, candidate))
    return results