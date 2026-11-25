# Опис: C_i = P_i ⊕ E(counter_i). Counter унікальний для кожного блоку. Вразливості:
#
# Nonce/counter reuse → keystream reuse → c1⊕c2 = p1⊕p2.
# Malleability.
# Відсутність цілісності (якщо немає MAC).
# Скрипт: CTR nonce reuse

def ctr_nonce_reuse(c1: bytes, c2: bytes, known_pt: bytes = None):
    if known_pt:
        ks = bytes(p ^ c for p, c in zip(known_pt, c1))
        return bytes(c ^ k for c, k in zip(c2, ks))
    return bytes(a ^ b for a, b in zip(c1, c2))   # p1 ⊕ p2