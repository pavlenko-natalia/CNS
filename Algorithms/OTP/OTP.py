# Опис
#
# c = p ⊕ k, де |k| = |p|, k — істинно випадковий, використовується один раз. Єдиний безумовно стійкий шифр (Shannon).
#
# Вразливості
#
# Key reuse (двократне використання) → c1⊕c2 = p1⊕p2 — основна атака.
# Crib dragging: якщо знаємо частину p1 — отримуємо відповідну частину p2.
# Malleability: XOR-модифікація ciphertext.
# Практично OTP майже ніколи не реалізують коректно; зазвичай це stream cipher з поганим PRG.

# (a) Двократне використання ключа з crib

c1 = bytes.fromhex("...")   # ciphertext 1
c2 = bytes.fromhex("...")   # ciphertext 2, ТОЙ САМИЙ ключ
crib = b"cns{"              # відомий початок p1

# c1 ^ c2 = p1 ^ p2 → знаючи crib, отримуємо p2
p2_prefix = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, crib))
print(p2_prefix)            # це початок p2
# далі — crib dragging: ковзаємо crib по p1^p2, шукаємо читабельні фрагменти

# (b) Підбір слова-ключа (якщо OTP реалізовано як звичайний XOR з ключем фіксованої довжини)

# не справжній OTP, але зустрічається на практиці: ключ-слово
ct = bytes.fromhex("...")
for word in open("wordlist.txt"):
    k = word.strip().encode()
    if not k: continue
    pt = bytes(c ^ k[i % len(k)] for i, c in enumerate(ct))
    if b"cns{" in pt:
        print(k, pt); break

# (c) Malleability / bit-flipping

# міняємо конкретні байти plaintext, знаючи структуру
original = b"amount=10"
target   = b"amount=99"
c = bytearray(ct)
delta = bytes(a ^ b for a, b in zip(original, target))
for i, d in enumerate(delta):
    c[i] ^= d
    
# Коли що: key reuse → (a). «OTP» через wordlist → (b). Потрібно щось змінити в plaintext → (c).