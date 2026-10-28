

# (a) Додавання (XOR)

def gf_add(a, b): return a ^ b

# (b) Множення (shift + умовний XOR з редукційним поліном)

def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1B        # x⁸ + x⁴ + x³ + x + 1 → 0x11B mod 0xFF = 0x1B
        b >>= 1
    return p

# приклад: 0x57 * 0x83 = 0xC1
print(hex(gf_mul(0x57, 0x83)))   # 0xc1

# (c) Extended Euclid для оберненого елемента

python
def gf_inv(a):
    if a == 0: raise ZeroDivisionError
    # розширений алгоритм Евкліда над GF(2)[x]
    r0, r1 = a, 0x11B
    x0, x1 = 1, 0
    while r1:
        q, r = poly_div(r0, r1)
        r0, r1 = r1, r
        x0, x1 = x1, x0 ^ gf_mul(q, x1)
    return x0 & 0xFF

def poly_div(a, b):
    """Ділення поліномів над GF(2) (байти як бітові поліноми)."""
    q = 0
    while a.bit_length() >= b.bit_length():
        shift = a.bit_length() - b.bit_length()
        q ^= 1 << shift
        a ^= b << shift
    return q, a

# приклад: 0x53^⁻¹ = 0xCA
print(hex(gf_inv(0x53)))   # 0xca

# (d) AES MixColumns для одного стовпця

def mix_column(col):
    """col — 4 байти."""
    def mul2(x): return gf_mul(x, 2)
    def mul3(x): return gf_mul(x, 3)
    s0, s1, s2, s3 = col
    return [
        mul2(s0) ^ mul3(s1) ^ s2 ^ s3,
        s0 ^ mul2(s1) ^ mul3(s2) ^ s3,
        s0 ^ s1 ^ mul2(s2) ^ mul3(s3),
        mul3(s0) ^ s1 ^ s2 ^ mul2(s3),
    ]

# (e) Генерація AES S-box (перевірка)

def sbox_generate():
    sbox = []
    for x in range(256):
        inv = gf_inv(x) if x else 0
        # affine transformation
        y = inv
        for shift in range(1, 5):
            y ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        y ^= 0x63
        sbox.append(y)
    return sbox
# sbox_generate()[0x53] == 0xED

# Коли що: вправа на дошці → (a)/(b). "Обчислити обернений" → (c). "Перевірити AES" → (d)/(e).