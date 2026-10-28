# Опис
#
# c = p ⊕ k, де k періодично повторюється (XOR-Vigenère). У завданні Dutch Exclusivity — це XOR з hex-ключем, після чого результат — hex-ASCII, який треба hex-decode.
#
# Вразливості
#
# Періодичний ключ → Hamming distance + IC знаходять довжину; кожен «стовпець» — Caesar над бітами.
# Відомий plaintext / crib (cns{, the, http) → XOR crib'а з ciphertext одразу дає фрагменти ключа.
# Key reuse між повідомленнями → c1⊕c2 = p1⊕p2.
# Наївний XOR без MAC → malleability: c ⊕ t → p ⊕ t.
#
# (a) Знаємо ключ (Dutch Exclusivity)

key_hex = "636f6d7075746572656e6e65747765726b7365637572697479697374686562657374636f75727365"
ct_hex  = ("555c4d461054524145590c45434045445353525a55400d544f515342594555535342564f47"
           "165353514f5b455542065253594e534d5753434b450043471649434e494545485354454542"
           "43591652455043585e5047104545524e585d544150525d16455111525e4d595f15545f5042"
           "571754555c55444245550a4d421154534a45585f45434145445e53570755455a544e5d5343"
           "5a4554035342054f42425352544f5b4155425352535b4e53175752414b4401")

key = bytes.fromhex(key_hex)
ct  = bytes.fromhex(ct_hex)
x   = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(x)                            # hex-ASCII з пробілами
print(bytes.fromhex(x.decode().replace(" ", "")).decode())   # фінальний plaintext

# (b) Невідомий ключ — знайти довжину + розшифрувати

def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def xor_bytes(data, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

# 1) оцінка довжини ключа через усереднений Hamming distance
def guess_keylen(ct, maxlen=40):
    scores = []
    for klen in range(2, maxlen+1):
        blocks = [ct[i:i+klen] for i in range(0, klen*8, klen)][:8]
        ds = [hamming(blocks[i], blocks[i+1])/klen for i in range(len(blocks)-1)]
        scores.append((sum(ds)/len(ds), klen))
    return sorted(scores)[:5]

# 2) для кожного "стовпця" — Caesar over bytes
def score_english(bs):
    freq = {' ':12.7,'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'h':6.1,'r':6.0}
    return sum(freq.get(chr(b).lower(), 0) for b in bs)

def crack_single_byte(col):
    return max(range(256), key=lambda k: score_english(bytes(b^k for b in col)))

# використання
for _, klen in guess_keylen(ct)[:3]:
    key = bytes(crack_single_byte(ct[i::klen]) for i in range(klen))
    print(klen, key, xor_bytes(ct, key)[:80])

# (c) Відомий crib (cns{ на початку)

ct = bytes.fromhex("...")
crib = b"cns{"
key_start = bytes(c ^ p for c, p in zip(ct, crib))
print("перші байти ключа:", key_start.hex())

# тепер перевіряємо на повторюваність / Kasiski
# Коли що: відомий ключ → (a). Стандартне завдання → (b). Формат cns{ — (c), потім (b) для довжини.