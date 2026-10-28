# Description
#
# c = p ⊕ k, where k repeats periodically (XOR-Vigenère). In the Dutch Exclusivity problem, this is an XOR operation with a hex key,
# after which the result is hex-ASCII, which must be hex-decoded.
#
# Vulnerabilities
#
# Periodic key → Hamming distance + IC are used to determine the length; each ‘column’ is a Caesar shift over the bits.
# Known plaintext / crib (cns{, the, http) → XORing the crib with the ciphertext immediately yields fragments of the key.
# Key reuse between messages → c1⊕c2 = p1⊕p2.
# Naive XOR without MAC → malleability: c ⊕ t → p ⊕ t.
#------------------------------------------------------
# c = p ⊕ k, де k періодично повторюється (XOR-Vigenère). У завданні Dutch Exclusivity — це XOR з hex-ключем,
# після чого результат — hex-ASCII, який треба hex-decode.
#
# Вразливості
#
# Періодичний ключ → Hamming distance + IC знаходять довжину; кожен «стовпець» — Caesar над бітами.
# Відомий plaintext / crib (cns{, the, http) → XOR crib'а з ciphertext одразу дає фрагменти ключа.
# Key reuse між повідомленнями → c1⊕c2 = p1⊕p2.
# Наївний XOR без MAC → malleability: c ⊕ t → p ⊕ t.
#------------------------------------------------------

#XOR on python
5 ^ 3        # 101 ^ 011 = 110 = 6
b"AB" ^ b"\x01\x02"   # TypeError! bytes ^ bytes doesnt work dirrectly
bytes(a ^ b for a, b in zip(b"AB", b"\x01\x02"))   # b"@C"

#XOR properties

#involution A ⊕ A = 0
#neutral element A ⊕ 0 = A
#comutativity A ⊕ B = B ⊕ A
#associativity (A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)
#inverse (A ⊕ K) ⊕ K = A
# distribution A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C

# => if c1 = p1 ⊕ k and c2 = p2 ⊕ k then c1 ⊕ c2 = (p1 ⊕ k) ⊕ (p2 ⊕ k) = p1 ⊕ p2

# (a) We know the key (Dutch Exclusivity)

key_hex = "636f6d7075746572656e6e65747765726b7365637572697479697374686562657374636f75727365"
ct_hex  = ("555c4d461054524145590c45434045445353525a55400d544f515342594555535342564f47"
           "165353514f5b455542065253594e534d5753434b450043471649434e494545485354454542"
           "43591652455043585e5047104545524e585d544150525d16455111525e4d595f15545f5042"
           "571754555c55444245550a4d421154534a45585f45434145445e53570755455a544e5d5343"
           "5a4554035342054f42425352544f5b4155425352535b4e53175752414b4401")

key = bytes.fromhex(key_hex)
ct  = bytes.fromhex(ct_hex)
x   = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(x)                            # hex-ASCII with spaces
print(bytes.fromhex(x.decode().replace(" ", "")).decode())   # finale plaintext

# (b) Repeating-key XOR (XOR-Vigenère), key is unknown

# 1) estimat the key length using the average Hamming distance
def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

def guess_keylen(ct: bytes, maxlen: int = 40):
    scores = []
    for klen in range(2, maxlen + 1):
        blocks = [ct[i:i+klen] for i in range(0, min(len(ct), klen * 8), klen)]
        ds = [hamming(blocks[i], blocks[i+1]) / klen for i in range(len(blocks) - 1)]
        scores.append((sum(ds)/len(ds), klen))
    return sorted(scores)[:5]

# 2) for each column — Caesar over bytes
def crack_repeating_xor(ct: bytes, klen: int) -> bytes:
    key = bytes(crack_single_byte(ct[i::klen])[0] for i in range(klen))
    return key

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))

# brute-force search for candidates of length + scoring of the complete plaintext
for _, klen in guess_keylen(ct)[:3]:
    key = crack_repeating_xor(ct, klen)
    pt = xor_bytes(ct, key)
    print(klen, key, pt[:100])

# (c) known crib (cns{ ...)

ct = bytes.fromhex("...")
crib = b"cns{"
key_start = bytes(c ^ p for c, p in zip(ct, crib))
print("first bytes of the key", key_start.hex())
# know check for the repeatability / Kasiski

# (d) single-byte XOR (known, that key — 1 byte) => Brute force всіх 256 + scoring by language

def score_english(bs):
    freq = {' ':12.7,'e':12.7,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,
            's':6.3,'h':6.1,'r':6.0,'d':4.3,'l':4.0,'u':2.8}
    return sum(freq.get(chr(b).lower(), 0) for b in bs)

def crack_single_byte(ct: bytes):
    best = max(range(256), key=lambda k: score_english(bytes(b ^ k for b in ct)))
    return best, bytes(b ^ best for b in ct)

# example
ct = bytes.fromhex("...")
k, pt = crack_single_byte(ct)
print(f"key={k:02x}  pt={pt!r}")

# (e) key reuse without known plaintext → crib dragging
# given: x = c1 ⊕ c2 = p1 ⊕ p2. Known, that p1 tonatins cns{ (or the, http, password).

def crib_drag(x: bytes, crib: bytes):
    for i in range(len(x) - len(crib) + 1):
        guess = bytes(a ^ b for a, b in zip(x[i:i+len(crib)], crib))
        if guess.isascii() and all(32 <= c < 127 or c in b"\r\n\t" for c in guess):
            print(f"pos {i}: if p1[{i}:{i+len(crib)}]=={crib!r}, то p2={guess!r}")
