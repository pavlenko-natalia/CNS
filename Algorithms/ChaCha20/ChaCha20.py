# Модифікація Salsa20 з кращою дифузією. Використовує 32-бітний counter і 96-бітний nonce (у стандартному IETF-варіанті). Quarter-round оновлює кожне слово двічі; QR застосовується до стовпців і діагоналей.
#
# Вразливості
#
# Nonce reuse — та сама проблема, що і в Salsa20: c1⊕c2 = p1⊕p2.
# Malleability (без MAC).
# Передбачуваність при поганому nonce/counter (наприклад, counter починається з 0 і nonce фіксований).
# Скрипти

# (a) ChaCha20 encryption/decryption

from Crypto.Cipher import ChaCha20

def chacha20_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(data)

# (b) Nonce reuse → keystream recovery

known_pt = b"..."       # відомий plaintext
known_ct = bytes.fromhex("...")
ks = bytes(p ^ c for p, c in zip(known_pt, known_ct))

secret_ct = bytes.fromhex("...")
print(bytes(c ^ k for c, k in zip(secret_ct, ks)))

# (c) Nonce reuse + crib dragging (без known plaintext)

c1 = bytes.fromhex("...")
c2 = bytes.fromhex("...")
x = bytes(a ^ b for a, b in zip(c1, c2))
# crib dragging: шукаємо "cns{", "the", "password" у x
# Коли що: аналогічно Salsa20.