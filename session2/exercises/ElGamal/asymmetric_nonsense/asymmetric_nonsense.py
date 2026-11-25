import json
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

with open("challenge.json", "r") as f:
    ch = json.load(f)

p = ch["p"]
g = ch["g"]
y = ch["y"]

known_plaintext = ch["known_plaintext"].encode()
c1_known, c2_known = ch["cipher_known"]
c1_flag, c2_flag = ch["cipher_flag"]

# Перевірка: nonce справді повторно використаний
assert c1_known == c1_flag, "c1 different -> nonce reuse not applicable"

m_known = bytes_to_long(known_plaintext)

# m_flag = m_known * c2_flag * inverse(c2_known, p) mod p
m_flag = (m_known * c2_flag * inverse(c2_known, p)) % p

flag_bytes = long_to_bytes(m_flag)
print(flag_bytes.decode(errors="replace"))