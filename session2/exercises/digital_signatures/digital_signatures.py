import json
import hashlib
from Crypto.Util.number import inverse, long_to_bytes

with open("dsa1_challenge.json", "r") as f:
    ch = json.load(f)

p = ch["p"]
q = ch["q"]
g = ch["g"]
y = ch["y"]
sigs = ch["signatures"]

m1 = sigs[0]["message"]
r1 = sigs[0]["r"]
s1 = sigs[0]["s"]

m2 = sigs[1]["message"]
r2 = sigs[1]["r"]
s2 = sigs[1]["s"]

# Умова: однаковий nonce => однаковий r
assert r1 == r2, "r different — nonce reuse not applicable"

# H(m) = int(sha256(m)) mod q
def H(m: str, q: int) -> int:
    return int.from_bytes(hashlib.sha256(m.encode()).digest(), "big") % q

H1 = H(m1, q)
H2 = H(m2, q)

# k = (H1 - H2) / (s1 - s2) mod q
k = ((H1 - H2) * inverse(s1 - s2, q)) % q

# x = (s1*k - H1) / r mod q
x = ((s1 * k - H1) * inverse(r1, q)) % q

print("[+] k =", k)
print("[+] x =", x)

# Перевірка, що x правильний
assert pow(g, x, p) == y, "x verification failed"
print("[+] x verified: g^x mod p == y")

# ---- дешифрування флага ----
ct = bytes.fromhex(ch["encrypted_flag"])

keystream = b""
i = 0
while len(keystream) < len(ct):
    block = hashlib.sha256(f"{x}:{i}".encode()).digest()
    keystream += block
    i += 1

pt = bytes(a ^ b for a, b in zip(ct, keystream))

print("[+] FLAG:")
print(pt.decode(errors="replace"))