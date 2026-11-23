import json
from Crypto.Util.number import inverse, long_to_bytes

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

with open("challenge.json", "r") as f:
    ch = json.load(f)

n, e1, e2 = ch["n"], ch["e1"], ch["e2"]
c1, c2 = ch["c1"], ch["c2"]

g, a, b = egcd(e1, e2)
assert g == 1, "e1 and e2 must be coprime"

if a < 0:
    c1 = inverse(c1, n)
    a = -a
if b < 0:
    c2 = inverse(c2, n)
    b = -b

m = (pow(c1, a, n) * pow(c2, b, n)) % n
print(long_to_bytes(m).decode(errors="replace"))