import re
import gmpy2
from Crypto.Util.number import long_to_bytes

# --------------------------------------------------
# Parse public_keys.txt
# --------------------------------------------------
with open("public_keys.txt", "r") as f:
    text = f.read()

n_list = [int(x) for x in re.findall(r"n\s*=\s*(\d+)", text)]
e_list = [int(x) for x in re.findall(r"e\s*=\s*(\d+)", text)]

# --------------------------------------------------
# Parse ciphertexts.txt
# --------------------------------------------------
with open("ciphertexts.txt", "r") as f:
    text = f.read()

c_list = [int(x) for x in re.findall(r"c\d+\s*=\s*(\d+)", text)]

print("[*] n count:", len(n_list))
print("[*] e count:", len(e_list))
print("[*] c count:", len(c_list))

assert len(n_list) == len(c_list) == 3
assert all(e == 3 for e in e_list)

n1, n2, n3 = n_list
c1, c2, c3 = c_list

# --------------------------------------------------
# CRT
# --------------------------------------------------
def crt(remainders, moduli):
    x = 0
    N = 1
    for n in moduli:
        N *= n

    for r, n in zip(remainders, moduli):
        Ni = N // n
        inv = pow(Ni, -1, n)
        x = (x + r * Ni * inv) % N

    return x, N

x, N = crt([c1, c2, c3], [n1, n2, n3])

print("[*] CRT result x =", x)
print("[*] N =", N)

# --------------------------------------------------
# Exact cube root
# --------------------------------------------------
m, exact = gmpy2.iroot(x, 3)
print("[*] exact cube root:", exact)

if not exact:
    print("[-] Not an exact cube. Maybe padding or not enough ciphertexts.")
else:
    flag = long_to_bytes(int(m))
    print("[+] FLAG:")
    print(flag.decode(errors="replace"))