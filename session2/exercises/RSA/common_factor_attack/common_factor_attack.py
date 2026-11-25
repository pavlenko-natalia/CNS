import json
import re
from math import gcd
from Crypto.Util.number import inverse, long_to_bytes

# --------------------------------------------------
# Load keys & ciphertexts
# --------------------------------------------------
with open("public_keys.txt") as f:
    text = f.read()

n_list = [int(x) for x in re.findall(r"n\s*=\s*(\d+)", text)]
e_list = [int(x) for x in re.findall(r"e\s*=\s*(\d+)", text)]

with open("ciphertexts.txt") as f:
    text = f.read()

c_list = [int(x) for x in re.findall(r"c\d+\s*=\s*(\d+)", text)]

# --------------------------------------------------
# Find shared factors
# --------------------------------------------------
def find_shared_primes(n_list):
    """Повертає dict: index -> (p, q, d) для всіх зламаних ключів."""
    results = {}

    for i in range(len(n_list)):
        for j in range(i + 1, len(n_list)):
            p = gcd(n_list[i], n_list[j])
            if p != 1:
                # Знайшли спільний множник
                q_i = n_list[i] // p
                q_j = n_list[j] // p
                results[i] = (p, q_i)
                results[j] = (p, q_j)

    return results

broken = find_shared_primes(n_list)

print("[*] Broken keys:", list(broken.keys()))

# --------------------------------------------------
# Recover d for each broken key and decrypt
# --------------------------------------------------
for idx, (p, q) in broken.items():
    n = n_list[idx]
    e = e_list[idx]
    c = c_list[idx]

    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)

    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print(f"\n[+] Key {idx+1}:")
    print(f"    p = {p}")
    print(f"    q = {q}")
    print(f"    d = {d}")
    print(f"    FLAG = {flag.decode(errors='replace')}")