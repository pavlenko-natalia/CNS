import json
import math
import random
from math import gcd, isqrt
from Crypto.Util.number import inverse, long_to_bytes

# --------------------------------------------------
# Load challenge
# --------------------------------------------------
with open("challenge.json", "r") as f:
    challenge = json.load(f)

n = challenge["n"]
e = challenge["e"]
ciphertext = challenge["ciphertext"]
block_size = challenge["block_size"]
original_length = challenge["original_length"]

# --------------------------------------------------
# 1. Factorization helpers
# --------------------------------------------------

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p

    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    while True:
        c = random.randrange(1, n - 1)
        x = random.randrange(2, n - 1)
        y = x
        d = 1

        def f(v):
            return (v * v + c) % n

        while d == 1:
            x = f(x)
            y = f(f(y))
            d = gcd(abs(x - y), n)

        if d != n:
            return d


def factor_recursive(n: int):
    if n == 1:
        return []
    if is_prime(n):
        return [n]

    d = pollard_rho(n)
    return factor_recursive(d) + factor_recursive(n // d)


# --------------------------------------------------
# 2. Factor n
# --------------------------------------------------
random.seed(0)  # для відтворюваності

factors = factor_recursive(n)
factors.sort()
print("[*] Factors:", factors)

p, q = factors[0], factors[1]
assert p * q == n, "Factorization failed"

print(f"[*] p = {p}")
print(f"[*] q = {q}")

# --------------------------------------------------
# 3. Compute private exponent d
# --------------------------------------------------
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

print(f"[*] phi = {phi}")
print(f"[*] d = {d}")

# --------------------------------------------------
# 4. Decrypt
# --------------------------------------------------
plaintext = bytearray()

for c in ciphertext:
    m = pow(c, d, n)
    block = m.to_bytes(block_size, byteorder="big")
    plaintext.extend(block)

plaintext = plaintext[:original_length]

print("\n[+] Decrypted bytes:")
print(bytes(plaintext))

try:
    print("\n[+] Decrypted message:")
    print(plaintext.decode("utf-8"))
except UnicodeDecodeError:
    print("[-] UTF-8 decode failed")