import json
from math import isqrt
from Crypto.Util.number import long_to_bytes

with open("challenge.json", "r") as f:
    ch = json.load(f)

n = ch["n"]
e = ch["e"]
c = ch["c"]


def continued_fraction(a, b):
    cf = []
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a % b
    return cf


def convergents(cf):
    # h/k — підхожі дроби
    h0, h1 = 0, 1
    k0, k1 = 1, 0

    for q in cf:
        h = q * h1 + h0
        k = q * k1 + k0
        yield h, k
        h0, h1 = h1, h
        k0, k1 = k1, k


def wiener_attack(n, e):
    cf = continued_fraction(e, n)

    for k, d in convergents(cf):
        # d — кандидат на приватний показник
        if d == 0:
            continue

        # e*d - 1 має ділитися на k
        if k !=0:
            if (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k

            # p + q = n - phi + 1
            s = n - phi + 1

            # p, q — корені x^2 - s*x + n = 0
            disc = s * s - 4 * n
            if disc < 0:
                continue

            t = isqrt(disc)
            if t * t != disc:
                continue

            if (s + t) % 2 != 0:
                continue

            p = (s + t) // 2
            q = (s - t) // 2

            if p * q == n:
                return d, p, q

    return None


result = wiener_attack(n, e)

if result is None:
    print("[-] Wiener attack failed")
else:
    d, p, q = result
    print("[+] d =", d)
    print("[+] p =", p)
    print("[+] q =", q)

    m = pow(c, d, n)
    flag = long_to_bytes(m)
    print("[+] FLAG:")
    print(flag.decode(errors="replace"))