import requests
import json
import random

BASE = "http://cns-test.idlab.uantwerpen.be:50011"
MY_NAME = "Bob"          # naam waaronder we onze sleutel registreren
                          # -> pas aan als "Bob" al bestaat en niet overschreven mag/kan worden

def get_params():
    r = requests.get(f"{BASE}/params")
    r.raise_for_status()
    data = r.json()
    print("[params]", data)
    p = int(data["p"])
    g = int(data["g"])
    return p, g

def gen_keypair(p, g):
    # privé-sleutel x, publieke sleutel y = g^x mod p
    x = random.randrange(2, p - 2)
    y = pow(g, x, p)
    return x, y
def register(name, y):
    payload = {"name": name, "y": str(y)}
    r = requests.post(f"{BASE}/directory", json=payload)
    print("[register]", r.status_code, r.text)
    return r
def list_directory():
    r = requests.get(f"{BASE}/directory")
    print("[directory]", r.json())
    return r.json()

def get_send(to):
    r = requests.get(f"{BASE}/send", params={"to": to})
    r.raise_for_status()
    data = r.json()
    print("[send]", data)
    return data

def elgamal_decrypt(c1, c2, x, p):
    s = pow(c1, x, p)          # shared secret = c1^x mod p
    s_inv = pow(s, -1, p)      # modulaire inverse (Python 3.8+)
    m = (c2 * s_inv) % p
    return m

#long_to_bytes
def int_to_bytes(m):
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")

def main():
    p, g = get_params()

    x, y = gen_keypair(p, g)
    print(f"[keypair] x={x}")
    print(f"[keypair] y={y}")

    register(MY_NAME, y)
    list_directory()

    data = get_send(MY_NAME)

    # LET OP: pas deze veldnamen aan op basis van wat /send echt teruggeeft
    # vaak iets als {"c1": ..., "c2": ...}
    c1 = int(data["c1"])
    c2 = int(data["c2"])

    m = elgamal_decrypt(c1, c2, x, p)
    secret = int_to_bytes(m)

    print("\n[+] Decrypted int:", m)
    print("[+] Decrypted bytes:", secret)
    try:
        print("[+] As text:", secret.decode())
    except UnicodeDecodeError:
        print("[+] (geen geldige UTF-8 tekst, laat als bytes staan)")

if __name__ == "__main__":
    main()