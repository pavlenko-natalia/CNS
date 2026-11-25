# If AES is so good, why isn't there an AES 2?
#
# The demo version only uses 20-bit keys, but 2x20=40 which should be unhackable!
#
# Here is a promo-code to purchase the full version, if you can crack it:
# df7c7dfbd5e1ba2af108d658132d5f20d34de27da16375ceabd7a79cbfe738244027a4a0b26ec498a2c223a545b9567c20bf423bb38514e6cd6f043ab9e23a84ffa6745294c224068e1cffd9e8c9e294
#
# (Key format:
#
# k1_small = secrets.randbelow(2**20)
# k2_small = secrets.randbelow(2**20)
#
# K1 = k1_small.to_bytes(3, "big") + b"\x00"*13
# K2 = k2_small.to_bytes(3, "big") + b"\x00"*13

from Crypto.Cipher import AES
from collections import Counter
import struct

def make_key(k):
    return k.to_bytes(3, "big") + b"\x00"*13
with open("enc.bmp.hex") as f:
    raw = bytes.fromhex(f.read().replace(" ", "").replace("\n", ""))

def is_solid_bgra(P):
    return len(P) == 16 and P[0:4] == P[4:8] == P[8:12] == P[12:16]

file_size = struct.unpack_from("<I", raw, 2)[0]
print(f"raw={len(raw)}  header_size={file_size}  extra={len(raw)-file_size}")

# Знайти найчастіший блок при offset=138
data = raw[138:138+9216]
blocks = [data[i:i+16] for i in range(0, len(data), 16)]
C_block = bytes.fromhex("d444f9cbff851c7fa12cf323e0cce4cf")

print(f"C_block = {C_block.hex()}")

found_K1 = None
for start in [54, 138, 134, 142]:
    data = raw[start:]
    blocks = [data[i:i+16] for i in range(0, len(data) - 15, 16)]
    if not blocks:
        continue
    C_block, count = Counter(blocks).most_common(1)[0]
    print(f"\nstart={start}, top={C_block.hex()} ({count}x)")

    for k in range(2**20):
        P = AES.new(make_key(k), AES.MODE_ECB).decrypt(C_block)
        if is_solid_bgra(P):
            print(f"  *** K1 = {k}  BGRA={P[:4].hex()}")
            exit(0)
    print("  ✗ not found")

if found_K1 is not None:
    K1 = make_key(found_K1)
    promo = bytes.fromhex(
        "df7c7dfbd5e1ba2af108d658132d5f20"
        "d34de27da16375ceabd7a79cbfe73824"
        "4027a4a0b26ec498a2c223a545b9567c"
        "20bf423bb38514e6cd6f043ab9e23a84"
        "ffa6745294c224068e1cffd9e8c9e294"
    )

    # Спроба 1: promo — теж single AES з K1
    plain = AES.new(K1, AES.MODE_ECB).decrypt(promo)
    print(f"single AES: {plain!r}")
    if b"cns{" in plain:
        print("FLAG FOUND (single).")
        exit(0)

    # Спроба 2: double AES, перебір K2
    promo_block = promo[:16]
    print("\n=== brute force K2 for promo ===")
    for order in ["E1E2", "E2E1"]:
        for k2 in range(2**20):
            K2 = make_key(k2)
            if order == "E1E2":  # C = E_K2(E_K1(P))
                mid  = AES.new(K2, AES.MODE_ECB).decrypt(promo_block)
                cand = AES.new(K1, AES.MODE_ECB).decrypt(mid)
            else:                # C = E_K1(E_K2(P))
                mid  = AES.new(K1, AES.MODE_ECB).decrypt(promo_block)
                cand = AES.new(K2, AES.MODE_ECB).decrypt(mid)
            if cand.startswith(b"cns{"):
                print(f"\n*** K2 = {k2}, order = {order}")
                if order == "E1E2":
                    mid  = AES.new(K2, AES.MODE_ECB).decrypt(promo)
                    full = AES.new(K1, AES.MODE_ECB).decrypt(mid)
                else:
                    mid  = AES.new(K1, AES.MODE_ECB).decrypt(promo)
                    full = AES.new(K2, AES.MODE_ECB).decrypt(mid)
                print(f"FLAG: {full}")
                exit(0)
            if k2 % 100000 == 0:
                print(f"  {order} {k2}...", end="\r", flush=True)

    print("\n❌ K2 не знайдено.")