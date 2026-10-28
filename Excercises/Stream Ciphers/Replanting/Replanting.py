# You have obtained two encrypted messages:
#
# A public server status message whose plaintext is known. A confidential message containing a secret flag.
#
# Both messages were encrypted using the same stream cipher configuration.

#get keystream

pt = b"STATUS: SERVER ONLINE"
ct = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f") #from public

#make oppostite from bytes( p ^ k for p, k in zip(plaintext, keystream) )
keystream = bytes(p ^ c for p, c in zip(pt, ct))
# print(keystream.hex())

secret = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")

answer = bytes(p ^ c for p, c in zip(secret, keystream)) #gives first 23 bytes (keystream is 23 bytes long because plain is 23 bytes long)

# print(answer)

"""
Fallback D: brute force over seed mod 2^24.
Pure Python, no dependencies.

Why 2^24 and not 2^31?
  The keystream byte is ((state >> 16) & 0xff).
  These are bits 16..23 of the state, which live entirely inside
  the low 24 bits. Since 2^31 mod 2^24 == 0, the low 24 bits of every
  state depend only on the low 24 bits of seed. So seeds that differ
  only in the top 7 bits produce an identical keystream.
  Effective key space = 2^24 = 16_777_216.
"""
import sys
import time

A    = 1103515245
C    = 12345
M    = 2 ** 31
MASK = M - 1


def load_known_keystream(plaintext: bytes, ciphertext_hex: str) -> bytes:
    """Recover the first len(plaintext) bytes of keystream via XOR."""
    ct = bytes.fromhex(ciphertext_hex)
    if len(plaintext) != len(ct):
        raise ValueError(
            f"length mismatch: plaintext={len(plaintext)} bytes, "
            f"ciphertext={len(ct)} bytes. "
            f"Did you forget a trailing newline?"
        )
    return bytes(p ^ c for p, c in zip(plaintext, ct))


def find_seed_low24(keystream: bytes) -> int:
    """
    Brute-force the low 24 bits of the seed.
    Returns the first seed_low24 that reproduces the entire known keystream.
    """
    total = 1 << 24                          # 16_777_216
    k0 = keystream[0]
    ks_rest = keystream[1:]

    t0 = time.time()
    for seed in range(total):
        # ---- step 1: match first keystream byte ----
        state = (A * seed + C) & MASK
        if ((state >> 16) & 0xff) != k0:
            continue                         # 255/256 seeds die here

        # ---- steps 2..N: match the rest ----
        ok = True
        for k in ks_rest:
            state = (A * state + C) & MASK
            if ((state >> 16) & 0xff) != k:
                ok = False
                break
        if ok:
            print(f"[i] brute force finished in {time.time() - t0:.2f}s")
            return seed

    return None


def generate_keystream(seed: int, length: int) -> bytes:
    """Exact copy of cipher.py's generate_keystream."""
    state = seed
    out = bytearray()
    for _ in range(length):
        state = (A * state + C) & MASK
        out.append((state >> 16) & 0xff)
    return bytes(out)


def main():
    # ---- 1. known plaintext/ciphertext pair from public.txt ----
    known_pt = b"STATUS: SERVER ONLINE"
    known_ct_hex = "22135cc0b9daa9e717f98a998e6ee5e92655e1a88f"

    keystream = load_known_keystream(known_pt, known_ct_hex)
    print(f"[i] known keystream ({len(keystream)} bytes): {keystream.hex()}")

    # ---- 2. brute-force the seed ----
    seed = find_seed_low24(keystream)
    if seed is None:
        print("[!] no seed found - check keystream or A/C/M")
        sys.exit(1)
    print(f"[+] seed mod 2^24 = {seed}  (0x{seed:06x})")

    # ---- 3. sanity check: regenerate keystream and compare ----
    check = generate_keystream(seed, len(keystream))
    assert check == keystream, "regenerated keystream != observed - BUG"
    print("[i] sanity check passed: regenerated keystream matches")

    # ---- 4. decrypt secret.txt ----
    secret_ct_hex = (
        "12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b0"
        "1d833d628a941b82fb65176b4ed3c3f64"
    )
    secret_ct = bytes.fromhex(secret_ct_hex)

    full_ks = generate_keystream(seed, len(secret_ct))
    secret_pt = bytes(c ^ k for c, k in zip(secret_ct, full_ks))

    print("\n=== Decrypted secret ===")
    print(secret_pt.decode(errors="replace"))


if __name__ == "__main__":
    main()