"""
Monoalphabetic substitution cipher cracker.
Hill climbing with n-gram (default: quadgram) log-probability scoring.

Usage:
    python subst_crack.py "cipher text here"
    python subst_crack.py --file cipher.txt --format cns --restarts 20

Requirements:
    english_quadgrams.txt in the same directory (or --quadgrams PATH).
"""

import argparse
import math
import random
import string
import sys
from collections import Counter
from pathlib import Path

ALPHABET = string.ascii_lowercase
N = 4  # quadgram


# ---------- N-gram loading / generation ----------

def load_ngrams(path, n=N):
    """Load pre-computed n-grams: lines 'gram count'. Convert to log10 probs."""
    counts = {}
    total = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            gram = parts[0].lower()
            if len(gram) != n:
                continue
            try:
                c = int(parts[1])
            except ValueError:
                continue
            counts[gram] = c
            total += c
    if total == 0:
        raise ValueError(f"No {n}-grams loaded from {path}")

    log_probs = {g: math.log10(c / total) for g, c in counts.items()}
    # Penalty for unseen grams; very low but finite
    floor_log = math.log10(0.01 / total)
    return log_probs, floor_log


def generate_ngrams_from_text(text_path, out_path, n=N):
    """Build n-gram count file from any English text (e.g. Gutenberg)."""
    with open(text_path, encoding="utf-8", errors="ignore") as f:
        text = f.read()
    text = "".join(c.lower() for c in text if c.isalpha())
    counts = Counter()
    for i in range(len(text) - n + 1):
        counts[text[i:i + n]] += 1
    total = sum(counts.values())
    with open(out_path, "w", encoding="utf-8") as f:
        for gram, c in counts.most_common():
            f.write(f"{gram} {c}\n")
    print(f"Wrote {len(counts)} {n}-grams to {out_path} (total={total})")


# ---------- Scoring ----------

def score(text, log_probs, floor_log, n=N):
    """Sum log-prob of every n-gram (non-letters stripped)."""
    letters = "".join(c for c in text.lower() if c in ALPHABET)
    total = 0.0
    for i in range(len(letters) - n + 1):
        gram = letters[i:i + n]
        total += log_probs.get(gram, floor_log)
    return total


# ---------- Decryption ----------

def decrypt(cipher_text, mapping):
    """Apply cipher->plain mapping, leaving non-letters untouched."""
    return "".join(
        mapping.get(c, c) if c in ALPHABET else c
        for c in cipher_text.lower()
    )


# ---------- Fixed mapping from known format ----------

def fixed_from_format(cipher_text, expected="cns"):
    """
    Extract forced cipher->plain pairs from '{' prefix.
    E.g. ciphertext 'qnb{...}', expected 'cns' -> {'q':'c','n':'n','b':'s'}.
    """
    if "{" not in cipher_text:
        return {}
    prefix = cipher_text.split("{", 1)[0].lower()
    if len(prefix) != len(expected):
        return {}
    return dict(zip(prefix, expected))


# ---------- Hill climbing ----------

def crack_substitution(cipher_text, log_probs, floor_log,
                       fixed_mapping=None, restarts=15, iters=5000,
                       verbose=True):
    """
    Hill-climb cipher->plain mapping. Only swaps cipher letters that
    aren't in fixed_mapping; the plain letters they map to are equally
    restricted so known format stays correct.
    """
    fixed_mapping = dict(fixed_mapping or {})
    fixed_cipher = set(fixed_mapping)
    used_plain = set(fixed_mapping.values())

    free_cipher = [c for c in ALPHABET if c not in fixed_cipher]
    free_plain = [p for p in ALPHABET if p not in used_plain]

    best_plain, best_score = None, -1e18

    for r in range(restarts):
        perm = free_plain[:]
        random.shuffle(perm)
        mapping = dict(fixed_mapping)
        for c, p in zip(free_cipher, perm):
            mapping[c] = p

        current_plain = decrypt(cipher_text, mapping)
        current_score = score(current_plain, log_probs, floor_log)

        for _ in range(iters):
            if len(free_cipher) < 2:
                break
            a, b = random.sample(free_cipher, 2)
            mapping[a], mapping[b] = mapping[b], mapping[a]
            new_plain = decrypt(cipher_text, mapping)
            new_score = score(new_plain, log_probs, floor_log)

            if new_score > current_score:
                current_plain, current_score = new_plain, new_score
            else:
                mapping[a], mapping[b] = mapping[b], mapping[a]

        if current_score > best_score:
            best_score = current_score
            best_plain = current_plain
            if verbose:
                print(f"[restart {r+1}/{restarts}] new best = {best_score:.2f}")

    return best_plain, best_score


# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cipher_text", nargs="?", help="ciphertext string")
    ap.add_argument("--file", help="read ciphertext from file instead")
    ap.add_argument("--quadgrams", default="english_quadgrams.txt")
    ap.add_argument("--format", default="cns",
                    help="expected plaintext prefix, e.g. 'cns'")
    ap.add_argument("--restarts", type=int, default=15)
    ap.add_argument("--iters", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--generate-from", metavar="TEXT",
                    help="generate quadgrams from TEXT corpus, then exit")
    args = ap.parse_args()

    if args.generate_from:
        generate_ngrams_from_text(args.generate_from, args.quadgrams)
        return

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            ct = f.read().strip()
    elif args.cipher_text:
        ct = args.cipher_text
    else:
        ap.error("Provide ciphertext or --file")

    if not Path(args.quadgrams).exists():
        print(f"ERROR: {args.quadgrams} not found.")
        print("Download from practicalcryptography.com, or generate with:")
        print(f"  python {sys.argv[0]} --generate-from book.txt")
        sys.exit(1)

    random.seed(args.seed)

    log_probs, floor_log = load_ngrams(args.quadgrams, N)
    print(f"Loaded {len(log_probs)} quadgrams.")

    fixed = fixed_from_format(ct, expected=args.format)
    if fixed:
        print(f"Forced from format '{args.format}': {fixed}")

    plain, sc = crack_substitution(
        ct, log_probs, floor_log,
        fixed_mapping=fixed,
        restarts=args.restarts,
        iters=args.iters,
    )

    print(f"\nBest score: {sc:.2f}")
    print(f"Plaintext: {plain}")

    if plain.startswith(args.format + "{"):
        print("✓ Format check passed.")
    else:
        print(f"✗ Expected prefix '{args.format}{{' — try more --restarts / --iters.")


if __name__ == "__main__":
    main()