# The Belgians have also joined.
# Decrypt their message:
# qnb{vsi-fihczlnb-dlyi-vsi-fibv-plaahib-fi-zv-l-hzici-plaahi-mr-l-frtbbihb-plaahi}
#
# Hint: They used the English language to solve the language border. The attached wordlist may be of use.
#!/usr/bin/env python3

import re
import sys
import time
from collections import defaultdict

try:
    from wordfreq import zipf_frequency
    def word_score(w):
        return zipf_frequency(w.lower(), "en")
    SCORE_SRC = "wordfreq"
except ImportError:
    print("[!] wordfreq missing → fallback list (pip install wordfreq)")
    COMMON = set("""
    the be to of and a in that have it for not on with he as you do at
    this but his by from they we say her she or an will my one all would
    there their what so up out if about who get which go me when make can
    like time no just him know take people into year your good some could
    them see other than then now look only come its over think also back
    after use two how our work first well way even new want because any
    these give day most us waffle waffles brussels belgians belgian liege
    best make fake
    """.split())
    def word_score(w):
        if w in COMMON: return 7.0
        if len(w) <= 2: return 4.0
        return 2.0
    SCORE_SRC = "builtin"


# ---------------- helpers ----------------
def word_pattern(word):
    seen, out = {}, []
    for ch in word.lower():
        if ch not in seen:
            seen[ch] = len(seen)
        out.append(str(seen[ch]))
    return "".join(out)


def build_pattern_index(wordlist):
    idx = defaultdict(list)
    for w in wordlist:
        idx[word_pattern(w)].append(w)
    return idx


def is_consistent(cw, pw, cmap, pmap):
    """
    Bijective check:
      • cipher letter may decode to only one plaintext letter
      • plaintext letter may be produced by only one cipher letter
    """
    for c, p in zip(cw, pw):
        if cmap.get(c, p) != p: return False
        if pmap.get(p, c) != c: return False
    return True


def commit(cw, pw, cmap, pmap):
    changed = False
    for c, p in zip(cw, pw):
        if cmap.get(c) != p: cmap[c] = p; changed = True
        if pmap.get(p) != c: pmap[p] = c; changed = True
    return changed


def propagate(cmap, pmap, words_cands):
    words_cands = [[w, list(c)] for w, c in words_cands]
    changed = True
    while changed:
        changed = False
        for wc in words_cands:
            w, c = wc
            c = [x for x in c if is_consistent(w, x, cmap, pmap)]
            wc[1] = c
            if not c:
                return None
            if len(c) == 1:
                if commit(w, c[0], cmap, pmap):
                    changed = True
    return cmap, pmap, words_cands


def assemble(ct, cmap):
    return "".join(cmap.get(ch, "?") if ch.isalpha() else ch
                   for ch in ct.lower())


def text_score(plain):
    words = re.findall(r"[a-z]+", plain)
    if not words: return 0.0
    return sum(word_score(w) for w in words) / len(words)


# ---------------- main cracker ----------------
def crack(ct, wordlist, known_prefix="cns",
          max_solutions=500, time_limit=60):
    cmap, pmap = {}, {}

    if known_prefix and "{" in ct:
        prefix = ct.split("{", 1)[0].lower()
        if len(prefix) == len(known_prefix):
            for c, p in zip(prefix, known_prefix):
                cmap[c], pmap[p] = p, c
            print(f"[seed] '{prefix}' -> '{known_prefix}'")

    content = ct.split("{", 1)[1].rsplit("}", 1)[0] if "{" in ct else ct
    cipher_words = re.findall(r"[a-z]+", content.lower())

    idx = build_pattern_index(wordlist)
    print(f"\n[i] wordlist: {len(wordlist)}   scoring: {SCORE_SRC}")
    print(f"[i] {len(cipher_words)} cipher words\n")
    print(f"{'cipher':<12} {'pattern':<12} {'#cands':>6}   top-5 by freq")
    print("-" * 82)

    words_cands = []
    for w in cipher_words:
        cands = [c for c in idx.get(word_pattern(w), [])
                 if is_consistent(w, c, cmap, pmap)]
        cands.sort(key=word_score, reverse=True)
        words_cands.append([w, cands])
        print(f"{w:<12} {word_pattern(w):<12} {len(cands):>6}   {cands[:5]}")

    if any(not c for _, c in words_cands):
        print("\n[!] wordlist miss for some word — aborting")
        return []

    solutions = []
    start = time.time()

    def dfs(cmap, pmap, wc):
        if len(solutions) >= max_solutions: return
        if time.time() - start > time_limit: return

        res = propagate(cmap, pmap, wc)
        if res is None: return
        cmap, pmap, wc = res

        unresolved = [(i, w) for i, w in enumerate(wc) if len(w[1]) > 1]
        if not unresolved:
            plain = assemble(ct, cmap)
            solutions.append((text_score(plain), plain, dict(cmap)))
            return

        # most-constrained-first, candidates already sorted by frequency
        i, (w, cands) = min(unresolved, key=lambda x: len(x[1][1]))
        for cand in cands:
            cmap2, pmap2 = dict(cmap), dict(pmap)
            commit(w, cand, cmap2, pmap2)
            wc2 = [[ww, [cand] if j == i else list(cc)]
                   for j, (ww, cc) in enumerate(wc)]
            dfs(cmap2, pmap2, wc2)
            if len(solutions) >= max_solutions: return

    print(f"\n[~] searching (bijective, freq-ordered)...")
    dfs(dict(cmap), dict(pmap), words_cands)
    solutions.sort(key=lambda x: x[0], reverse=True)
    return solutions


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wordlist.txt>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
        wordlist = sorted({w.strip().lower() for w in f if w.strip().isalpha()})
    print(f"[i] loaded {len(wordlist)} words")

    ct = ("qnb{vsi-fihczlnb-dlyi-vsi-fibv-plaahib-fi-zv-l-hzici-"
          "plaahi-mr-l-frtbbihb-plaahi}")

    sols = crack(ct, wordlist, known_prefix="cns",
                 max_solutions=500, time_limit=60)

    if not sols:
        print("\n[!] no solution"); sys.exit(2)

    print(f"\n=== Top {min(5, len(sols))} of {len(sols)} bijective solutions ===")
    for i, (score, plain, _) in enumerate(sols[:5], 1):
        print(f"[{i}] score={score:.2f}  {plain}")

    print("\n=== BEST ===")
    print(sols[0][1])