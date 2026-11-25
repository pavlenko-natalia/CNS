# The French pattisiers are in a bake-off with the Italian pizza restaurants.
# Can you decrypt their communication?
# eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}
#
# They key is France's favorite moon-shaped breakfast item!

#IF key is known
key = "croissant"
cipher_text = "eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}"
alphabet = "abcdefghijklmnopqrstuvwxyz"

message = ""
j = 0

for ch in cipher_text:
    if ch in alphabet:
        c = alphabet.index(ch)
        k = alphabet.index(key[j % len(key)])
        message += alphabet[(c - k) % 26]
        j += 1
    else:
        message += ch

print(message)

#ELSE

import string
from collections import Counter

alphabet = string.ascii_lowercase
eng_freq = {
 'a':8.17,'b':1.49,'c':2.78,'d':4.25,'e':12.70,'f':2.23,'g':2.02,
 'h':6.09,'i':6.97,'j':0.15,'k':0.77,'l':4.03,'m':2.41,'n':6.75,
 'o':7.51,'p':1.93,'q':0.10,'r':5.99,'s':6.33,'t':9.06,'u':2.76,
 'v':0.98,'w':2.36,'x':0.15,'y':1.97,'z':0.07
}

def ic(text):
    n = len(text)
    if n < 2: return 0
    c = Counter(text)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

def best_shift(column):
    best = None
    for s in range(26):
        dec = ''.join(alphabet[(alphabet.index(ch)-s)%26] for ch in column)
        # chi-squared
        chi = 0
        n = len(dec)
        c = Counter(dec)
        for ch in alphabet:
            exp = eng_freq[ch]/100 * n
            obs = c.get(ch, 0)
            chi += (obs-exp)**2/exp
        if best is None or chi < best[0]:
            best = (chi, s)
    return best[1]

def vigenere_crack(cipher_text, max_m=20):
    ct = ''.join(ch for ch in cipher_text.lower() if ch in alphabet)
    scores = []
    for m in range(1, max_m+1):
        cols = [ct[i::m] for i in range(m)]
        avg_ic = sum(ic(c) for c in cols)/m
        scores.append((abs(avg_ic-0.066), m, avg_ic))
    scores.sort()
    m = scores[0][1]
    key = ''.join(alphabet[best_shift(ct[i::m])] for i in range(m))
    return key

ct = "eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}"
key = vigenere_crack(ct)
print(key)