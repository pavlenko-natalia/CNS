# c_i = (p_i + k_{i mod m}) mod 26. Поліалфавітна підстановка — m моноалфавітних шарів, що чергуються.
#
# Вразливості
#
# Періодичність → повторювані послідовності ciphertext на кратних m дають підказку довжини ключа (Kasiski).
# Index of Coincidence для кожного «стовпця» → довжина m; після цього кожен стовпець — Caesar → brute force / chi-square.
# Відомий префікс cns{ → ключ відновлюється прямим XOR/subtraction для перших 3 символів, далі перевіряємо на періодичність.
# Часто ключ — очевидне слово (croissant, pass).

# (a) Знаємо ключ

key = "croissant"
ct = "eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}"
alpha = "abcdefghijklmnopqrstuvwxyz"

j = 0
pt = ""

for c in ct:
    if c in alpha:
        pt += alpha[(alpha.index(c) - alpha.index(key[j%len(key)])) % 26]
        j += 1
    else:
        pt += c

print(pt)

# (b) Не знаємо ключа — IC + chi-square — уже є The French Cipher.py, друга половина. Мінімальний core:

import string
from collections import Counter

alpha = string.ascii_lowercase
ENG = {'a':8.17,'b':1.49,'c':2.78,'d':4.25,'e':12.70,'f':2.23,'g':2.02,
       'h':6.09,'i':6.97,'j':0.15,'k':0.77,'l':4.03,'m':2.41,'n':6.75,
       'o':7.51,'p':1.93,'q':0.10,'r':5.99,'s':6.33,'t':9.06,'u':2.76,
       'v':0.98,'w':2.36,'x':0.15,'y':1.97,'z':0.07}

def ic(text):
    n = len(text);
    if n < 2: return 0
    c = Counter(text)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

def best_shift(col):
    best = None
    for s in range(26):
        dec = ''.join(alpha[(alpha.index(ch)-s)%26] for ch in col)
        n = len(dec); cnt = Counter(dec)
        chi = sum((cnt.get(ch,0) - ENG[ch]/100*n)**2 / (ENG[ch]/100*n) for ch in alpha)
        if best is None or chi < best[0]: best = (chi, s)
    return best[1]

ct = ''.join(c for c in ct.lower() if c in alpha)
# 1) довжина ключа
ic_scores = [(abs(sum(ic(ct[i::m]) for i in range(m))/m - 0.066), m)
             for m in range(1, 20)]
m = min(ic_scores)[1]
# 2) кожен стовпець → зсув
key = ''.join(alpha[best_shift(ct[i::m])] for i in range(m))

print(m, key)

# (c) Відомий префікс cns{

ct = "eeg{kjgiflceha..."
prefix = "cns"
# перші 3 зсуви = ключові літери 0..2
key_part = [ (ord(ct[i]) - ord(prefix[i])) % 26 for i in range(3) ]
print("перші літери ключа:", [chr(97+k) for k in key_part])
# далі — Kasiski або IC для решти

# Коли що: відомий ключ → (a). Стандартне завдання → (b). Маєш формат і хочеш швидко → (c), потім (b) для решти.