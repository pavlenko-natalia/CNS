# `c = (p + k) mod 26`. Ключ — зсув `k ∈ [1,25]`.
# По суті — моноалфавітна підстановка зі структурним обмеженням (циклічний зсув).

### Вразливості
# - **Ключовий простір 25** → brute force за мілісекунди.
# - Навіть без перебору — **frequency analysis**: найчастіша літера ciphertext ≈ `E`, далі `T,A,O,I,N`.
# - Відомий префікс `cns{` дає зсув **одразу**.

### Скрипти

# **(a) Знаємо формат `cns{` → зсув миттєво**
ct = "fqv{iluvw-fkdoohqjh}"
prefix = "cns"
# беремо перші 3 літери ciphertext і рахуємо зсув
k = (ord(ct[0]) - ord(prefix[0])) % 26
pt = "".join(chr((ord(c)-ord('a')-k)%26 + ord('a')) if c.islower()
             else chr((ord(c)-ord('A')-k)%26 + ord('A')) if c.isupper()
             else c for c in ct)
print(k, pt)

# **(b) Не знаємо формату — brute force всіх 25**

import string
ct = "fqv{iluvw-fkdoohqjh}"
for k in range(26):
    pt = "".join(
        string.ascii_lowercase[(string.ascii_lowercase.index(c)-k)%26] if c.islower()
        else string.ascii_uppercase[(string.ascii_uppercase.index(c)-k)%26] if c.isupper()
        else c for c in ct)
    print(k, pt)

# **(c) Scoring за англійською (коли повідомлення довге)**

from collections import Counter
ENG = "etaoinshrdlucmfwypvbgkjqxz"
ct = "fqv{iluvw-fkdoohqjh}"
letters = [c.lower() for c in ct if c.isalpha()]
scores = []
for k in range(26):
    dec = [chr((ord(c)-97-k)%26+97) for c in letters]
    freq = Counter(dec)
    # score = наскільки часто літери збігаються з ENG-порядком
    score = sum(freq.get(ch,0)*(len(ENG)-i) for i,ch in enumerate(ENG))
    scores.append((score, k))
print(sorted(scores, reverse=True)[:3])

