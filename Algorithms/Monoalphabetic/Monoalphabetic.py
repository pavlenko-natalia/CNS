# Опис
#
# Бієктивне відображення A→X для кожної літери (26! ключів ≈ 4·10²⁶).
# Приклад Switcheroo: ABCDEFGHIJKLMNOPQRSTUVWXYZ → QWERTYUIOPASDFGHJKLZXCVBNM.
#
# Вразливості
#
# Frequency analysis (однолітерні, біграми, триграми).
# Word pattern (that → 1231, see → 122) — дуже сильний сигнал разом зі словником.
# Відомий формат cns{ фіксує до 3 відображень одразу.
# Часто ключ — стандартна розкладка (QWERTY) або очевидна фраза.
# Скрипти
#
# (a) Фіксована перестановка (Switcheroo-стиль)

python
plain  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ-"
cipher = "QWERTYUIOPASDFGHJKLZXCVBNM-"
ct = "STZZTK-LGXH"
pt = "".join(plain[cipher.index(c)] if c in cipher else c for c in ct)
print(pt)

# (b) Автоматичний hill-climb з quadgrams — уже є subst_crack.py. Мінімальний виклик:

# python subst_crack.py --file cipher.txt --format cns --restarts 25 --iters 8000

# (c) Word-pattern + wordlist (Count the letters-стиль) — уже є Count the letters.py. Ключова ідея:

import re
from collections import defaultdict

def pattern(w):
    seen, out = {}, []
    for ch in w.lower():
        if ch not in seen: seen[ch] = len(seen)
        out.append(str(seen[ch]))
    return "".join(out)

# групуємо словник за патерном
idx = defaultdict(list)
for w in open("wordlist.txt").read().split():
    if w.isalpha(): idx[pattern(w)].append(w)
# для кожного cipher-слова обираємо кандидатів, робимо DFS з бієктивною перевіркою

# (d) Frequency + ручний аналіз (коротке повідомлення)

from collections import Counter
ct = "qnb{vsi-fihczlnb-...}"
letters = [c for c in ct.lower() if c.isalpha()]
print(Counter(letters).most_common(10))
# топ-літери → очікувано E,T,A,O,I,N,S,H,R
# топ-біграми: "th","he","in","er","an","re"

# Коли що: Switcheroo з відомою розкладкою → (a). Довільна підстановка з довгим текстом → (b).
# Є словник і дефіси/структура → (c). Дуже коротке → (d) + ручне.
