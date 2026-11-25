# Опис
#
# Для a, b ∈ ℤ знаходить gcd(a, b) і коефіцієнти x, y такі, що a·x + b·y = gcd(a, b). Якщо gcd(a, m) = 1 → x = a⁻¹ mod m. Використовується в RSA, GF(2⁸), polynomial inverse, CRT.
#
# Вразливості
#
# Timing side-channel, якщо не constant-time (для RSA).
# Некоректна редукція на проміжних кроках → неправильний gcd.
# a не взаємно просте з m → оберненого не існує (треба перевіряти gcd).
# Скрипти

# (a) Класичний ітеративний extended Euclid (integer)

def egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t   # gcd, x, y

# приклад
g, x, y = egcd(240, 46)
print(g, x, y, 240*x + 46*y)     # 2, -9, 47, 2
# (b) Модульний обернений (integer)

python
def mod_inv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no inverse, gcd = {g}")
    return x % m

# приклад: 3⁻¹ mod 7 = 5
print(mod_inv(3, 7))     # 5
# (c) Обернений у GF(2⁸) через extended Euclid над GF(2)[x] — уже в §11(c).

# (d) RSA sanity check (e=65537)

# gcd(e, φ(n)) має дорівнювати 1, інакше e не має оберненого
e = 65537
phi_n = ...   # (p-1)(q-1)
g, _, _ = egcd(e, phi_n)
assert g == 1
# обернений — це d = e⁻¹ mod φ(n)
d = mod_inv(e, phi_n)

# (e) CRT через extended Euclid (для швидкого RSA)

def crt_pair(r1, m1, r2, m2):
    g, a, b = egcd(m1, m2)
    if g != 1: raise ValueError("m1, m2 not coprime")
    return (r1 * b * m2 + r2 * a * m1) % (m1 * m2)

# Коли що: "знайти обернений" → (a)+(b). "GF(2⁸)" → (c). "Перевірити RSA" → (d)+(e).