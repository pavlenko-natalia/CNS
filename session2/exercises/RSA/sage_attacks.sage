# sage_attacks.sage
# Запуск: sage sage_attacks.sage   (або: sage -python sage_attacks.py)
# Тестовано на SageMath 10.x

# =====================================================================
# 1. Coppersmith univariate (малий корінь полінома mod n)
#    Найбільш уживаний у реальних CTF
# =====================================================================
def coppersmith_univariate(f, n, X, beta=1.0):
    """
    Знаходить x0: |x0| < X і f(x0) ≡ 0 (mod n) (або mod p, де p|n, p ≥ n^beta).
    f — поліном над Zmod(n) або ZZ; X — верхня межа |x0|.
    Повертає список коренів x0.
    """
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    f = R(f)
    try:
        roots = f.small_roots(X=X, beta=beta)
    except Exception as e:
        print(f"  [!] small_roots failed: {e}")
        return []
    return [Integer(r) for r in roots]


# =====================================================================
# 2. Partial plaintext: m = known + x, де x малий
# =====================================================================
def partial_plaintext(n, e, c, known_bits, shift):
    """
    m = known_bits * 2^shift + x, де x < 2^shift (shift біт невідомі знизу).
    Тобто молодші shift біт невідомі, старші known_bits відомі.
    Або: m = x * 2^shift + known_bits (тоді передай shift і known_bits
    у зворотному порядку — див. приклад нижче).
    """
    X = 2^shift
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    # f(x) = (known_bits * 2^shift + x)^e - c
    f = (known_bits * (2^shift) + x)^e - c
    return coppersmith_univariate(f, n, X)


def partial_plaintext_low(n, e, c, known_low, unknown_bits):
    """
    m = x * 2^unknown_bits + known_low.
    Невідомі старші біти (безпосередньо перед відомими молодшими).
    """
    X = 2^unknown_bits
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    f = (x * (2^unknown_bits) + known_low)^e - c
    return coppersmith_univariate(f, n, X)


# =====================================================================
# 3. Håstad з Coppersmith (коли m^e > N після CRT)
# =====================================================================
def hastad_coppersmith(ns, e, cs, m_max_bits):
    """
    CRT об'єднує c_i у X = m^e mod N. Якщо m^e > N, X = m^e - k·N.
    Тоді шукаємо малий корінь f(x) = x^e - X mod N, з |x| < 2^m_max_bits.
    """
    from functools import reduce
    N = 1
    for n in ns: N *= n
    # CRT
    X_crt = 0
    for ci, ni in zip(cs, ns):
        Ni = N // ni
        X_crt += ci * Ni * inverse_mod(Ni, ni)
    X_crt %= N
    R.<x> = PolynomialRing(Zmod(N), implementation='NTL')
    f = x^e - X_crt
    return coppersmith_univariate(f, N, 2^m_max_bits)


# =====================================================================
# 4. Common Modulus з gcd(e1,e2)=g > 1 і m^g > n
# =====================================================================
def common_modulus_general(n, e1, e2, c1, c2, m_max_bits):
    g = gcd(e1, e2)
    _, a, b = xgcd(e1, e2)
    if a < 0:
        c1 = inverse_mod(c1, n); a = -a
    if b < 0:
        c2 = inverse_mod(c2, n); b = -b
    mg = (power_mod(c1, a, n) * power_mod(c2, b, n)) % n
    # спробувати точний корінь
    r = mg.nth_root(g, truncate_mode=True)[0]
    if r^g == mg:
        return [r]
    # інакше — Coppersmith: f(x) = x^g - mg mod n
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    f = x^g - mg
    return coppersmith_univariate(f, n, 2^m_max_bits)


# =====================================================================
# 5. Franklin–Reiter (працює для e до ~30 у Sage)
# =====================================================================
def franklin_reiter(n, e, c1, c2, a, b):
    """
    c1 = m^e, c2 = (a·m + b)^e. Повертає m.
    Метод: gcd(x^e - c1, (a·x+b)^e - c2) над Z/nZ дає (x − m).
    """
    R.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    f1 = x^e - c1
    f2 = (a*x + b)^e - c2
    g = f1.gcd(f2)
    if g.degree() == 1:
        # g = α·x + β, корінь = −β/α
        alpha = g[1]; beta = g[0]
        return [Integer(-beta * inverse_mod(alpha, n) % n)]
    return []


# =====================================================================
# 6. Boneh–Durfee (d < n^0.292) — стандартна реалізація Herrmann–May
#    Атрибуція: адаптовано з mimoo/RSA-and-LLL-attacks
# =====================================================================
def boneh_durfee(n, e, delta=0.26, mm=4, tt=2):
    """
    Знаходить d, якщо d < n^delta (теоретична межа delta ≈ 0.292).
    На практиці mm=4..6, tt=2..3 для малих n.
    """
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u)
    A = (n + 1) // 2
    pol = 1 + x * (A + y)  # 1 + x(A + y) ≡ 0 mod e при x = k, y = p+q
    polZ = Q(pol).lift()

    XX = 2 * floor(n^delta)   # межа для d (x-змінна)
    YY = 2 * floor(n^(1/2))   # межа для s = p+q (y-змінна)
    UU = XX * YY + 1

    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            gg.append(x^ii * e^(mm - kk) * polZ(u, x, y)^kk)

    # y-shifts
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            gg.append(y^jj * polZ(u, x, y)^kk * e^(mm - kk))

    # зібрати всі мономи
    monomials = set()
    for g in gg:
        for m in g.monomials():
            monomials.add(m)
    monomials = sorted(monomials)

    # побудувати матрицю
    nn = len(monomials)
    BB = Matrix(ZZ, nn, nn)
    for ii, g in enumerate(gg):
        BB[ii, 0] = g(0, 0, 0)
        for jj in range(1, nn):
            if monomials[jj] in g.monomials():
                BB[ii, jj] = g.monomial_coefficient(monomials[jj]) * \
                             monomials[jj](UU, XX, YY)

    BB = BB.LLL()

    # перетворити назад у поліноми
    new_pol = []
    for ii in range(nn):
        s = 0
        for jj in range(nn):
            s += BB[ii, jj] * monomials[jj](u, x, y)
        new_pol.append(s)

    PR2.<u, x> = PolynomialRing(ZZ)
    new_pol = [PR2(p) for p in new_pol]

    # resultants → знайти (u, x)
    for ii in range(nn):
        for jj in range(ii + 1, nn):
            if new_pol[ii].is_zero() or new_pol[jj].is_zero():
                continue
            try:
                res = new_pol[ii].resultant(new_pol[jj], y).univariate_polynomial()
            except Exception:
                continue
            if res == 0:
                continue
            try:
                roots = res.roots()
            except Exception:
                continue
            for r, _ in roots:
                r = Integer(r)
                if 1 < gcd(r, n) < n:
                    p = Integer(gcd(r, n))
                    d = inverse_mod(e, (p - 1) * (n // p - 1))
                    return d
    return None


# =====================================================================
# 7. Bleichenbacher '06 (e=3, PKCS#1 v1.5 signature forgery)
# =====================================================================
def bleichenbacher_signature_forge_sketch():
    """
    Псевдокод (не повна функція — залежить від конкретної перевірки).
    Ідея: якщо перевірка не вимагає, щоб "00 01 FF FF ... FF 00 <hash>"
    займало рівно k байт, можна підробити s таке, що s³ mod n має
    правильний префікс і містить hash, але "зайві" байти ігноруються.
    s = iroot(emb * 2^(8·extra_pad), 3) для достатнього extra_pad.
    """
    return "Дивись деталі у Bleichenbacher 2006 / конкретній умові"


# =====================================================================
# CLI: інтеграція з challenge.json (сумісно з general_plus.py)
# =====================================================================
def run_challenge(path):
    import json
    with open(path) as f:
        ch = json.load(f)
    n = ch.get('n') or (ch.get('ns') or [None])[0]
    e = ch.get('e') or (ch.get('es') or [None])[0]
    c = ch.get('c') or (ch.get('cs') or [None])[0]
    if n is None:
        print("  [!] no n found")
        return
    n, e, c = Integer(n), Integer(e), Integer(c)

    # самостійно вирішити, яку функцію викликати
    print(f"  n = {n.nbits()} bits, e = {e}")
    # Приклад: e=3 + partial plaintext
    if 'known_prefix' in ch:
        prefix = bytes(ch['known_prefix'], 'utf-8')
        prefix_int = int.from_bytes(prefix, 'big')
        unknown_bits = 8 * ch.get('unknown_length', 4)
        print(f"  → спроба Coppersmith з відомим префіксом, {unknown_bits} невідомих біт")
        roots = partial_plaintext(n, e, c, prefix_int, unknown_bits)
        for r in roots:
            m = prefix_int * (2^unknown_bits) + r
            print(f"  [+] candidate m = {m}")
            try:
                print(f"      text = {bytes(Integer(m).digits(256))[::-1].decode()!r}")
            except Exception:
                pass
    elif 'known_low' in ch:
        print("  → Coppersmith з відомими молодшими бітами")
        roots = partial_plaintext_low(n, e, c, Integer(ch['known_low']),
                                      8 * ch['unknown_length'])
        for r in roots:
            print(f"  [+] candidate m = {r}")
    elif ch.get('boneh_durfee') or (e > n // 2 and e.nbits() > n.nbits() - 4):
        print("  → Boneh–Durfee")
        d = boneh_durfee(n, e)
        if d:
            m = power_mod(c, d, n)
            print(f"  [+] m = {m}")
    else:
        print("  [-] не вдалось визначити атаку — заповни вручну")


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        run_challenge(sys.argv[1])
    else:
        print("Usage: sage sage_attacks.sage challenge.json")