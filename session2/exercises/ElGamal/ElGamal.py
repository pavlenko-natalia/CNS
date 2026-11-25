from sympy import factorint, discrete_log
from Crypto.Util.number import long_to_bytes, inverse

def elgamal_decrypt(p, x, c1, c2):
    """Дешифрування, якщо відомий приватний ключ x."""
    s = pow(c1, x, p)
    m = (c2 * inverse(s, p)) % p
    return long_to_bytes(m)

def solve_dlp(p, g, y):
    """Розв'язати y = g^x mod p. Працює для малих p або гладких p-1."""
    # sympy discrete_log сам вибирає метод (BSGS, Pohlig-Hellman тощо)
    return discrete_log(p, y, g)

def nonce_reuse_decrypt(p, c1a, c2a, c1b, c2b, m_known=None):
    """
    Якщо два шифротексти мають однаковий c1 (тобто однакове k),
    то c2a / c2b = ma / mb mod p.
    Якщо відоме одне повідомлення — відновлюємо інше.
    """
    ratio = (c2a * inverse(c2b, p)) % p
    if m_known is not None:
        m_other = (m_known * ratio) % p
        return long_to_bytes(m_other)
    return ratio  # ratio = ma / mb

def nonce_reuse_signature(p, r, s1, s2, m1, m2):
    """
    Два підписи з однаковим r (тобто однакове k) розкривають x.
    """
    k = ((m1 - m2) * inverse(s1 - s2, p - 1)) % (p - 1)
    x = ((m1 - k * s1) * inverse(r, p - 1)) % (p - 1)
    return k, x
