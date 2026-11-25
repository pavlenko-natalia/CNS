# import json
# from sympy import factorint
# from sympy.ntheory.residue_ntheory import discrete_log
# from Crypto.Util.number import long_to_bytes, inverse
#
# #--------------------------------------------------------------
# #diagnostic
# from sympy import factorint
# from math import log2
#
# p = 11655642371051559137021899193675264155833927634094563432113185127386727205937460119710022717731068222597389976317754800759209574764650965841375803852559979
#
# print("bits of p:", int(log2(p)))
# print("factoring p-1...")
# f = factorint(p - 1, limit=10**6)  # таймаут-обмеження
# print(f)
#
# for prime, exp in f.items():
#     print(f"  factor {prime}: {int(log2(prime))} bits, exp {exp}")
#
# #--------------------------------------------------------------
# p = 11655642371051559137021899193675264155833927634094563432113185127386727205937460119710022717731068222597389976317754800759209574764650965841375803852559979
#
# factors = {
#     2: 1,
#     3: 1,
#     394931: 1,
#     4918851804092174387011865867571493145145999188927755072874833463477049242330710984834491222403857983038973886711752517426761288581486793828700795773: 1
# }
#
# order = p - 1
# for q in factors:
#     while order % q == 0 and pow(2, order // q, p) == 1:
#         order //= q
#
# print("Order of g=2:", order)
#
# #--------------------------------------------------------------
#
# with open("ElGamal_challenge.json", "r") as f:
#     ch = json.load(f)
#
# p = ch["p"]
# g = ch["g"]
# y = ch["y"]
#
# known_plaintext = ch["known_plaintext"].encode()
# c1_known, c2_known = ch["cipher_known"]
# c1_flag, c2_flag = ch["cipher_flag"]
#
# # Переконуємось, що nonce справді різні
# assert c1_known != c1_flag
#
# # 1. Дивимось на факторизацію p-1
# print("[*] Factors of p-1:")
# print(factorint(p - 1))
#
# # 2. Розв'язуємо DLP: y = g^x mod p
# x = discrete_log(p, y, g)
# print("[*] Recovered x =", x)
#
# # 3. Перевірка на відомому повідомленні
# s_known = pow(c1_known, x, p)
# m_known = (c2_known * inverse(s_known, p)) % p
# assert long_to_bytes(m_known) == known_plaintext, "x is wrong!"
# print("[+] Known plaintext verified")
#
# # 4. Дешифрування флага
# s_flag = pow(c1_flag, x, p)
# m_flag = (c2_flag * inverse(s_flag, p)) % p
#
# # 5. Вивід
# flag = long_to_bytes(m_flag)
# print("[+] FLAG:")
# print(flag.decode(errors="replace"))
#
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

p = 11655642371051559137021899193675264155833927634094563432113185127386727205937460119710022717731068222597389976317754800759209574764650965841375803852559979
g = 2
y = 9800591634283795563239010288422807427250772972248905077913156331845129940720568824686127789650137814974517570792931867542026304326067442859164029332748259

c2_known = 8759566829194606197686812395646595794049488302474261788961896130436950485994883615535090565469512484522090257967282046589703760298560800614883747636114689
c2_flag  = 3467989230295532481326431340093805895254662271351805318280358781960118688260750373485102961759337253216408588463968428735046199681348104481230934531159373

m_known = bytes_to_long(b"Nonces are never reused here")

# y^k_known = c2_known / m_known
yk_known = (c2_known * inverse(m_known, p)) % p

# k_flag = k_known + 1  =>  y^k_flag = y^k_known * y
yk_flag = (yk_known * y) % p

# m_flag = c2_flag / y^k_flag
m_flag = (c2_flag * inverse(yk_flag, p)) % p

flag = long_to_bytes(m_flag)
print("[+] FLAG:")
print(flag.decode(errors="replace"))