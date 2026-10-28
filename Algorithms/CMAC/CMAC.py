# Опис
#
# CMAC(K, M) — блочний MAC на базі AES/3DES. NIST SP 800-38B. Два підключі K1, K2 (похідні від L = E(K, 0^b)). Останній блок обробляється по-різному (з K1 або K2), щоб уникнути проблем CBC-MAC.
#
# Вразливості
#
# Сам CMAC — стійкий.
# Nonce/IV reuse не стосується (CMAC детермінований).
# Порівняння не в constant-time → timing attack.
# Ключі K1, K2 залежать від E(K,0) — обов'язково правильно генерувати.
# Скрипт

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def cmac_aes(key, message):
    c = CMAC.new(key, ciphermod=AES)
    c.update(message)
    return c.hexdigest()

# приклад
print(cmac_aes(bytes(16), b"hello world"))

# Коли що: у завданні є CMAC — просто обчислюємо/перевіряємо. Не ламаємо.