# Опис
#
# Sponge construction, переможець конкурсу NIST 2012. Параметри r (bitrate) + c (capacity) = 1600 біт. Для SHA3-256: r=1088, c=512. Не Merkle–Damgård → не вразливий до length extension.
#
# Вразливості
#
# Практично невідомі (Keccak стійкий).
# Неправильне використання (той самий "H(K||M)" патерн) — хоча length extension не працює, краще HMAC.
# Bias у реалізаціях (не пов'язано з математикою).
# Скрипти

# (a) SHA-3 обчислення (усі варіанти)

import hashlib
print(hashlib.sha3_256(b"hello").hexdigest())
print(hashlib.sha3_512(b"hello").hexdigest())

# (b) Демонстрація, що length extension НЕ працює

# якщо hashpumpy не дає результату для SHA-3 (або результат невалідний) —
# це очікувано, бо SHA-3 не Merkle–Damgård

# (c) HMAC-SHA3 (правильний MAC)

import hmac, hashlib
mac = hmac.new(b"key", b"message", hashlib.sha3_256).hexdigest()

# Коли що: SHA-3 рідко зустрічається в CTF; частіше — як "безпечна альтернатива" в теорії.