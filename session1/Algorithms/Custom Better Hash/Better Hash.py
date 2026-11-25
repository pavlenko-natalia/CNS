# Курсова "саморобка": послідовність з 8 раундів, кожен раунд — XOR з константою (rnd*41 + i*17), rol на (rnd+i) & 7, ланцюжок XOR state[i] ^= state[i-1], і циклічний зсув байтів state[1:] + state[:1].
#
# Ключове: усі операції оборотні, і довжина виходу = довжина входу → це не хеш, а оборотне перетворення.
#
# Вразливості
#
# Reversibility → легко відновити вихідне повідомлення з "хешу".
# Довжина виходу = довжині входу — вже сигнал, що це не хеш.
# Жодної компресії, жодного "one-way" ефекту.
# Скрипт (уже є у файлі — публікую фінальну версію)

def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def ror(x, n):
    n &= 7
    if n == 0: return x
    return ((x >> n) | (x << (8 - n))) & 0xff

def decrypt_better_hash(hash_hex):
    state = bytearray(bytes.fromhex(hash_hex))
    for rnd in range(7, -1, -1):
        # 4) зворотний циклічний зсув
        state = state[-1:] + state[:-1]
        # 3) зворотний ланцюжок XOR
        for i in range(len(state) - 1, 0, -1):
            state[i] ^= state[i - 1]
        # 2) + 1) зворотний rol + XOR з константою
        for i in range(len(state)):
            state[i] = ror(state[i], (rnd + i) & 7)
            state[i] ^= (rnd * 41 + i * 17) & 0xff
    return bytes(state)

# print(decrypt_better_hash("5f070b54361613bc..."))
# Коли що: "зламати хеш" у завданні — тільки реверс. Це і є розв'язок.