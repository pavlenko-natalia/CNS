# ECB (Electronic Codebook)
#
# Опис: кожен блок шифрується незалежно. Вразливість: детермінованість; однакові plaintext-блоки → однаковий ciphertext;
# byte-at-a-time attack (якщо є encryption oracle).
#
# Скрипт: byte-at-a-time ECB decryption

from Crypto.Cipher import AES

BLOCK_SIZE = 16

def byte_at_a_time_ecb(oracle, prefix_len=0):
    """oracle: функція, що повертає ciphertext для довільного plaintext."""
    recovered = b""
    while True:
        pad_len = BLOCK_SIZE - ((prefix_len + len(recovered)) % BLOCK_SIZE) - 1
        prefix = b"A" * pad_len
        target_ct = oracle(prefix)
        block_idx = (prefix_len + len(recovered)) // BLOCK_SIZE

        for b in range(256):
            guess = prefix + recovered + bytes([b])
            guess_ct = oracle(guess)
            if guess_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE] == \
               target_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]:
                recovered += bytes([b])
                break
        else:
            return recovered

# Це класичний підхід для завдань типу "Fool the Oracle".