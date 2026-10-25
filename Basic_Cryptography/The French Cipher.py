# The French pattisiers are in a bake-off with the Italian pizza restaurants.
# Can you decrypt their communication?
# eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}
#
# They key is France's favorite moon-shaped breakfast item!
key = "croissant"
cipher_text = "eeg{kjgiflceha-sje-oxvksz-lzaa-ikqni}"
alphabet = "abcdefghijklmnopqrstuvwxyz"

message = ""
j = 0

for ch in cipher_text:
    if ch in alphabet:
        c = alphabet.index(ch)
        k = alphabet.index(key[j % len(key)])
        message += alphabet[(c - k) % 26]
        j += 1
    else:
        message += ch

print(message)

