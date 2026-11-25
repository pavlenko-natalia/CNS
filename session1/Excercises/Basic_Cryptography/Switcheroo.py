plain = "ABCDEFGHIJKLMNOPQRSTUVWXYZ-"
cipher = "QWERTYUIOPASDFGHJKLZXCVBNM-"
cipher_text = "STZZTK-LGXH"

message = ""
for letter in cipher_text:
    i = -1
    for char in cipher:
        if char == letter:
            i = cipher.index(char)
    message += plain[i]

print("cns{" + message + "}")
