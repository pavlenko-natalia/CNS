# The German bakers have joined the bake-off. They are using their signature ENIGMA machine. It works as follows:
#
# Characters are inputted via the keyboard, A=0, B=1, ... When a character is inputted, Rotor 1: MACHINEBDFGJKLOPQRSTUVWXYZ advances. e.g. Rotor 1 becomes: ACHINEBDFGJKLOPQRSTUVWXYZM.
#
# The character is passed through the rotor using the index of the character. Z = 25 --> rotor 1[25] = M
#
# This happens again for Rotor 2: ORBITACDEFGHJKLMNPQSUVWXYZ and Rotor 3: CIPHERABDFGJKLMNOQSTUVWXYZ
#
# However, Rotor 2 only rotates when Rotor 1 has made a full rotation and Rotor 3 only rotates when Rotor 2 has made a full rotation.
#
# The bakers have sent the following message: HKV{BSBU-B-SJYZNNB-DNFW-IXH-YTA-RPL-RTXOLWFQ} Their rotors started at 0,0,0.
#cns
rotor1 = "MACHINEBDFGJKLOPQRSTUVWXYZ"
rotor2 = "ORBITACDEFGHJKLMNPQSUVWXYZ"
rotor3 = "CIPHERABDFGJKLMNOQSTUVWXYZ"

plain = "HKV{BSBU-B-SJYZNNB-DNFW-IXH-YTA-RPL-RTXOLWFQ}"
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# rotor1_position = (len(plain) - 11)  % len(rotor1)
# rotor2_position = (len(plain) - 11)  // len(rotor1) % len(rotor2)
# rotor3_position = (len(plain) - 11) // len(rotor1) // len(rotor2) % len(rotor3)

# print (rotor1_position, rotor2_position, rotor3_position)

message = ""
rotor1_position = 0
rotor2_position = 0
rotor3_position = 0

for lettern in plain:
    if lettern not in { "{", "}", "-"}:
        rotor1_position += 1
        rotor2_position = rotor1_position // len(alphabet)
        i = rotor3.find(lettern)
        rotor2_letter = alphabet[i]
        j = rotor2.find(rotor2_letter) - rotor2_position
        rotor1_letter = alphabet[j]
        k = rotor1.find(rotor1_letter)
        c = alphabet[ (k - rotor1_position) % len(alphabet) ]
        message += c
    else:
        message += lettern

print(message)