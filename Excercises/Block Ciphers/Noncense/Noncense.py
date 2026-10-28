# The guys in IT told be those nonces are nonsene!

c_flag  = bytes.fromhex("def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c")
c_known = bytes.fromhex("fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a")

known_pt = b"According to all known laws of aviation, there is no way a bee should be able to fly."

# c1 = p1 XOR keystream
# c2 = p2 XOR keystream
#
# c1 XOR c2 = (p1 XOR ks) XOR (p2 XOR ks) = p1 XOR p2
#
# p2 = c1 XOR c2 XOR p1

print("flag len: ", len(c_flag))       # 41
print("known ct: ", len(c_known))      # 63
print("known pt: ", len(known_pt))     # 75

n = len(c_flag)
p_flag = bytes(
    a ^ b ^ c
    for a, b, c in zip(c_flag, c_known[:n], known_pt[:n])
)

print(p_flag)