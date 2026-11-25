# Secure Bank has unleashed their newest CLI-based money transfer tool:
# Connect using nc cns-test.idlab.uantwerpen.be 50001 now!
#
# They internally use super secure Salsa20 encryption using their proprietary JSON formatted transaction format (see file).
# Maybe you can hack it to pay Bob back the money you owe him...
#
# (In case you try this at home, you need to be connected to the UA-VPN)
#
# Hint:
#
# def encrypt_transaction(transaction):
#     """Encrypt a transaction using Salsa20."""
#     nonce = secrets.token_bytes(8)
#
#     cipher = Salsa20.new(key=KEY, nonce=nonce)
#
#     plaintext = json.dumps(
#         transaction,
#         separators=(",", ":")
#     ).encode()
#     print(plaintext)
#
#     ciphertext = cipher.encrypt(plaintext)
#
#     # Transmit nonce alongside ciphertext
#     return nonce + ciphertext