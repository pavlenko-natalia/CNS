# I have standardised the keys for my IoT devices so they are easier to program!
# I think this is really smart, since the devices are simple I decided to use DES as the encryption algorithm.
#
# { "namespace": "IOTDEV", "message": "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac" }

from Crypto.Cipher import DES

message = bytes.fromhex(
    "74eb40cf03b84d0bc4cd2c6e0fe97fb4"
    "e70546d3e09c530d35b344e530351bac"
)

for i in range(65536):
    key = b"IOTDEV" + i.to_bytes(2, "big")
    pt = DES.new(key, DES.MODE_ECB).decrypt(message)
    if b"cns{" in pt:
        print(f"FOUND: {key!r}")
        print(f"   {pt!r}")
        break
else:
    print("not found among IOTDEV + 2 bytes")