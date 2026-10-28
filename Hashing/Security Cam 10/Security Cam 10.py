# We intercepted some network traffic from a security camera.
# Can you figure out the password and see into their facility?
#
# (The screenshot attached is a small hint to configure Wireshark to show the correct traffic type on a non-standard port)

import hashlib

user = "user"
realm = "PythonRTSP"
nonce = "4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"

attempts = [
    ("DESCRIBE", "rtsp://cns-test.idlab.uantwerpen.be:50002/video",
     "b3539154c5b784bba2c47a1a6c7c4ab0"),
    ("SETUP", "rtsp://cns-test.idlab.uantwerpen.be:50002/video/trackID=0",
     "083ae471a613399abb781f9e36111893"),
    ("PLAY", "rtsp://cns-test.idlab.uantwerpen.be:50002/video/",
     "be8c3203cdda65b8f6687bb134354562"),
]

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

with open("rockyou.txt", "r", errors="ignore") as f:
    passwords = [line.rstrip("\r\n") for line in f]

for method, uri, expected in attempts:
    ha2 = md5(f"{method}:{uri}")
    for password in passwords:
        ha1 = md5(f"{user}:{realm}:{password}")
        response = md5(f"{ha1}:{nonce}:{ha2}")
        if response == expected:
            print("Found:", password)
            print("Method:", method)
            raise SystemExit

print("Nothing found")