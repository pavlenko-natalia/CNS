# See the code below, I don't think it's a better hash:
#
# def rol(x, n):
#     return ((x << n) | (x >> (8 - n))) & 0xff
#
# def better_hash(msg):
#     state = bytearray(msg.encode())
#
#     for rnd in range(8):
#
#         for i in range(len(state)):
#             state[i] ^= (rnd * 41 + i * 17) & 0xff
#             state[i] = rol(state[i], (rnd + i) & 7)
#
#         for i in range(1, len(state)):
#             state[i] ^= state[i - 1]
#
#         state = state[1:] + state[:1]
#
#     return state.hex()
#
# print(better_hash(FLAG))
# Hash: 5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba

def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def better_hash(msg):
    state = bytearray(msg.encode())

    for rnd in range(8):

        for i in range(len(state)):
            state[i] ^= (rnd * 41 + i * 17) & 0xff
            state[i] = rol(state[i], (rnd + i) & 7)

        for i in range(1, len(state)):
            state[i] ^= state[i - 1]

        state = state[1:] + state[:1]

    return state.hex()

# print(better_hash(FLAG))

def ror(x, n):
    n &= 7
    if n == 0:
        return x
    return ((x >> n) | (x << (8 - n))) & 0xff

def decrypt_better_hash(hash):
    state = bytearray(bytes.fromhex(hash))

    for rnd in range(7, -1, -1):

        state = state[-1:] + state[:-1]

        for i in range(len(state) - 1, 0, -1):
            state[i] ^= state[i - 1]

        for i in range(len(state)):
            state[i] = ror(state[i], (rnd + i) & 7)
            state[i] ^= (rnd * 41 + i * 17) & 0xff

    return bytes(state)

print(decrypt_better_hash("5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"))
