import json
from ecc_side_channel import Point, double_and_add
from Crypto.Util.number import bytes_to_long

FLAG = b'crypto{?????????????????????????????????????}'

# Secp256k1 curve parameters
p = 2**256 - 2**32 - 977
a = 0
b = 7

# Generator 
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = Point(gx, gy)

# Private key
d = bytes_to_long(FLAG)

# Side channel data collection
collected_data = []
for _ in range(50):
    Q, leak = double_and_add(G, d)
    collected_data.append(leak)

with open('collected_data.txt', 'w') as f:
    f.write(json.dumps(collected_data))




