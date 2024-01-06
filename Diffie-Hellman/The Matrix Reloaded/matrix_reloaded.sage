from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad

import json
from os import urandom

FLAG = b'crypto{?????????????????????????????????????}'

P = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
N = 30

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row.split(' '))) for row in data.splitlines()]
    return Matrix(GF(P), rows)

SECRET = getRandomRange(0, P-1)
KEY_LENGTH = 128
KEY = SHA256.new(data=str(SECRET).encode()).digest()[:KEY_LENGTH]

G = load_matrix("generator.txt")
H = G^SECRET

v = vector(GF(P), [getRandomRange(0, P-1) for _ in range(N)])
w = H*v

json.dump({
    'v': [int(x) for x in list(v)],
    'w': [int(x) for x in list(w)]
}, open('output.txt', 'w'))

iv = urandom(16)
cipher = AES.new(KEY, AES.MODE_CBC, iv)
plaintext = pad(FLAG, 16)
ciphertext = cipher.encrypt(plaintext)

json.dump({
    "iv": iv.hex(), 
    "ciphertext": ciphertext.hex()
}, open('flag.enc', 'w'))