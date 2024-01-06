from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from sage.all import *

import json


FLAG = b'crypto{?????????????????????????????????????}'

P = 13322168333598193507807385110954579994440518298037390249219367653433362879385570348589112466639563190026187881314341273227495066439490025867330585397455471
N = 30

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row.split(' '))) for row in data.splitlines()]
    return Matrix(GF(P), rows)

G = load_matrix("generator.txt")


f1 = open('output.txt', 'r')
dh = json.loads(f1.readline())
v = vector(GF(P), dh['v'])
w = vector(GF(P), dh['w'])

a = p.inverse() * v
b = p.inverse() * w 
theta = g[N - 2][N - 2]

# Solution to dlog
SECRET = theta * (b[N - 2] - (a[N - 2] * b[N - 1]) / a[N - 1]) / b[N - 1]
KEY_LENGTH = 128
KEY = SHA256.new(data=str(SECRET).encode()).digest()[:KEY_LENGTH]

ct = open('flag.enc', 'r')
enc_flag = json.loads(ct.readline())
iv = bytes.fromhex(enc_flag['iv'])
ciphertext = bytes.fromhex(enc_flag['ciphertext'])

cipher = AES.new(KEY, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(ciphertext), 16))