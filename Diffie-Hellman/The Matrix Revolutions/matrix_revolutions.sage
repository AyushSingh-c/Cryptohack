from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad

import json
from os import urandom

FLAG = b'crypto{????????????????????????????????????????}'

P = 2
N = 150

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

def save_matrix(M, fname):
    open(fname, 'w').write('\n'.join(''.join(str(x) for x in row) for row in M))

KEY_LENGTH = 128
def derive_aes_key(M):
    mat_str = ''.join(str(x) for row in M for x in row)
    return SHA256.new(data=mat_str.encode()).digest()[:KEY_LENGTH]

G = load_matrix("generator.txt")

A_priv = getPrime(149)
B_priv = getPrime(149)

A_pub = G^A_priv
B_pub = G^B_priv

save_matrix(A_pub, 'alice.pub')
save_matrix(B_pub, 'bob.pub')

shared_secret = A_pub^B_priv

key = derive_aes_key(shared_secret)
iv = urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = pad(FLAG, 16)
ciphertext = cipher.encrypt(plaintext)

json.dump({"iv": iv.hex(), "ciphertext": ciphertext.hex()}, 
          open('flag.enc', 'w'))