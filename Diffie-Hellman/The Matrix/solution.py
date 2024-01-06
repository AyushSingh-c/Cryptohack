from sage.all import *

P = 2
N = 50
E = 31337

FLAG = b'crypto{??????????????????????????}'

def recover_plaintext(mat):
    temp = ""
    for i in range(N):
        for j in range(N):
            temp = temp + str(mat[j][i])

    temp = temp[:len(FLAG) * 8]
    return int(temp, 2).to_bytes((len(temp) + 7) // 8, 'big')

def load_matrix(fname):
    data = open(fname, 'r').read().strip()
    rows = [list(map(int, row)) for row in data.splitlines()]
    return Matrix(GF(P), rows)

ciphertext = load_matrix("flag.enc")
d = pow(E, -1, ciphertext.multiplicative_order())
mat = ciphertext ** d
print(recover_plaintext(mat))