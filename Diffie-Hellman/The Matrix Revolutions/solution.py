from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import *
from Crypto.Util.Padding import pad, unpad
from sage.all import *
import json
from tqdm import tqdm

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

def get_flag(shared_secret):
    ct = open('flag.enc', 'r')
    enc_flag = json.loads(ct.readline())
    iv = bytes.fromhex(enc_flag['iv'])
    ciphertext = bytes.fromhex(enc_flag['ciphertext'])

    key = derive_aes_key(shared_secret)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    print("Flag: ", unpad(cipher.decrypt(ciphertext), 16))

G = load_matrix("generator.txt")
G_A = load_matrix("alice.pub")
G_B = load_matrix("bob.pub")

g_factors = [61,89]
x = []
y = []
p = []

for i in range(2):
    g_poly = PolynomialRing(GF(2**g_factors[i]), 'x')(G.charpoly().factor()[i][0])  
    g_a_poly = PolynomialRing(GF(2**g_factors[i]), 'x')(G_A.charpoly().factor()[i][0])  
    g_b_poly = PolynomialRing(GF(2**g_factors[i]), 'x')(G_B.charpoly().factor()[i][0])  

    g_roots = (g_poly.roots())
    g_a_roots = (g_a_poly.roots())
    g_b_roots = (g_b_poly.roots())

    mod_a = []
    mod_b = []
    for k in tqdm(range(int(g_factors[i]))):
        g_root = GF(2**g_factors[i])(g_roots[0][0])
        g_a_root = GF(2**g_factors[i])(g_a_roots[k][0])
        g_b_root = GF(2**g_factors[i])(g_b_roots[k][0])
        mod_a.append(g_a_root.log(g_root))
        mod_b.append(g_b_root.log(g_root))
    x.append(mod_a)
    y.append(mod_b)
    p.append(g_root.multiplicative_order())


X = 0
Y = 0
for i in x[0]:
    for j in x[1]:
        temp = crt([i,j],p)
        if G**temp == G_A and is_prime(temp):
            print("find X: ", temp)
            X = temp 
            break

for i in y[0]:
    for j in y[1]:
        temp = crt([i,j],p)
        if G**temp == G_B and is_prime(temp):
            print("find Y: ", temp)
            Y = temp 
            break


get_flag((G**X)**Y)
