from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import pad

from mpmath import mp
from os import urandom

import json
import random

FLAG = b'crypto{????????????????????????}'

mp.dps = 200

# y^2 = x^3 - x
def lift_x(x):
    return mp.sqrt(x**3 - x)

def double(pt):
    x, y = pt
    m = (3*x*x - 1)/(2 * y)
    xf = m*m - 2*x
    yf = -(y + m*(xf - x))
    return (xf, yf)

def add(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    m = (y1 - y2)/(x1 - x2)
    xf = m*m - x1 - x2
    yf = -(y1 + m*(xf - x1))
    return (xf, yf)

def scalar_multiply(pt, m):
    if m == 1:
        return pt
    half_mult = scalar_multiply(pt, m // 2)
    ans = double(half_mult)
    if m % 2 == 1:
        ans = add(ans, pt)
    return ans

key = urandom(16)
iv = urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = pad(FLAG, 16)
ciphertext = cipher.encrypt(plaintext)

N = bytes_to_long(key)

gx = mp.mpf(1 + random.random())
gy = lift_x(gx)
G = (gx, gy)
P = scalar_multiply(G, N)

json.dump({
    'gx': str(G[0]),
    'gy': str(G[1]),
    'px': str(P[0]),
    'py': str(P[1]),
    'ciphertext': ciphertext.hex(),
    'iv': iv.hex()
}, open('output.txt', 'w'))
