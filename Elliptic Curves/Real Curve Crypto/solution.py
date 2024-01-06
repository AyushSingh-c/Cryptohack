import json

from decimal import Decimal
from mpmath import mp
from tqdm import trange
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad
from sage.all import *

import random


mp.dps = 1000
pari("\p 1000")
RR = RealField(3000)

class Custom_Point:
    def __init__(self, a, b):
        self.x = a
        self.y = b
    
# for y^2 = x^3 + g1*x + g2
class Custom_Elliptic_Curve:
    def __init__(self, a, b):
        self.g1 = a
        self.g2 = b
        self.e = [0, 1 ,2]
        if (4*a*a*a) + (27*b*b) < 0:
            self.e = []
            x = var('x') 
            eq = (x**3) + (a*x) + b  
            roots = eq.roots()
            for i in range(3):
                self.e.append(roots[i][0])
            self.e.sort()
        self.torus_img_period = mp.pi / self.M(mp.sqrt(self.e[2] - self.e[0]), mp.sqrt(self.e[1] - self.e[0]))
        self.torus_real_period = mp.pi / self.M(mp.sqrt(self.e[2] - self.e[0]), mp.sqrt(self.e[2] - self.e[1]))

    def lift_x(self, x):
        return mp.sqrt(x**3 + (self.g1*x) + self.g2)
    
    def get_random_point(self):
        gx = mp.mpf(1 + random.random())
        gy = self.lift_x(gx)
        return Custom_Point(gx, gy)
    
    def addition(self, C1, C2):
        slope = 0
        if C1.x == C2.x and C1.y == C2.y:
            slope = (3*C1.x*C1.x + self.g1) / (2*C1.y) 
        elif C1.x == C2.x:
            return None
        else:
            slope = (C1.y - C2.y) / (C1.x - C2.x) 
        x_r = (slope**2) - C1.x - C2.x
        y_r = (slope*(C1.x - x_r)) - C1.y
        return Custom_Point(x_r, y_r)

    def scalar_multiply(self, P, m):
        if m == 1:
            return P
        half_mult = self.scalar_multiply(P, m // 2)
        ans = self.addition(half_mult, half_mult)
        if m % 2 == 1:
            ans = self.addition(ans, P)
        return ans

    def M(self, a, b):
        for _ in range(100):
            a, b = (a + b) / 2, mp.sqrt(a * b)
        return a    
    
    def weierstrass_p(self, z):
        pari("\p 1000")
        pari(f"E=ellinit([{self.g1}, {self.g2}])")
        return pari(f"ellwp(E, {z})")


    def inverse_weierstrass_p(self, P, y=None):
        lb = self.torus_real_period / 2 + 10 ** -5
        hb = self.torus_real_period - 10 ** -5
        tq = trange(500)
        for _ in tq:
            tq.set_description(f'{hb - lb = }')
            mid = (lb + hb) / 2
            if self.weierstrass_p(mid) > P.x:
                hb = mid
            else:
                lb = mid
        if y and y < 0:
            return self.torus_real_period - lb
        return lb
    
def solve_dlp_ecc(curve, G, P):
    g_z = curve.inverse_weierstrass_p(G)
    p_z = curve.inverse_weierstrass_p(P)

    N = 10 ** 200
    ks = 2 ** 128
    eps = 10 ** -112
    mat = Matrix(QQ, 3, 4)
    mat[0, 0] = 1
    mat[0, 3] = floor(N * g_z / curve.torus_real_period)
    mat[1, 1] = 1
    mat[1, 3] = floor(N * p_z / curve.torus_real_period)
    mat[2, 2] = 1
    mat[2, 3] = N
    x = N * eps / ks
    y = N * eps
    z = N * eps / ks
    W = Matrix(QQ, 4, 4)
    W[0, 0] = x
    W[1, 1] = y
    W[2, 2] = z
    W[3, 3] = 1
    L = (mat * W).LLL() / W
    return int(abs(L[0, 0]))


curve = Custom_Elliptic_Curve(-1, 0)

with open('output.txt', 'r') as f:
    data = json.load(f)
    G = Custom_Point(Decimal(data['gx']), Decimal(data['gy']))
    P = Custom_Point(Decimal(data['px']), Decimal(data['py']))
    iv = bytes.fromhex(data['iv'])
    ciphertext = bytes.fromhex(data['ciphertext'])

    private_key = long_to_bytes(solve_dlp_ecc(curve, G, P))
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    print("Flag: ", unpad(plaintext, 16))