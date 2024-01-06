from Crypto.Util.number import inverse, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randint
from hashlib import sha1
import os

FLAG = b'crypto{????????????????????????????????????}'


class TwistedEdwards():
    # Elliptic curve in Edwards form:
    # -x**2 + y**2 = 1 + d*x**2*y**2
    # birationally equivalent to the Montgomery curve:
    # y**2 = x**3 + 2*(1-d)/(1+d)*x**2 + x

    def __init__(self, p, d, order, x0bit, y0):
        self.p = p
        self.d = d
        self.order = order
        self.base_point = (x0bit, y0)

    def recover_x(self, xbit, y):
        xsqr = (y**2 - 1)*inverse(1 + self.d*y**2, self.p) % self.p
        x = pow(xsqr, (self.p + 1)//4, self.p)
        if x**2 == xsqr :
            if x & 1 != xbit:
                return p - x
            return x
        return 0

    def decompress(self, compressed_point):
        xbit, y = compressed_point
        x = self.recover_x(xbit, y)
        return (x, y)

    # complete point addition formulas
    def add(self, P1, P2):
        x1, y1 = P1
        x2, y2 = P2
        
        C = x1*x2 % self.p
        D = y1*y2 % self.p
        E = self.d*C*D
        x3 = (1 - E)*((x1 + y1)*(x2 + y2) - C - D) % self.p
        y3 = (1 + E)*(D + C) % self.p
        z3 = 1 - E**2 % self.p
        z3inv = inverse(z3, self.p)
        return (x3*z3inv % self.p, y3*z3inv % self.p)

    # left-to-right double-and-add
    def single_mul(self, n, compressed_point):
        P = self.decompress(compressed_point)        
        t = n.bit_length()
        if n == 0:
            return (0,1)
        R = P
        for i in range(t-2,-1,-1):
            bit = (n >> i) & 1
            R = self.add(R, R)
            if bit == 1:
                R = self.add(R, P)
        return (R[0] & 1, R[1])


def gen_key_pair(curve):
    n = randint(1, curve.order-1)
    P = curve.single_mul(n, curve.base_point)
    return n, P
    
def gen_shared_secret(curve, n, P):
    xbit, y = curve.single_mul(n, P)
    return y
    

def encrypt_flag(shared_secret: int):
    # Derive AES key from shared secret
    key = sha1(str(shared_secret).encode('ascii')).digest()[:16]
    # Encrypt flag
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    data = {}
    data['iv'] = iv.hex()
    data['encrypted_flag'] = ciphertext.hex()
    return data



# curve parameters
# birationally equivalent to the Montgomery curve y**2 = x**3 + 337*x**2 + x mod p
p = 110791754886372871786646216601736686131457908663834453133932404548926481065303
order = 27697938721593217946661554150434171532902064063497989437820057596877054011573
d = 14053231445764110580607042223819107680391416143200240368020924470807783733946
x0bit = 1
y0 = 11
curve = TwistedEdwards(p, d, order, x0bit, y0)


# Generate key pairs
n_a, P_alice = gen_key_pair(curve)
n_b, P_bob = gen_key_pair(curve)

print(f"Alice sends public key: {P_alice}")
print(f"Bob sends public key: {P_bob}\n")


# Encrypted flag with shared secret
shared_secret = gen_shared_secret(curve, n_a, P_bob)
encrypted_flag = encrypt_flag(shared_secret)

print(f"Alice sends encrypted_flag: {encrypted_flag}")
