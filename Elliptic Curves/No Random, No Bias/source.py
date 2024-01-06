from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint

G = generator_256
q = G.order()

FLAG = b'crypto{??????????????????}'


def hide_flag(privkey):
    x = bytes_to_long(FLAG)
    p = curve_256.p()
    b = curve_256.b()
    ysqr = (x**3 - 3*x + b) % p
    y = pow(ysqr, (p+3)//4, p)
    Q = ellipticcurve.Point(curve_256, x, y)
    T = privkey.secret_multiplier*Q
    return (int(T.x()), int(T.y()))


def genKeyPair():
    d = randint(1,q-1)
    pubkey = Public_key(G, d*G)
    privkey = Private_key(pubkey, d)
    return pubkey, privkey


def ecdsa_sign(msg, privkey):
    hsh = sha1(msg.encode()).digest()
    nonce = sha1(long_to_bytes(privkey.secret_multiplier) + hsh).digest()
    sig = privkey.sign(bytes_to_long(hsh), bytes_to_long(nonce))
    return {"msg": msg, "r": hex(sig.r), "s": hex(sig.s)}



pubkey, privkey = genKeyPair()
hidden_flag = hide_flag(privkey)

sig1 = ecdsa_sign('I have hidden the secret flag as a point of an elliptic curve using my private key.', privkey)
sig2 = ecdsa_sign('The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', privkey)
sig3 = ecdsa_sign('Good luck!', privkey)

print('Hidden flag:', hidden_flag)
print('\nPublic key:', (int(pubkey.point.x()), int(pubkey.point.y())), '\n')
print(sig1)
print(sig2)
print(sig3)
