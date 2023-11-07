from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
from Crypto.Util.number import getPrime, GCD, bytes_to_long, long_to_bytes, inverse
from random import randint

FLAG = b'crypto{????????????????????????????????}'

p, q = getPrime(512), getPrime(512)
n = p * q

# Alice side
v = (p * randint(1, n)) % n
k_A = randint(1, n)
while GCD(k_A, n) != 1:
    k_A = randint(1, n)
vka = (v * k_A) % n

# Bob side
k_B = randint(1, n)
while GCD(k_B, n) != 1:
    k_B = randint(1, n)
vkakb = (vka * k_B) % n

# Alice side
vkb = (vkakb * inverse(k_A, n)) % n

# Bob side
v_s = (vkb * inverse(k_B, n)) % n

# Alice side
key = sha256(long_to_bytes(v)).digest()
cipher = AES.new(key, AES.MODE_ECB)
m = pad(FLAG, 16)
c = cipher.encrypt(m).hex()

out = ""
out += f"p, q = ({p}, {q}) \n"
out += f"vka = {vka} \n"
out += f"vkakb = {vkakb} \n"
out += f"vkb = {vkb} \n"
out += f"c = '{c}' \n"
with open("out.txt", "w") as f:
    f.write(out)
