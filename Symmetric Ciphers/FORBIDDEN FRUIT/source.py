from Crypto.Cipher import AES
import os
from sage.all import *
import struct


IV = bytes.fromhex("88276c4db3b315358d61708f")
KEY = bytes.fromhex("041e501690830c7af350dc70adb93491")
FLAG = b"crypto{false_flag}"

def generate_tag(associated_data, plaintext, ciphertext):
    associated_data = bytes.fromhex(associated_data)
    plaintext = bytes.fromhex(plaintext)
    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(KEY, AES.MODE_ECB)
    h = cipher.encrypt(b'\x00'*16)
    s = cipher.encrypt(IV + b'\x00'*3 + b'\x01')
    # print("H: ", h.hex(), "\nS: ", s.hex(), "\nKEY: ", KEY.hex())
    encrypted = IV+ciphertext

    content = associated_data + (b'\x00' * (-len(associated_data) % 16)) 
    content += encrypted + (b'\x00' * (-len(encrypted) % 16))
    content += struct.pack('>2Q', 8*len(associated_data), 8*len(encrypted))          #is it in bits or bytes
                
    K = FiniteField(2**128, name='x')
    g = K.zero()
    h = K.from_integer(int.from_bytes(h, 'big'))
    s = K.from_integer(int.from_bytes(s, 'big'))
    for i in range(0, len(content), 16):
        b = K.from_integer(int.from_bytes(content[i : i + 16], 'big'))
        g += b
        g *= h
        # print("\nB: ", hex(b.to_integer()), "\nG: ", hex(g.to_integer()))
    g += s
    print("H: ", hex((h).to_integer()), "\nS: ", hex(s.to_integer()),"\nG: ", hex(g.to_integer()), "\nContent: ", content.hex())
    return g


def encrypt(plaintext):
    plaintext = bytes.fromhex(plaintext)
    header = b"CryptoHack"

    cipher = AES.new(KEY, AES.MODE_GCM, nonce=IV)
    encrypted = cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    if b'flag' in plaintext:
        return {
            "error": "Invalid plaintext, not authenticating",
            "ciphertext": ciphertext.hex(),
        }

    return {
        "nonce": IV.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "associated_data": header.hex()
    }

def compare_tag(plaintext):
    enc = encrypt(plaintext)
    print(enc)

    tag_gen = generate_tag(enc["associated_data"], plaintext, enc["ciphertext"])
    tag_ac = enc["tag"]

    print("plaintext: ", plaintext)
    print("ciphertext: ", enc["ciphertext"])
    print("my tag: ",hex(tag_gen.to_integer())[2:])
    bytes.fromhex(tag_ac)
    print("python tag: ", tag_ac)

    return tag_gen

tag1 = compare_tag("61"*15 + "00")
tag2 = compare_tag("61"*15 + "01")

print("tag sum", hex((tag1+tag2).to_integer())[2:])

K = FiniteField(2**128, name='x')
cipher = AES.new(KEY, AES.MODE_ECB)
h = cipher.encrypt(b'\x00'*16)
h = K.from_integer(int.from_bytes(h, 'big'))
h = h**3
h *= 0x100000000

print(hex((h).to_integer()))


# plaintext = "61"*15 + "62"
# enc = encrypt(plaintext)
# print(enc)

# tag_gen2 = generate_tag(enc["associated_data"], plaintext, enc["ciphertext"])
# tag_ac2 = enc["tag"]

# x = tag_gen1 + tag_gen2
# print(hex(x.to_integer()))
# print(hex(int(tag_ac1, 16)^int(tag_ac2,16)))

    
    # R = PolynomialRing(GF(2**128),'x')
    # x = R.gen()
    # S = R.quotient(x**128 + x**7 + x**2 + x + 1)
    # a = S.gen()
    # print(a)041e501690830c7af350dc70adb93491

# K = FiniteField(2**128, name='x')
# g1 = K.from_integer(1)
# g2 = K.from_integer(2)

# print(g1+g2)

