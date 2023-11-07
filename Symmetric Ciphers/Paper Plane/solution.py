import json
import requests 
from pwn import xor 
from tqdm import tqdm

# decrypts ct^m0
def decryptionOracle(ct, m0, c0):
    print("Starting Oracle: ")
    plainText = b''

    for i in tqdm(range(1, 17), desc="outer loop", position=0, leave=True):
        temp = c0[:(16 - i)]
        pad = b''
        
        for j in tqdm(range(256), desc="inner loop", position=1, leave=False):
            guess = bytes([c0[(16 - i)] ^ j])
            if len(plainText) > 0:
                pad = bytes([i]) * (i - 1)
                c0_pad = temp + guess + xor(xor(plainText, pad), c0[(17 - i):])
            else:
                c0_pad = temp + guess    
            
            r = requests.get('https://aes.cryptohack.org/paper_plane/send_msg/' 
                             + ct.hex() + "/" 
                             + m0.hex() + "/" 
                             + c0_pad.hex())
            
            if 'Message received' in r.text:
                if i == 1 and j == 0:
                    continue
                plainText = bytes([i ^ j]) + plainText
                print("Decrypted Text....: ", plainText)
                break

    return plainText



r = requests.get('https://aes.cryptohack.org/paper_plane/encrypt_flag')
encrypted_flag = json.loads(r.text)

ct = bytes.fromhex(encrypted_flag['ciphertext'])
m0 = bytes.fromhex(encrypted_flag['m0'])
c0 = bytes.fromhex(encrypted_flag['c0'])


x = ct[:16]
a = decryptionOracle(x, m0, c0)

y = ct[16:]
b = decryptionOracle(y, a, x)

print("Flag:", a + b)