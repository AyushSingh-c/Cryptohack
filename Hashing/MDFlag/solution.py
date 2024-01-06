import numpy as np
from pwn import *
import json 

# Implementation from https://www.youtube.com/watch?v=HWpaz5XsECc
# choose this because this generates the same hash as Python hashlib MD5 implementation

# ----- BEGIN IMPLEMENTATION OF MD5 -----
shift = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

sines = np.abs(np.sin(np.arange(64) + 1))  # "nothing up my sleeve" randomness
sine_randomness = [int(x) for x in np.floor(2 ** 32 * sines)]

md5_block_size = 64
md5_digest_size = 16

def left_rotate(x: int, y: int) -> int:
    """
    Rotate the bits of x by y places, as if x and y are 32-bit unsigned integers.
    >>> left_rotate(0b11111111000000001010101011001100, 1) == \
                    0b11111110000000010101010110011001
    True
    """
    return ((x << (y & 31)) | ((x & 0xffffffff) >> (32 - (y & 31)))) & 0xffffffff


def bit_not(x: int) -> int:
    """
    The bitwise complement of x if x were represented as a 32-bit unsigned integer.
    >>> bit_not(0b11111111000000001010101011001100) == \
                0b00000000111111110101010100110011
    True
    """
    return 4294967295 - x


"""
Mixing functions. 
Each of F, G, H, I has the following property.
Given: all the bits of all the inputs are independent and unbiased,
Then: the bits of the output are also independent and unbiased.
"""

def F(b: int, c: int, d: int) -> int:
    return d ^ (b & (c ^ d))

def G(b: int, c: int, d: int) -> int:
    return c ^ (d & (b ^ c))

def H(b: int, c: int, d: int) -> int:
    return b ^ c ^ d

def I(b: int, c: int, d: int) -> int:
    return c ^ (b | bit_not(d))

mixer_for_step = [F for _ in range(16)] + [G for _ in range(16)] + [H for _ in range(16)] + [I for _ in range(16)]

"""
These are all permutations of [0, ..., 15].
"""

round_1_perm = [i for i in range(16)]  # [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
round_2_perm = [(5 * i + 1) % 16 for i in range(16)]  # [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
round_3_perm = [(3 * i + 5) % 16 for i in range(16)]  # [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2]
round_4_perm = [(7 * i) % 16 for i in range(16)]  # [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]

msg_idx_for_step = round_1_perm + round_2_perm + round_3_perm + round_4_perm

class MD5:
    def __init__(self):
        self.length: int = 0
        self.state: tuple[int, int, int, int] = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
        self.message: bytes = None 
    
    def digest(self) -> bytes:
        return b''.join(x.to_bytes(length=4, byteorder='little') for x in self.state)

    def hex_digest(self) -> str:
        return self.digest().hex()
    
    # Message padding, following what is in Wikipedia MD5 algorithm
    # https://en.wikipedia.org/wiki/MD5
    def pad(self, message):
        self.message = message 
        self.length = (len(message) * 8) % (2 ** 64)

        pad = message + b'\x80'
        while len(pad) % 64 != 56:
            pad += b'\x00'
        
        pad += self.length.to_bytes(length=8, byteorder='little')

        return pad 

    # The compression function, takes in a chunk of 64 bytes and output the hash from 
    # the block and current state
    def compress(self, msg_chunk: bytearray) -> None:
        assert len(msg_chunk) == md5_block_size  # 64 bytes, 512 bits
        msg_ints = [int.from_bytes(msg_chunk[i:i + 4], byteorder='little') for i in range(0, md5_block_size, 4)]
        assert len(msg_ints) == 16

        a, b, c, d = self.state

        for i in range(md5_block_size):
            bit_mixer = mixer_for_step[i]
            msg_idx = msg_idx_for_step[i]
            a = (a + bit_mixer(b, c, d) + msg_ints[msg_idx] + sine_randomness[i]) % (2 ** 32)
            a = left_rotate(a, shift[i])
            a = (a + b) % (2 ** 32)
            a, b, c, d = d, a, b, c
        
        self.state = (
            (self.state[0] + a) % (2 ** 32),
            (self.state[1] + b) % (2 ** 32),
            (self.state[2] + c) % (2 ** 32),
            (self.state[3] + d) % (2 ** 32),
        )

    # Load the state of the previous blocks from the given hash
    def load_state(self, hash):
        registers = [0, 0, 0, 0]

        for i in range(len(registers)):
            registers[i] = int.from_bytes(bytes.fromhex(hash[8 * i: 8 * (i + 1)]), byteorder='little')
        self.state = tuple(registers)

# ----- END IMPLEMENTATION OF MD5 -----

# Initialize the MD5 hash generation and the "dummy" flag
m = MD5()

# Dummy flag to use for the dummy padding, only purpose is to extract the extension 
# in particular, the \x80 byte and the little endian representation of the length of 
# the message in bits
FLAG = b'crypto{??????????????????????????????????????}'

# All ASCII characters
chars = [chr(i) for i in range(32, 127)]

# Generate what the flag should look like with the underneath payload
dummy = FLAG * 3 + FLAG[:-1]

# Any bytes of length len(dummy) works, I choose the \x00 byte
payload = b'\x00' * len(dummy)

# Connect to server
io = remote('socket.cryptohack.org', 13407)
io.recvline()
to_send = {'option': 'message', 'data': payload.hex()}
io.sendline(json.dumps(to_send).encode())

# The secret block where we have no control over the text in
secret_blk = json.loads(io.recvline().decode())['hash']

# Get extension (the padding of \x80, followed by some \x00 and 
# the length of the message) for hash-extension attack
dummy_pad = m.pad(dummy)
extension = dummy_pad[-9:]
payload += xor(extension[:8], b'}' + FLAG[:7])

# Guess out first character after the {, for the payload to be 64-byte aligned
# The aim is to generate a block where the extension is of the form \x80 + length of the message
dummy_pad_extend = m.pad(dummy_pad)

# Load the state of the secret block to compare
m.load_state(secret_blk)

# The hash is the state update on the extension block
m.compress(dummy_pad_extend[64 * 3:])
target = m.hex_digest()

FLAG = 'crypto{'

# Guess out the character after the { character
for char in chars: 
    guess = payload + char.encode()
    to_send = {'option': 'message', 'data': guess.hex()}
    io.sendline(json.dumps(to_send).encode())
    hash = json.loads(io.recvline().decode())['hash']
    if hash == target:
        payload = guess 
        FLAG += char
        break

print(FLAG)

# Now we guess the character as we know the state before the last block, 
# the eventual hash can be requested from the server. Hence the task is 
# just to calculate the hash on our end and see which character produces the same hash
for i in range(38):
    payload += b'\x00' # \x00 byte here as we want to preserve the character of the flag
    to_send = {'option': 'message', 'data': payload.hex()}
    io.sendline(json.dumps(to_send).encode())
    target = json.loads(io.recvline().decode())['hash']

    # Guessing out which character produces the same hash
    for char in chars:  
        m = MD5()
        m.load_state(secret_blk)
        # guessing the characters in the final block
        guess = m.pad(dummy_pad + FLAG[8:].encode() + char.encode()) 

        # Again, same thing as above, the hash is the state update of the compression
        m.compress(guess[64 * 3:])
        guess_hash = m.hex_digest()
        if guess_hash == target:
            FLAG += char 
            print(FLAG)
            break 
    