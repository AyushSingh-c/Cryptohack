import itertools
import random
from hashlib import sha512
FLAG = "crypto{????????????????????????????????}"


class MyCipher:
    __NR = 31
    __SB = [13, 14, 0, 1, 5, 10, 7, 6, 11, 3, 9, 12, 15, 8, 2, 4]
    __SR = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

    def __init__(self, key):
        self.__RK = int(key.hex(), 16)
        self.__subkeys = [[(self.__RK >> (16 * j + i)) & 1 for i in range(16)]
                          for j in range(self.__NR + 1)]

    def __xorAll(self, v):
        res = 0
        for x in v:
            res ^= x
        return res

    def encrypt(self, plaintext):
        assert len(plaintext) == 8, "Error: the plaintext must contains 64 bits."

        S = [int(_, 16) for _ in list(plaintext.hex())]

        for r in range(self.__NR):
            # print("\niter: ", r, "\n S start: ", S)
            S = [S[i] ^ self.__subkeys[r][i] for i in range(16)]
            S = [self.__SB[S[self.__SR[i]]] for i in range(16)]
            X = [self.__xorAll(S[i:i + 4]) for i in range(0, 16, 4)]
            S = [X[c] ^ S[4 * c + r]
                 for c, r in itertools.product(range(4), range(4))]
            # print("S end: ", S)

        S = [S[i] ^ self.__subkeys[self.__NR][i] for i in range(16)]
        return bytes.fromhex("".join("{:x}".format(_) for _ in S))

class MyHash:
    def __init__(self, content):
        self.cipher = MyCipher(sha512(content).digest())
        self.h = b"\x00" * 8
        self._update(content)

    def _update(self, content):
        while len(content) % 8:
            content += b"\x00"
        for i in range(0, len(content), 8):
            self.h = bytes(x ^ y for x, y in zip(self.h, content[i:i+8]))
            self.h = self.cipher.encrypt(self.h)
            self.h = bytes(x ^ y for x, y in zip(self.h, content[i:i+8]))

    def digest(self):
        return self.h

    def hexdigest(self):
        return self.h.hex()

def split_num(num):
    return num>>4, num%(1<<4)
def merge_num(num):
    return (num[0]<<4)+num[1]
def gen_input_list(num):
    binary = format(num, "016b")
    bit_list = list(binary)
    return [(6^int(bit_list[i]), 6^int(bit_list[i+1])) for i in range(0, len(bit_list), 2)]
def get_random_input_list():
    binary_list = []
    for i in range(16):
        bit = random.randint(0, 1)
        binary_list.append(bit)
    return [(6^int(binary_list[i]), 6^int(binary_list[i+1])) for i in range(0, len(binary_list), 2)]

for _ in range(10):
    random_input_list = get_random_input_list()
    print("random_input_list: ", random_input_list)
    for i in range(1<<16):
        input_list = gen_input_list(i)
        data = bytes([merge_num(num) for num in random_input_list]) + bytes([merge_num(num) for num in input_list])
        hash_list = [split_num(num) for num in list(map(int,MyHash(data).digest()))]
        count = 0
        for j in range(8):
            if hash_list[j] == (0, 0):
                count+=1
        if count>7:
            print("value: ", i)
            print("input_list: ", input_list)
            print("random_input_list: ", random_input_list)
            print("hash: ", hash_list)
