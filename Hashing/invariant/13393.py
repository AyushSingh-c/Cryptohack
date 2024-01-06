import itertools
import json
from hashlib import sha512
from utils import listener

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
            S = [S[i] ^ self.__subkeys[r][i] for i in range(16)]
            S = [self.__SB[S[self.__SR[i]]] for i in range(16)]
            X = [self.__xorAll(S[i:i + 4]) for i in range(0, 16, 4)]
            S = [X[c] ^ S[4 * c + r]
                 for c, r in itertools.product(range(4), range(4))]

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


class Challenge:
    def __init__(self):
        self.counter = 0
        self.before_input = "Can you cryptanalyse this cryptohash?\n"
        self.exit = True

    def hash(self, data):
        self.counter += 1
        return MyHash(data).digest()

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'hash':
            try:
                assert 'data' in your_input
                data = bytes.fromhex(your_input["data"])
                assert len(data) > 0
            except AssertionError:
                return {"error": "You must send hex data to be hashed"}

            h = self.hash(data)
            if h == b"\x00" * 8:
                return {"hash": h.hex(), "info": "Congratulations!", "flag": FLAG}
            elif h[:7] == b"\x00" * 7:
                return {"hash": h.hex(), "info": "You are so close!"}
            elif h[:6] == b"\x00" * 6:
                return {"hash": h.hex(), "info": "Almost there!"}
            elif h[:5] == b"\x00" * 5:
                return {"hash": h.hex(), "info": "This was easy, right?"}
            else:
                return {"hash": h.hex()}


listener.start_server(port=13393)
