#!/usr/bin/env python3

import hashlib
import re
import secrets
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse, isPrime
from pkcs1 import emsa_pkcs1_v15
from utils import listener
# from params import N, E, D

FLAG = b"crypto{????????????????????????????????????}"

BIT_LENGTH = 768

MSG = b'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG, BIT_LENGTH // 8)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)
BTC_PAT = re.compile("^Please send all my money to ([1-9A-HJ-NP-Za-km-z]+)$")


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def btc_check(msg):
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    addr = BTC_PAT.match(msg)
    if not addr:
        return False
    addr = addr.group(1)
    raw = b"\0" * (len(addr) - len(addr.lstrip(alpha[0])))
    res = 0
    for c in addr:
        res *= 58
        res += alpha.index(c)
    raw += long_to_bytes(res)

    if len(raw) != 25:
        return False
    if raw[0] not in [0, 5]:
        return False
    return raw[-4:] == hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]


PATTERNS = [
    re.compile(r"^This is a test(.*)for a fake signature.$").match,
    re.compile(r"^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$").match,
    btc_check
]


class Challenge():
    def __init__(self):
        self.shares = [secrets.token_bytes(len(FLAG))
                       for _ in range(len(PATTERNS) - 1)]
        last_share = FLAG
        for s in self.shares:
            last_share = xor(last_share, s)
        self.shares.append(last_share)

        self.pubkey = None
        self.suffix = None

        self.before_input = "This server validates statements we make for you. Present your messages and public key, and if the signature matches ours, you must undoubtably be us. Just do it multiple times to make sure...\n"

    def challenge(self, your_input):
        if not 'option' in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'get_signature':
            return {
                "N": hex(N),
                "E": hex(E),
                "signature": hex(SIGNATURE)
            }

        elif your_input['option'] == 'set_pubkey':
            if self.pubkey is None:
                pubkey = int(your_input['pubkey'], 16)
                if isPrime(pubkey):
                    return {"error": "Everyone knows RSA keys are not primes..."}
                self.pubkey = pubkey
                self.suffix = secrets.token_hex(32)

                return {"status": "ok", "suffix": self.suffix}
            return {"error": "I already had one"}

        elif your_input['option'] == 'claim':
            if self.pubkey is None:
                return {"error": "I need your modulus first, please"}

            msg = your_input['msg']
            n = self.pubkey
            e = int(your_input['e'], 16)
            index = your_input['index']
            if not (0 <= index < len(PATTERNS)):
                return {"error": "invalid index"}

            if not msg.endswith(self.suffix):
                return {"error": "Invalid message"}

            digest = emsa_pkcs1_v15.encode(msg.encode(), BIT_LENGTH // 8)
            calculated_digest = pow(SIGNATURE, e, n)

            if bytes_to_long(digest) == calculated_digest:
                r = PATTERNS[index](msg[:-len(self.suffix)])
                if r:
                    return {"msg": "Congratulations, here's a secret", "secret": self.shares[index].hex()}
                else:
                    return {"msg": "Ownership verified."}
            else:
                return {"error": "Invalid signature"}

        else:
            return {"error": "Invalid option"}


listener.start_server(port=13394)
