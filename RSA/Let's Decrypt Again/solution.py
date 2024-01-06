#done
from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket
import json
from sage.all import *
import hashlib
import re
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse, isPrime
from pkcs1 import emsa_pkcs1_v15
import sympy
import random

####################################################### from problem implementation ######################################################
BTC_PAT = re.compile("^Please send all my money to ([1-9A-HJ-NP-Za-km-z]+)$")
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
BIT_LENGTH = 768
############################################################ setup socket ###################################################################
HOST = "socket.cryptohack.org"
PORT = 13394

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def readline():
    return sock.recv(1024).decode("utf-8")

def json_recv():
    line = readline()
    st = line[line.find('{'):]
    return json.loads(st)

def json_send(payload):
    request = json.dumps(payload).encode()
    sock.sendall(request)

############################################################ helping data ###################################################################
BTC_valid_addresses = []
file = open("./btc_samples.txt", "r")
for line in file:
    BTC_valid_addresses.append(line.strip())
file.close()

alpha = " ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

pattern_0 = []
pattern_1 =[]
pattern_2 = []

for i in BTC_valid_addresses:
    pattern_2.append(b"Please send all my money to " + i.encode("utf-8") )
for i in alpha:
    pattern_1.append(b"My name is " + i.encode("utf-8")  + b" and I own CryptoHack.org")
    pattern_0.append(b"This is a test " + i.encode("utf-8")  + b" for a fake signature.")

possible_patterns = [pattern_0, pattern_1, pattern_2]
final_patterns = []

possible_N = []
for i in range(10):
    p = getPrime(20)
    possible_N.append([p**40,[[p,40]]])

############################################################ helping functions ###################################################################
def get_sig_req():
    stri = '''{
            "option" : "get_signature"
        }'''
    json_send(json.loads(stri))
    return json_recv()

def set_pub_req(pubkey):
    stri = '''{
            "option" : "set_pubkey",
            "pubkey" : "''' + pubkey + '''"
        }'''
    json_send(json.loads(stri))
    return json_recv()

def claim_req(msg, e, index):
    stri = '''{
            "option" : "claim",
            "msg" : "''' + msg.decode() + '''",
            "e" : "''' + e + '''",
            "index" : ''' + index + '''
        }'''
    json_send(json.loads(stri))
    return json_recv()

def valid_msg(msg, index, N, E, suffix, SIGNATURE):
    if not (0 <= index < len(PATTERNS)):
        # print("invalid index")
        return False

    if not msg.endswith(suffix):
        # print("Invalid message")
        return False

    digest = emsa_pkcs1_v15.encode(msg, BIT_LENGTH // 8)
    calculated_digest = pow(SIGNATURE, E, N)

    if bytes_to_long(digest) == calculated_digest:
        r = PATTERNS[index](msg[:-len(suffix)].decode())
        if r:
            # print("Msg: ", msg, " is valid for index: ", index)
            return True
        else:
            # print("Ownership verified.")
            return False
    else:
        # print("Invalid signature")
        return False

def merge(d1, lis):
    temp = d1
    for p, e in lis:
        if p in temp:
            temp[p] += e
        else:
            temp[p] = e
    return temp

def get_B_smooth_prime(B):
    temp = 2
    prime = -1
    order_factors = []
    for _ in range(100):
        test_prime = sympy.randprime(0, B)
        e = random.randint(1,10)
        order_factors.append([test_prime, e])
        temp *= test_prime**e
        if is_prime(temp+1):
            prime = temp+1
            break
    return [prime, prime-1, order_factors]


def get_pohlig_hellman_modulus(base, bit_size):
    B = 1<<10   ##hyper parameter valid ~ O(root(B))
    modulus = 1
    field_order = 1
    order_factors = {}
    while modulus.bit_length() < bit_size:
        prime = get_B_smooth_prime(B)
        if prime[0].bit_length() < bit_size and prime[0] != -1 and gcd(base, prime[0]) == 1:
            modulus *= prime[0]
            field_order *= prime[1]
            order_factors = merge(order_factors, prime[2])
    return [modulus, field_order, order_factors]


#get x st b^x == a mod n
def pohlig_hellman(a, b, n, field_order, order_factors):
    G = IntegerModRing(n) 
    g = G(b) 
    h = G(a) 
    x = [] 
    for p, e in order_factors.items():
        pe = p**e
        a = g**(field_order//pe) 
        b = h**(field_order//pe) 
        x.append(discrete_log(b, a, ord=pe)) 
    return CRT(x, [p**e for p, e in order_factors.items()]) 

def find_valid_messages(SIGNATURE):
    result = 0
    n, field_order, order_factors = get_pohlig_hellman_modulus(SIGNATURE, 800)
    res = set_pub_req(hex(n))
    # print(res)
    if res['status'] != 'ok':
        print("error in setting pub key:", res)
        return
    suffix = res['suffix'].encode()
    for index in range(3):
        temp = []
        for msg in possible_patterns[index]:
            test_message = msg + suffix
            digest = emsa_pkcs1_v15.encode(test_message, BIT_LENGTH // 8)
            try: 
                e = pohlig_hellman(bytes_to_long(digest), SIGNATURE, n, field_order, order_factors)
            except:
                continue
            # print("possible e: ", e)
            if valid_msg(test_message, index, n, e, suffix, SIGNATURE):
                temp.append([test_message, e])
        final_patterns.append(temp)
        if len(temp) != 0:
            result += 1
    return result == 3


def get_flag():
    value = 0
    for index in range(3):
        res = claim_req(final_patterns[index][0][0], hex(final_patterns[index][0][1]), str(index))
        if res['msg'] == "Congratulations, here's a secret":
            value = value ^ int(res['secret'][2:], 16)
        else:
            print(res['msg'])
            return
    print("Flag: ", value.to_bytes((value.bit_length() + 7) // 8, byteorder='big'))

############################################################### get flag ##########################################################################
tries = 0
while True:
    tries += 1
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    final_patterns = []
    readline()
    res = get_sig_req()
    signature = int(res['signature'][2:], 16)

    guess = find_valid_messages(signature)
    if guess:
        get_flag()
        sock.close()
        break

    sock.close()
    print("Retrying............(for", tries, "times)")
