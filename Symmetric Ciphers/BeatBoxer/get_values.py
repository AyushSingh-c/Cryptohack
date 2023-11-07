#done
from Crypto.Util.number import bytes_to_long, long_to_bytes
import socket
import json
from sage.all import *
############################################################setup socket###################################################################
HOST = "socket.cryptohack.org"
PORT = 13406

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

############################################################helping functions###################################################################
def send_encrypt_req(msg):
    stri = '''{
            "option" : "encrypt_message",
            "message" : "''' + msg + '''"
        }'''
    json_send(json.loads(stri))
    return (json_recv()['encrypted_message'])

def send_flag_encrypt_req():
    stri = '''{
            "option" : "encrypt_flag"
        }'''
    json_send(json.loads(stri))
    return (json_recv()['encrypted_flag'])
###############################################################get data##########################################################################

def get_data(msg):
    sock.connect((HOST, PORT))
    readline()

    msg = "".join([str(i) for i in msg])
    ciphertext = send_encrypt_req(msg)
    flag_enc = send_flag_encrypt_req()

    sock.close()

    return [i for i in bytes.fromhex(ciphertext)], [i for i in bytes.fromhex(flag_enc)]
