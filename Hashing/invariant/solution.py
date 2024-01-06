import telnetlib
import json

HOST = "socket.cryptohack.org"
PORT = 13393

tn = telnetlib.Telnet(HOST, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)


print(readline())

to_send = {
        "data": "76777776666666666666667767767676",
        "option": "hash"
    }
json_send(to_send)
received = json_recv()
print(received)