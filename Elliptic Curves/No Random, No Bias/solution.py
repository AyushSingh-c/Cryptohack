from hashlib import sha1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa.ecdsa import curve_256, generator_256
from ecdsa import ellipticcurve
from sage.all import *

# curve-256 order
n = int(generator_256.order())

# Known signed messages
msg1 = {'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.', 'r': '0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae', 's': '0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d'}
msg2 = {'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.', 'r': '0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c', 's': '0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8'}
msg3 = {'msg': 'Good luck!', 'r': '0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6', 's': '0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba'}

known = [msg1, msg2, msg3]
msgs = []
sigs = []

for msg in known: 
    msg_hsh = bytes_to_long(sha1(msg['msg'].encode()).digest())
    msgs.append(msg_hsh)
    msg_sigs = (int(msg['r'], 16), int(msg['s'], 16))
    sigs.append(msg_sigs)

# Make the matrix in the paper, also covered in the first example (with 2 messages) in the TrailOfBits article
# was having trouble with setting up the matrix with the Github script
def make_matrix():
    (r1, s1), (r2, s2), (r3, s3) = sigs
    m1, m2, m3 = msgs

    t1 = r1 * inverse_mod(s1, n)
    t2 = r2 * inverse_mod(s2, n)
    t3 = r3 * inverse_mod(s3, n)

    a1 = m1 * inverse_mod(s1, n)
    a2 = m2 * inverse_mod(s2, n)
    a3 = m3 * inverse_mod(s3, n)

    basis = [ [n,           0,           0,            0,                  0],
              [0,           n,           0,            0,                  0],
              [0,           0,           n,            0,                  0],
              [t1,          t2,          t3,           (2**160) / n,       0],
              [a1,          a2,          a3,           0,             2**160]
             ]
    return Matrix(QQ, basis)

# Size of the nonce is 160 bits
B = 160
matrix = make_matrix()

# LLL to find the possible key
new_matrix = matrix.LLL(early_red=True, use_siegel=True)

# Retrieve the secret from the known nonce
r1_inv = pow(sigs[0][0], -1, n)
s1 = sigs[0][1]
G = generator_256

# Target is the public key
target = (48780765048182146279105449292746800142985733726316629478905429239240156048277, 74172919609718191102228451394074168154654001177799772446328904575002795731796)

d = 0
for row in new_matrix:
    potential_nonce_1 = row[0]
    potential_priv_key = r1_inv * ((potential_nonce_1 * s1) - msgs[0])

    possible = G * potential_priv_key
    possible = (possible.x(), possible.y())

    if possible == target:
        d = potential_priv_key

enc_flag = (16807196250009982482930925323199249441776811719221084165690521045921016398804, 72892323560996016030675756815328265928288098939353836408589138718802282948311)
enc_flag = ellipticcurve.Point(curve_256, enc_flag[0], enc_flag[1])

# Obtain the flag trivially
flag = enc_flag * inverse_mod(d, n)
print(long_to_bytes(int(flag.x())))