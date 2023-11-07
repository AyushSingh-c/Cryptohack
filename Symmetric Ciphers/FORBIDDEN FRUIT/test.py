from Crypto.Cipher import AES
from os import urandom
import struct

def xor(s1, s2):
	"""
	XOR two strings s1, s2
	Strings s1 and s2 need not be of equal length
	Whatever be the length of two strings, the longer string will be sliced
	to a string of length equal to that of the shorter string 
	"""
	if len(s1) == len(s2):
		return "".join(chr(ord(i) ^ ord(j)) for i, j in zip(s1, s2))
	elif len(s1) > len(s2):
		return "".join(chr(ord(i) ^ ord(j)) for i, j in zip(s1[:len(s2)], s2))
	elif len(s1) < len(s2):
		return "".join(chr(ord(i) ^ ord(j)) for i, j in zip(s1, s2[:len(s1)]))

def str2bin(s1):
	"""
	Convert an ASCII string to corresponding binary string
	"""	
	char_list = [bin(ord(i))[2:].zfill(8) for i in s1]
	return "".join(char_list)

def bin2str(s1):
	"""
	Convert a binary string to corresponding ASCII string
	"""
	for i in s1:
		assert i == "0" or i == "1"
	bin_list = [int(s1[i:i+8], 2) for i in range(0, len(s1), 8)]
	for i in bin_list:
		assert i < 256
	bin_list = [chr(i) for i in bin_list]
	return "".join(bin_list)

def str2int(s1):
	"""
	Convert an ASCII string to it's corresponding integer format
	"""
	return int(s1.encode("hex"), 16)

def int2str(i):
	"""
	Convert an integer to corresponding ASCII string
	"""
	return hex(i)[2:].replace("L","").decode("hex")

def pad(s1):
	"""
	Pad a string to make it a multiple of blocksize. 
	If the string is already a multiple of blocksize, then simply return the string
	"""
	if len(s1) % 16 == 0:
		return s1
	else:
		return s1 + "\x00"*(16 - len(s1) % 16)


class AES_GCM:
	"""
	Implementation of encryption/decryption in AES_GCM using AES_ECB of pycrypto
	"""
	def __init__(self, key, nonce, associated_data):
		"""
		Initialising key for cipher object
		"""
		try:
			assert len(key) == 16 or len(key) == 24 or len(key) == 32
			assert len(nonce) == 12
			self.key = key
			self.nonce = nonce
			self.associated_data = associated_data + (b'\x00' * (-len(associated_data) % 16)) 
		except:
			raise ValueError("[+] Key length must be of length 16, 24 or 32 bytes and nonce must be of size 12 bytes", len(key))
	
	def _encrypt(self, plaintext):
		"""
		Encryption of plaintext using key and nonce in CTR mode
		96 bit nonce and 32 bit counter starting from 1
		"""
		plaintext = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
		ciphertext = ""
		for i in range(len(plaintext)):
			construct_nctr = bin2str(str2bin(self.nonce) + bin(pow(i+1, 1, 2**32))[2:].zfill(32))
			assert len(construct_nctr) == 16
			obj1 = AES.new(self.key, AES.MODE_ECB)
			print(bytes(construct_nctr, 'utf-8').hex())
			ct = obj1.encrypt(construct_nctr)
			ciphertext += xor(plaintext[i], ct)
		return ciphertext

	def mod_polynomial_mult(self, a, b, p):
		"""
		Multiplication of polynomials a.b modulo an irreducible polynomial p over GF(2**128)
		Assertion: a, b must already belong to the Galois Field GF(2**128)
		"""
		assert len(bin(a)[2:]) <= 128
		assert len(bin(b)[2:]) <= 128
		result = 0
		for i in bin(b)[2:]:
			result = result << 1
			if int(i):
				result = result ^ a
			if result >> 128:
				result = result ^ p
		return result

	def authtag_gen(self, ciphertext1):
		"""
		Generating auth-tag using ciphertext and associated data 
		"""
		ciphertext = [(ciphertext1[i:i+16]) for i in range(0, len(ciphertext1), 16)]
		associated_data = [(self.associated_data[i:i+16]) for i in range(0, len(self.associated_data), 16)]

		obj1 = AES.new(self.key, AES.MODE_ECB)

		# Step-1: Secret String Generation
		H = (obj1.encrypt(b"\x00"*16))
		X = 0
		p = (1<<128) + (1<<7) + (1<<2) + (1<<1) + 1
		
		# Step-2: Modular Polynomial Multiplication of Associated Data blocks with H
		for i in range(len(associated_data)):
			X = self.mod_polynomial_mult(X, int.from_bytes(associated_data[i], "big"), p)

		# Step-3: Modular Polynomial Multiplication of Ciphertext blocks with H
		for i in range(len(ciphertext)):
			X = self.mod_polynomial_mult(X, int.from_bytes(ciphertext[i], "big"), p)

		# Step-4: Modular Polynomial Multiplication of H with (bit length of A concatenated with bit length of C)
		# la = bin(len(self.associated_data))[2:].zfill(64)
		# lc = bin(len(ciphertext1))[2:].zfill(64)
		# res = int(la + lc, 2)
		res = struct.pack('>2Q', 8*len(self.associated_data), 8*len(ciphertext1))  
		S = self.mod_polynomial_mult(X, int.from_bytes(res, "big"), p)

		# Step-5: XORing S with E(J0) ie. XORing S obtained above with ciphertext of (iv || ctr)
		obj1 = AES.new(self.key, AES.MODE_ECB) 
		construct_nctr = self.nonce + b'\x00'*4
		T = S ^ int.from_bytes(obj1.encrypt(construct_nctr), "big")
		
		return hex(T)


	def _decrypt(self, ciphertext):
		"""
		Decryption of ciphertext using key and nonce in CTR mode
		96 bit nonce and 32 bit counter starting from 1
		"""
		ciphertext = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
		plaintext = ""
		for i in range(len(ciphertext)):
			construct_nctr = bin2str(str2bin(self.nonce) + bin(pow(i+1, 1, 2**32))[2:].zfill(32))
			assert len(construct_nctr) == 16
			obj1 = AES.new(self.key, AES.MODE_ECB)
			pt = obj1.encrypt(construct_nctr)
			plaintext += xor(ciphertext[i], pt)
		return plaintext
	


IV = bytes.fromhex("88276c4db3b315358d61708f")
KEY = bytes.fromhex("041e501690830c7af350dc70adb93491")
header = b"CryptoHack"
plaintext = b'a'*16
cipher = bytes.fromhex("a02de463a294b903b3ae556340b6a0a2")

AES_code = AES_GCM(KEY, IV, header)
print(AES_code.authtag_gen(cipher))
print(AES_code.authtag_gen(IV+cipher))
