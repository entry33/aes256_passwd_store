# Author: https://github.com/c0dy-c0des
from sys import exit
from Crypto.Protocol.KDF import scrypt
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes

def aes_encrypt(cipher, pt):
	# Pad to 16 byte boundary and encrpyt.
	padded_data = pad(pt.encode(), 16)
	return cipher.encrypt(padded_data)

def validate_mpass(padded_data):
	try:
		return unpad(padded_data, 16).decode()
	except ValueError:
		exit('\n**ACCESS DENIED**: Key/master password is incorrect!\n')

def aes_decrypt(cipher, ct):
	# Decrypt the cipher-text and finally unpad the plain-text data.
	padded_data = cipher.decrypt(ct)
	return validate_mpass(padded_data)

class Aes_scrypt:
	def __init__(self, passwd):
		self.passwd = passwd

	# Generate scrypt hash to build AES cipher object.
	def __build_cipher(self, salt):
		scrypt_cost = 20
		key = scrypt(self.passwd, salt, 32, N=2**scrypt_cost, r=8, p=1)
		return AES.new(key, AES.MODE_ECB)

	def encrypt(self, pt):
		# Generate random salt.
		salt = get_random_bytes(32)

		# Instantiate a AES-256 cipher object.
		cipher = self.__build_cipher(salt)

		# Base64 encode the salt bytes to prevent the salt from interfering with Data_handler.__db_read()'s data parsing.
		b64_salt = b64encode(salt)
		ct = aes_encrypt(cipher, pt)
		return b64_salt + b'\r\n' + ct

	def decrypt(self, file_data):
		# Parse salt and cipher-text.
		b64_salt, ct = file_data.split(b'\r\n', 1)
		salt = b64decode(b64_salt)

		# Instantiate a AES-256 cipher object.
		cipher = self.__build_cipher(salt)

		return aes_decrypt(cipher, ct)

class Aes_sha256:
	def __init__(self, passwd):
		self.passwd = passwd.encode()
		key = sha256(self.passwd).digest()
		self.cipher = AES.new(key, AES.MODE_ECB)

	def encrypt(self, pt):
		return aes_encrypt(self.cipher, pt)

	def decrypt(self, ct):
		# Decrypt the cipher-text and finally unpad the plain-text data.
		return aes_decrypt(self.cipher, ct)

def aes_cipher(alg, passwd):
	alg_dict = {
		'scrypt': Aes_scrypt,
		'sha256': Aes_sha256,
		}
	try:
		target_class = alg_dict[alg]
		return target_class(passwd)
	except KeyError:
		exit('Invalid encryption algorithm: ' + alg +' use -h/--help for examples.')
