# Author: https://github.com/c0dy-c0des
from argparse import ArgumentParser
from getpass import getpass
from sys import argv, exit

# Hashing algorithm parser + aes cipher object builder
from lib.aes_objects import aes_cipher

# Object to provide file io methods.
from lib.file_io import File_io

# Parsing functions. 
from lib.parsing import *

def parse_args():
	parser = ArgumentParser(description='Password encryptor/decryptor, store passwords securely on disk.')
	parser.add_argument('-a', '--algorithm', type=str, required=True,
	                    help='Key derivation algorithm to hash master password with. Available hashing algorithms: scrypt, sha256')
	parser.add_argument('-c', '--create', type=str, required=False,
	                    help='Create a database file and write encrypted data to it.')
	parser.add_argument('-cp', '--change_pass', type=str, required=False,
	                    help='Change database file\'s master password.')
	parser.add_argument('-e', '--edit', type=str, required=False,
	                    help='Write data to a encrypted database file.')
	parser.add_argument('-q', '--query', type=str, required=False,
	                    help='Dump all data or query data within database file based on unique password identifier(s).')
	return parser.parse_args()

def passwd_confirm(passwd):
	# Check if passwords match.
	tmp_passwd = getpass(prompt='Re-enter password: ')
	if tmp_passwd != passwd:
		exit('**ERROR**: Passwords do not match.')

# Class to handle encryption/decryption along with IO + parsing.
class Data_handler:
	filename = None

	def __init__(self, alg, passwd):
		# Generate our aes object.
		self.alg = alg
		self.aes = aes_cipher(alg, passwd)
		self.file_io = File_io(Data_handler.filename)

	# Open, read and decrypt the db file.
	def __db_read(self):
		# Read the database file's bytes.
		file_data = self.file_io.read_file()

		# Return decrypted the cipher-text
		return self.aes.decrypt(file_data)

	# Write encrypted data to a database file.
	def __db_write(self, data, format_flag=True):
		# If the data is a dictionary:
		if format_flag:
			# Format data to pass_id=pass\n format
			data = format_data(data)

		# Encrypt the data and write its salt + data to a database file.
		enc_list = self.aes.encrypt(data)
		self.file_io.write_file(enc_list)

	# Create file handler.
	def create_file(self):
		# Get data to be quired from stdin.
		pt = read_lines("Enter/paste data in pass_id=password format and press Ctrl-D or Ctrl-Z (Windows) to save the file:")

		# Parse data.
		data_dict = parse_data(pt)

		# Encrypt parsed data and write to a database file.
		self.__db_write(data_dict)

	# Edit a database file.
	def change_passwd(self):
		# Decrypt database file data.
		pt = self.__db_read()

		# Get new password and validate it.
		new_passwd = getpass(prompt='Enter new master password to encrypt/decrypt the database file\'s data: ')
		passwd_confirm(new_passwd)

		# Wipe previous file data:
		self.file_io.wipe_dbfile()

		# Generate a new aes object to encrypt our previously decrypted data.
		self.aes = aes_cipher(self.alg, new_passwd)

		# Write the encrypted bytes to the database file.
		self.__db_write(pt, False)

	# Edit a database file.
	def edit_file(self):
		# Decrypt database file data.
		pt = self.__db_read()

		# Get new key,value pairs from stdin.
		pt += read_lines('Enter/paste new data in pass_id=password format and press Ctrl-D or Ctrl-Z (Windows) to save the file:',
				pt=pt)

		# Parse data into a dictionary object.
		data_dict = parse_data(pt)

		# Encrypt data and write to the database file.
		self.__db_write(data_dict)

	# Query data from the database file.
	def query_data(self):
		# Decrypt database file data.
		pt = self.__db_read()

		# Get query keys from stdin.
		keys = read_lines('Enter password ids you wish to retrieve (entering nothing will dump all):',
				line_check=False)
		if not keys:
			keys = pt
		else:
			keys = keys.split()

		# Parse and print data to stdout.
		print('Decrypted data queried:\n')
		parse_data(pt, keys, True)

def dh_call(args):
	# Get master password from stdin.
	passwd = getpass(prompt='Enter master password to encrypt/decrypt the database file\'s data: ')

	# Create a database file.
	if args.create:
		Data_handler.filename = args.create
		passwd_confirm(passwd)
		dh_method = Data_handler.create_file
	
	# Change the password, i.e. decrypt data and encrypt with new password and write to db file.
	elif args.change_pass:
		Data_handler.filename = args.change_pass
		dh_method = Data_handler.change_passwd
	
	# Create the file and write encrypted input data to it.
	elif args.edit:
		Data_handler.filename = args.edit
		dh_method = Data_handler.edit_file
	
	# Query/retrieve data from the database file's data and print to stdout.
	elif args.query:
		Data_handler.filename = args.query
		dh_method = Data_handler.query_data

	# Instantiate our data handler object.
	dh_self = Data_handler(args.algorithm, passwd)

	# Call target method.
	dh_method(dh_self)

def main():
	args = parse_args()

	# Generate dh object and call dh methods.
	dh_call(args)

if __name__ == '__main__':
	main()
