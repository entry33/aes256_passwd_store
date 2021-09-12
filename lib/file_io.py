# Author: https://github.com/c0dy-c0des
import os

WIPE_PASSES = 1024*100

class File_io:
	def __init__(self, filename):
		self.filename = filename

	# Read a database file.
	def read_file(self):
		try:
			with open(self.filename, 'rb') as f:
				return f.read()
		except (FileNotFoundError, PermissionError) as e:
			exit(e)

	# Write salt and encrypted data to a database file.
	def write_file(self, file_data):
		try:
			with open(self.filename, 'wb') as f:
				f.write(file_data)
		except PermissionError as e:
			exit(e)

	# Wipe database file/write random bytes to database file.
	def wipe_dbfile(self):
		with open(self.filename, "br+") as f:
			length = os.path.getsize(self.filename)
			for i in range(WIPE_PASSES):
				f.seek(0)
				f.write(os.urandom(length))
			f.truncate()
