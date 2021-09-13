# Author: https://github.com/c0dy-c0des
import os
from multiprocessing import Process

# Number of child processes to start/launch.
PROC_COUNT = 10

# Total wipe passes (will be divided by PROC_COUNT).
WIPE_PASSES = 1024*512

def child_process(method):
    def wrapper(*args):
        p = Process(target=method, args=args)
        p.start()
        return p
    return wrapper

@child_process
def write_rand(f, passes, length):
	for _ in range(passes):
		f.seek(0)
		rand_data = os.urandom(length)
		f.write(rand_data)

def join_child_procs(procs):
	for p in procs:
		p.join()

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
			procs = []
			chunks = int(WIPE_PASSES / PROC_COUNT)
			for _ in range(PROC_COUNT):
				p = write_rand(f, chunks, length)
				procs.append(p)
			join_child_procs(procs)
			f.truncate()
