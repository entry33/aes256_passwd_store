
# Author: https://github.com/c0dy-c0des
import re

def get_line():
	try:
		return input()
	except EOFError:
		return None

# Read multiple lines of input from stdin until EOF (ctrl+D/ctrl+C) is detected 
def read_lines(msg, pt='', line_check=True):
	print(msg)
	while True:
		line = get_line()
		if not line:
			break
		elif line_check and '=' not in line:
			print('Invalid format:', line, 'Use \'pass_id=password\' as the input format.')
			continue
		pt += line + '\n'
	return pt

# Format previously parsed data into pass_id=password format.
def format_data(data_dict):
	formatted_data = ''
	for key, val in data_dict.items():
		if key and val != 'delete':
			formatted_data += key + '=' + val + '\n'
	return formatted_data

# Parse paintext data.
def parse_data(pt, keys=None, print_data=False):
	# Data dictionary object to store parsed key, value pairs.
	data_dict = {}

	# Temporary data_list object for return value of regex split function.
	data_list = re.split(r'=|\n', pt)

	# Parse key, value pairs.
	for i in range(1, len(data_list), 2):
		key, val = data_list[i-1], data_list[i]
		if key and val:
			if print_data:
				if key in keys:
					print(key + ':\n' + val + '\n')
			else:
				data_dict[key] = val
	return data_dict
