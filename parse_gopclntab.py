import os, sys
import subprocess
import struct

SECTION_HEADER = b'\xfb\xff\xff\xff\x00\x00'
HEADER_SIZE = 8
ADDR_SIZE = 8


def parse_argv():
	filename = sys.argv[1]
	if len(sys.argv) > 2:
		section_offset_in_hex = sys.argv[2]
		section_size_in_hex = sys.argv[3]
	else:
		objdump_output = subprocess.check_output(['objdump', '-x', filename]).splitlines()
		section = [i for i in objdump_output if b".gopclntab" in i] [0]
		_, _, section_size_in_hex, _, _, section_offset_in_hex, _ = section.split()

	section_offset = int(section_offset_in_hex, 16)
	section_size = int(section_size_in_hex, 16)
	return filename, section_offset, section_size

def convert_to_qword(data, pos):
	return struct.unpack("<Q", data[pos:pos+8]) [0]
def convert_to_dword(data, pos):
	return struct.unpack("<I", data[pos:pos+4]) [0]
def get_string(data, pos):
	s = ''
	i = 0
	while data[pos + i] != 0:
		s += chr(data[pos + i])
		i += 1
	return s

class Function(object):
	def __init__(self, func_offset, name_offset, name_addr, name):
		self.func_offset = func_offset
		self.name_offset = name_offset
		self.name_addr   = name_addr
		self.name        = name
	
	def __repr__(self):
		return f"function ({self.name}) @ .gopclntab + ({self.func_offset})"

	def __str__(self):
		return \
			f"func_offset : {self.func_offset} ; " \
			f"name_offset : {self.name_offset} ; " \
			f"name_addr   : {self.name_addr} ; " \
			f"name        : {self.name}"

	def __eq__(self, other):
		return self.name == other
	def __contains__(self, other):
		return other in self.name

	def rename(self, data, section_offset, new_name):
		raw_name = self.name.split('.')[-1]
		if len(new_name) > len(raw_name):
			print("unable to rename to a larger name")
			return False

		if type(data) is bytes:
			null = b'\x00'
		elif type(data) is str:
			null = '\x00'

		new_name = new_name + null * (len(raw_name) - len(raw_name))

		raw_name_addr = section_offset + self.name_addr + (len(self.name) - len(raw_name))
		name_addr_end = section_offset + self.name_addr + len(self.name)
		new_data = data[:raw_name_addr] + new_name + data[name_addr_end:]
		return new_data

def parse(data):
	qword = lambda x: convert_to_qword(data, x)
	dword = lambda x: convert_to_dword(data, x)

	pos = base = 0
	pos += HEADER_SIZE

	size = qword(pos)
	pos += ADDR_SIZE
	end = pos + (size * ADDR_SIZE * 2)

	funcs = []
	i = 0
	while pos < end:
		func_offset = qword(pos)
		name_offset = qword(pos + ADDR_SIZE)
		pos += 2 * ADDR_SIZE

		name_addr = dword(base + ADDR_SIZE + name_offset)
		name = get_string(data, name_addr)

		funcs.append(Function(func_offset, name_offset, name_addr, name))

	return funcs

def main():
	filename, section_offset, section_size = parse_argv()
	print(filename, section_offset, section_size)

	raw_data = open(filename, 'rb').read()
	data = raw_data[section_offset : section_offset + section_size]

	funcs = parse(data)

	new_data = raw_data[::]
	# rename function name
	for i in funcs:
		if "func2" in i:
			new_data = i.rename(new_data, section_offset, b"abcde")
	# display the renamed function
	for i in funcs:
		if "func2" in i:
			temp = new_data[section_offset + i.name_addr : section_offset + i.name_addr + len(i.name) + 1]
			print(f"{i.name} : {temp}")
	# manually find a function in a location
	for i in funcs:
		if 1313940 - 50 < section_offset + i.name_addr < 1313940 + 50:
			print(str(i))
			print("func_offset: ", new_data[section_offset + i.func_offset : section_offset + i.func_offset + 500])
			print("name_offset: ", new_data[section_offset + i.name_offset : section_offset + i.name_offset + 500])
			print("name_addr  : ", new_data[section_offset + i.name_addr   : section_offset + i.name_addr   + 500])
			# print(new_data[section_offset + i.name_addr - 500 : section_offset + i.name_addr + 500])
			# print(section_offset + i.name_addr)
	# print(new_data[1313940 - 1 : 1313940 + 20])
	open("panic_renamed", 'wb').write(new_data)

if __name__ == '__main__':
	main()