from __main__ import *
import os
import struct
import tempfile
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

def current_file_path():
	ep = currentProgram.getExecutablePath()
	norm_ep = os.path.normpath(ep)
	if norm_ep.startswith(os.path.sep):
		return norm_ep[1:]
	return norm_ep


def add_bookmark_comment(addr, text):
	#print 'addr', addr
	#print 'text', text
	addr = toAddr(addr)
	try:
		cu = currentProgram.getListing().getCodeUnitAt(addr)
		#print 'type', type(cu)
		createBookmark(addr, "Capa Ghidra", text)
		cu.setComment(CodeUnit.EOL_COMMENT, text)
	except Exception as e:
		print 'Unable to place bookmark at: ', addr
		print 'With text "%s"' % text
	return

def is_auto_symbol(func):
	source = func.symbol.getSource()
	if (source == SourceType.DEFAULT) or (source == SourceType.ANALYSIS):
		return True
	return False

def write_and_get_path(blob):
	tf = tempfile.NamedTemporaryFile('wb', delete=False)
	fd = open(tf.name, 'wb')
	for char in blob:
		fd.write(struct.pack('b', char))
	fd.close()
	return tf.name

def rebase_list(li, base1, base2):	
	new_addrs = []

	for i in li:
		#print 'rebase_list: ', i, base1, base2
		tmp = long(i)-long(base1)+long(base2)
		new_addrs.append(tmp)
	return new_addrs

def rebase_item(addr, base1, base2):
	#print 'rebase_item: ', addr, base1, base2
	#print '        new: ', int(addr)-int(base1)+int(base2), hex(int(addr)-int(base1)+int(base2))
	return str(long(addr)-long(base1)+long(base2))

def get_int_str(addr):
	#take in string in the form of '  0x180001910L'
	#return string in form of '6442457360'
	return str(long(addr.replace('L', '').replace('\n', ''), 16))