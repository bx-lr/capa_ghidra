from __main__ import *
import os
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

def current_file_path():
	ep = currentProgram.getExecutablePath()
	norm_ep = os.path.normpath(ep)
	if norm_ep.startswith(os.path.sep):
		return norm_ep[1:]
	return norm_ep


def add_bookmark_comment(addr, text):
	addr = toAddr(addr)
	cu = currentProgram.getListing().getCodeUnitAt(addr)
	createBookmark(addr, "Capa Ghidra", text)
	cu.setComment(CodeUnit.EOL_COMMENT, text)
	return

def is_auto_symbol(func):
	source = func.symbol.getSource()
	if (source == SourceType.DEFAULT) or (source == SourceType.ANALYSIS):
		return True
	return False
