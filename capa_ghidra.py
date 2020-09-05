import os
import sys
import json
import array
from subprocess import Popen, PIPE

from capaghidra.config import CAPAEXE
from capaghidra.config import CAPARULE

from capaghidra.ghidra_helper import current_file_path
from capaghidra.ghidra_helper import is_auto_symbol
from capaghidra.ghidra_helper import add_bookmark_comment
from capaghidra.ghidra_helper import write_and_get_path
from capaghidra.ghidra_helper import rebase_list
from capaghidra.ghidra_helper import rebase_item

import ghidra.app.script.GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder

def run_capa(blob=None, arch=None, log=False):
	#return type dict

	global CAPAEXE
	global CAPARULE

	#check our config 
	try:
		if len(CAPAEXE) < 1:
			CAPAEXE = askFile('FILE', 'Choose capa execuatble')
		if len(CAPARULE) < 1:
			CAPARULE = askDirectory('Directory', 'Choose capa rule directory')
	except CancelledException as e:
		print("[!] CANCELLED: " + str(e))
		return None

	if type(blob) != type(None):
		sample = write_and_get_path(blob)
		if arch == 'x86':
			flags = ' --vv --color never -j -f sc32 -r'
		else:
			flags = ' --vv -color never -j -f sc64 -r'
	else:
		#get the path to the sample
		sample = current_file_path()

		#setup our command 
		flags = ' --vv --color never -j -r'

	pipe_buf_size = 50*1024*1024
	if type(CAPAEXE) != type(str()):
		CAPAEXE = CAPAEXE.path
	if type(CAPARULE) != type(str()):
		CAPARULE = CAPARULE.path
	command = CAPAEXE + flags + ' %s ' % CAPARULE + sample

	#execute and get the results 
	p = Popen(command, stdout=PIPE, stderr=PIPE, shell=True, bufsize=pipe_buf_size)
	stdout, stderr = p.communicate()

	#something went wrong
	if p.returncode != 0:
		print('[!] Oh noes! capa failed...')
		print('[!] Something went wrong with "%s"' % command)
		return None

	#dict from json 
	output = json.loads(stdout)

	#log the capa output if asked
	if log == True:
		with open(sample+'.json', 'w') as wfile:
			json.dump(output, wfile, indent=4, sort_keys=True)
	return output

def process_capa_for_rename(capa_json, funcs, capabase, base):
	#returns dict with keys as the location
	#value as the new name

	temp = dict.fromkeys(funcs)
	output = {}
	for rulename, more in capa_json['rules'].iteritems():
		#print rulename
		for matches, v in more.iteritems():
			new_fn = rulename.replace(' ', '_').replace('\r', '').replace('\n', '').replace('/', '_').replace('.', '_').replace('(', '').replace(')', '')
			try:
				for k in v.keys():
					#print str(k)
					if str(k) in temp:
						val = str(temp[str(k)])
						if val == 'None':
							temp[str(k)] = 'cg_' + new_fn
							#print val
						else:
							val += '_&_' + new_fn 
							temp[str(k)] = val
					else:
						temp[str(k)] = 'cg_'+ new_fn
					#print new_fn+'@'+str(k)
			except Exception as e:
				#print e
				pass

	for k,v in temp.iteritems():
		if type(v) != type(None):
			try:
				#clear out junk
				#print('addr: ', k)
				#print('new addr: ', nk)
				#i = int(k)
				if long(k) > long(capabase):
					nk = rebase_item(k, capabase, base)
					try:
						del output[k]
					except KeyError:
						pass
					output[nk] = v
			except Exception as e:
				#print e
				pass
	print('Found %d functions to rename...' % len(output.keys()))
	return output


def process_capa_for_bookmark(capa_json, capabase, base):
	#returns a dict with keys set to rule name and value is list of locations

	output={}
	#so many dicts to iterate... changinging types... so ugly
	for rulename, more in capa_json['rules'].iteritems():
		output[rulename] = list()
		for mkey, vals in more.iteritems():
			#print 'KEY', mkey
			#print 'VALS', vals
			try:
				for matches, children in vals.iteritems():
					#print 'MATCHES', matches
					#print 'CHILDREN', children
					try:
						for node, locations in children.iteritems():
							#print 'NODE', node
							#print 'LOCATIONS', locations

							try:
								if type(locations) == type(list()):
									for i in xrange(0, len(locations)):
										#print 'locations[%d]' % i 
										#print 'locations', locations[i]
										try:
											for key, val in dict(locations[i]).iteritems():
												#print 'key', key
												#print 'val', val
												#print type(val)
												try:
													if type(val) == type(list()):
														if len(val) > 0:
															if (type(val[0]) == type(int())) or (type(val[0]) == type(long())):
																#print 'VALUE!!!', val
																for v in val:
																	output[rulename].append(v)
												except Exception as e:
													#print '5', e
													pass
										except Exception as e:
											#print '4', e
											pass
							except Exception as e:
								#print '3', e
								pass
					except Exception as e:
						#print '2', e
						pass
			except Exception as e:
				#print '1', e
				pass
	i = 0
	for k,v in output.iteritems():
		#print k
		#print v, len(v)
		if len(v) < 1:
			try:
				del output[k]
			except KeyError:
				pass
		else:
			v = rebase_list(v, capabase, base)
			output[k]=v
		i += len(v)
	print("Found %d locations to bookmark..." % i)
	return output


def rename_functions(to_rename):
	#return type list
	#TODO: sometimes vivisect has a different function head then ghidra... we need to check for this and update 
	#print to_rename.keys()

	all_functions = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
	num_renamed = 0
	num_skipped = 0
	#print to_rename
	while (all_functions.iterator().hasNext()):
		func = all_functions.iterator().next()
		if not is_auto_symbol(func):
			continue
		name = func.name
		ep =  long(str(func.getEntryPoint()),16)
		#print '%x' % ep
		#if str(ep) in to_rename:
		#	print 'Found function at address: %x' % ep
		if name.startswith('FUN_',0,4):
				#print 'name: ', name, 'ep:', ep, 'keys:', to_rename.keys()
				#print to_rename
				#break
				if str(ep) in to_rename:
					#print "IN IT!!!!"
					#print name, ep, to_rename[str(ep)]
					new_fn = to_rename[str(ep)] + '_@_' + func.name
					print('Renaming function "%s" to "%s"' % (func.name, new_fn))
					func.setName(new_fn, SourceType.ANALYSIS)
					num_renamed += 1
		else:
			#print "Non-default name found at address %x ... skipping" % ep
			num_skipped += 1
	#print "Skipped %d functions because of non-default name" % num_skipped
	#print "renamed %d functions..." % num_renamed
	return [num_renamed, num_skipped]

def add_rule_hits(to_comment):
	#return type int
	i = 0
	for k, v in to_comment.iteritems():
		#print k

		for addr in v:
			#print addr
			add_bookmark_comment(addr, k)
			i+=1
	return i

def main():
	#TODO: add chooser to record capa ouput

	try:
		choice = askChoice('Execution Options', 'Select file to process', ['Main executable', 'RAM segment'], 'Main Executable')
	except:
		sys.exit(0)

	if choice == 'RAM segment':
		try:
			base = askAddress('Segment Base', 'Enter segment base to process')
			arch = askChoice('Architecture Options', 'Select memory page architecture', ['x86', 'x64'], 'x86')
		except:
			sys.exit(0)
		all_pages = currentProgram.getMemory()
		for page in all_pages:
			if base == page.minAddress:
				page_sz = long(str(page.maxAddress), 16) - long(str(page.minAddress), 16)
				page_bin = array.array('b', '\x00'*page_sz)
				bytes_read = all_pages.getBytes(base, page_bin)
				print("Read %d bytes from page %s" % (bytes_read, base))
				base = long(str(base), 16)
				capa_json = run_capa(blob=page_bin, arch=arch)
	else:
		capa_json = run_capa()
		base = long(str(currentProgram.getMinAddress()), 16)
	if type(capa_json) == type(None):
		print('[!] exiting...')
		sys.exit(0)
	funcs = capa_json['meta']['analysis']['feature_counts']['functions']
	capabase = capa_json['meta']['analysis']['base_address']
	print('Capa using VA ' + hex(capabase))
	print('Capa found %d functions...' % len(funcs))

	#process capa dict and extract functions / rule hits to rename functions... 
	#key is each function address 
	#value is new function name
	to_rename = process_capa_for_rename(capa_json, funcs, capabase, base)

	#process capa dict and extract exact rule hit locations
	#key is rule name 
	#value is locations of hits
	to_comment = process_capa_for_bookmark(capa_json, capabase, base)

	#do the function renaming 
	num_renamed = rename_functions(to_rename)
	print('Renamed %d functions' % (num_renamed[0]))
	print('Skipped %d functions with non-default name' % num_renamed[1])

	#add bookmarks and comments for rule hit locations
	num_comments = add_rule_hits(to_comment)
	print('Added %d bookmarks' % num_comments)

	return
if __name__ == '__main__':
	main()
