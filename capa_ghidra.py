import os
import sys
import json
from subprocess import Popen, PIPE

from capaghidra.config import CAPAEXE
from capaghidra.config import CAPARULE

from capaghidra.ghidra_helper import current_file_path
from capaghidra.ghidra_helper import is_auto_symbol
from capaghidra.ghidra_helper import add_bookmark_comment

import ghidra.app.script.GhidraScript
from ghidra.program.model.symbol import SourceType
from ghidra.framework.model import DomainFile
from ghidra.framework.model import DomainFolder

def run_capa(log=False):
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


	#get the path to the sample
	sample = current_file_path()

	#setup our command 
	flags = ' --vv --color never -j -r'
	pipe_buf_size = 50*1024*1024
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

def process_capa_for_rename(capa_json, funcs, baseaddress):
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
				i = int(k)
				if i > int(baseaddress):
					output[k]=v
			except:
				continue
	print('Found %d functions to rename...' % len(output.keys()))
	return output


def process_capa_for_label(capa_json, baseaddress):
	#returns a dict with keys set to rule name and value is list of locations

	output={}
	#so many dicts to iterate... changinging types... so ugly
	for rulename, more in capa_json['rules'].iteritems():
		output[rulename] = list()
		for mkey, vals in more.iteritems():
			#print 'KEY', key
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
															if type(val[0]) == type(int()):
																#print 'VALUE!!!', val
																for v in val:
																	output[rulename].append(v)
												except:
													pass
										except:
											pass
							except:
								pass
					except:
						pass
			except:
				pass
	i = 0
	for k,v in output.iteritems():
		#print k
		#print v, len(v)
		if len(v) < 1:
			try:
				del output[key]
			except KeyError:
				pass
		i += len(v)
	print("Found %d locations to label" % i)
	return output


def rename_functions(to_rename):
	all_functions = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
	num_renamed = 0
	while (all_functions.iterator().hasNext()):
		func = all_functions.iterator().next()
		if not is_auto_symbol(func):
			continue
		name = func.name
		ep = int(str(func.getEntryPoint()),16)
		if name.startswith('FUN_',0,4):
				#print name, ep
				if str(ep) in to_rename:
					#print name, ep, to_rename[str(ep)]
					new_fn = to_rename[str(ep)] + '_@_' + func.name
					print('Renaming function "%s" to "%s"' % (func.name, new_fn))
					func.setName(new_fn, SourceType.ANALYSIS)
					num_renamed += 1
	#print "renamed %d functions..." % num_renamed
	return num_renamed

def add_rule_hits(to_comment):
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
	#TODO: add chooser to pick which thing to run
	#TODO: add chooser to run and only list what can be modified
	capa_json = run_capa()
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
	to_rename = process_capa_for_rename(capa_json, funcs, capabase)

	#process capa dict and extract exact rule hit locations
	#key is rule name 
	#value is locations of hits
	to_comment = process_capa_for_label(capa_json, capabase)

	#do the function renaming 
	num_renamed = rename_functions(to_rename)
	print('Renamed %d functions' % num_renamed)

	#add bookmarks and comments for rule hit locations
	num_comments = add_rule_hits(to_comment)
	print('Added %d comments' % num_comments)

	return
if __name__ == '__main__':
	main()