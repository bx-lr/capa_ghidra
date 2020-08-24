import ghidra.app.script.GhidraScript
from ghidra.program.model.symbol import SourceType
import operator

af = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
tmpstuff = {}
#print 'af', dir(af)
#print 'af', all_funcs.getFunctions()
while (af.iterator().hasNext()):
	nxt =  af.iterator().next()
	#print nxt.getName() 
	bdy = nxt.getBody()
	sz = 0
	for b in bdy:
		#print dir(b)
		sz += int(str(b.maxAddress), 16) - int(str(b.minAddress), 16)
	ep = nxt.entryPoint
	tmpstuff[ep] = [nxt.getName() , str(sz)]
	#print dir(nxt)
	#break
i=0
frn = 0
ksz = 0
usz = 0
toprocess = {}
for k,v in tmpstuff.iteritems():
	ignore_str = 'cg_contain_loop_@_FUN_'
	if not v[0].startswith(ignore_str, 0,len(ignore_str)):
		ksz += int(v[1])
		frn +=1
	else:
		#print k,v
		toprocess[k]=int(v[1])
		usz += int(v[1])
	i+=1
sorted_tmpstuff = sorted(toprocess.items(), key=operator.itemgetter(1))
fm = currentProgram.getFunctionManager()
print 'Begin x64dbg breakpoint script'
print '------------------------------------------'
print 'log "begin"'
for fun in sorted_tmpstuff:
	print 'bp %s' %fun[0] 
print 'log "end"'
print 'ret'
print '-----------------------------------------'
print 'End x64dbg breakpoint script'
print 'Save as .txt, load with "scriptload <path>" '
print 'Run by going to script window, rclk+run '
print ''
print 'Size of functions audited:', ksz
print 'Size of functions not audited:', usz
print 'Total size of code to audit:', ksz+usz
print ''
print 'Number of functions audited:', frn
print 'Number functions not audited:', i-frn
print 'Total number of functions in binary:', i
print 'Total number of functions with stubs:', fm.functionCount
print ''
print 'Percet of code audited:', (float(ksz)/float(ksz+usz))*100
