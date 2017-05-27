#!/usr/bin/env python
import os
import datetime
def conlist(brologdir):
	#Create a list of all conn logs in bro log directory
	logfiles = os.popen('find '+brologdir+' -name conn.* -type f').read().rstrip('\n').split('\n')
	return logfiles

def mkrules(broinstalldir,logfiles):
	#Create a dictionary of potential rules
	results = {}
	for conlog in logfiles:
		print "Processing logs in: " + conlog
		if conlog.endswith('.log'):
			data = os.popen('cat '+conlog+' | '+broinstalldir+'/bin/bro-cut id.resp_h id.resp_p proto id.orig_h').readlines()
			for line in data:
				key = str([line.split('\t')[i] for i in [0,1,2]]).strip("[]").replace("'","")
				val = str(line.split('\t')[3]).strip("[']").strip('\n')+'/32'
				if results.has_key(key):
					oldval  = result[key]
					if val in oldval:
						continue
					else:
						results[key] = oldval + ','+val
				else:
					results[key] = val
		else:
			data = os.popen('zcat '+conlog+' | '+broinstalldir+'/bin/bro-cut id.resp_h id.resp_p proto id.orig_h').readlines()
                        for line in data:
                                key = str([line.split('\t')[i] for i in [0,1,2]]).strip("[]").replace("'","")
                                val = str(line.split('\t')[3]).strip("[']").strip('\n')+'/32'
                                if results.has_key(key):
                                        oldval  = results[key]
                                        if val in oldval:
                                                continue
                                        else:
                                                results[key] = oldval + ','+val
                                else:                   
                                        results[key] = val
							
			
		print "Finished processing: " + conlog

	return results

def writeconrules(conresults,connrules):
	dstlst = sorted(connrules.keys())
	with open(conresults,'w') as myfile:
		myfile.write('#fields\tdestip\tdestport\tpro\tips\tcomment\tremotemeth\tsvchash\n')
		myfile.write('#Rules Generated via conn logs. These must be moved to baseline.data')
		myfile.write(' and Bro must be restarted to take effect\n')
                for x in dstlst:
                        mylst= x.replace("'","").replace(",","").split()
                        myline = '\t'.join(map(str,mylst)) + '\t'
                        myline += '\t'.join(map(str,connrules[x].split())) +'\n'
                        myfile.write(myline)
                myfile.write('#End Bropy RuleBlock\n')
                myfile.write('#Lastrun\t' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+ "\n")
		myfile.close()
		return

