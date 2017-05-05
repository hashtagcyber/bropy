#!/usr/bin/env python
import os

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

