#!/usr/bin/env python
import os
import gzip
from dateutil.parser import parse
def loglist(basedata,brologdir):
        lastrun = os.popen('tail -n1 ' + basedata).read()
        cutoff = parse(lastrun.lstrip('#Lastrun').rstrip('\n'))
        logfiles = os.popen('find '+brologdir+' -name notice* -type f -newermt "'+ str(cutoff) + '"').read().rstrip('\n').split('\n')
        print "These will be parsed:\n"
        for x in logfiles:
                print x
        return logfiles

def readlerts(basedata,brologdir,noticelog):
	addbase = {}	
	logfiles = loglist(basedata,brologdir)
	for mylog in logfiles:
		print "Reading alerts from: " + mylog
		try:
			with gzip.open(mylog) as f:
				for line in f:
					if "TrafficBaselineException" in line: 
						key = str([line.split('\t')[i] for i in [4,5,9]]).strip("[]").replace("'","")
						val = str(line.split('\t')[2:3]).strip("[']")+'/32'
						if addbase.has_key(key):
							oldval = addbase[key]
							if val in oldval:
								continue
							else: 
								addbase[key] = oldval + "," + val
						else:
							addbase[key] = val
			print str(mylog) + ' has been processed'
		except:
			print "Error Processing log file:  " + mylog
			return
	try:
		with open(noticelog) as f:
			for line in f:
				if "TrafficBaselineException" in line:
					key = str([line.split('\t')[i] for i in [4,5,9]]).strip("[]").replace("'","")
					val = str(line.split('\t')[2:3]).strip("[']")+'/32'
					if addbase.has_key(key):
						oldval = addbase[key]
						if val in oldval:
							continue
						else:
							addbase[key] = oldval + "," + val
					else:
						addbase[key] = val
		print str(noticelog) + " has been processed"
	except:
		print "Error processing file: " + str(noticelog)
	return addbase
