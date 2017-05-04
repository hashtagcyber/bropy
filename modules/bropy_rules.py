#!/usr/bin/env python
import os
import datetime
def qry_yn(question, default=None):
	valid={'yes':True,'y':True,'ye':True,'no':False,'n':False}
	prompt = " [y/n] "
	while True:
		print question + prompt
		choice = raw_input().lower()
		if choice in valid:
			return valid[choice]
		else:
			print "Please respond with 'yes' or 'no' "
def readrules(basedata):
	currbase = {}
	with open(basedata) as f:
		for line in f:
			if not line.startswith("#"):
				key  = str(line.split('\t')[0:3])
				val = str(line.split('\t')[3].rstrip('\n'))
				if len(line.split('\t')) > 4:
					remark = str(line.split('\t')[4].rstrip('\n'))
				currbase[str(key).strip("[]").replace("'","")] = val
	return	currbase

def writerules(broinstalldir,basedata,addbase,currbase):
	with open(basedata,'w') as myfile:
		#Make addbase vals include currbase vals
		for x in addbase:
			if x in currbase:
				addbase[x] += "," + currbase[x]
		#Add all current rules that are not in addbase to addbase
		for x in currbase:
			if x not in addbase:
				addbase[x] = currbase[x]
		#Do the Writing
		myfile.write('#fields\tdestip\tdestport\tpro\tips\tcomment\tremotemeth\tsvchash\n')
                myfile.write('#Begin Bropy RuleBlock\n')
		for x in addbase:
			mylst= x.replace("'","").replace(",","").split()
			myline = '\t'.join(map(str,mylst)) + '\t'
			myline += '\t'.join(map(str,addbase[x].split())) +'\n'
			myfile.write(myline)
		myfile.write('#End Bropy RuleBlock\n')
		myfile.write('#Lastrun\t' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+ "\n")
	if qry_yn("Bro must be restarted to take advantage of new rules. Restart Now? "):
		os.system(broinstalldir+'/bin/broctl restart')
	else:
		print "Restart skipped, be sure to restart Bro to take advantage of new rules. Try 'sudo nsm_sensor_ps-restart --only-bro'\n"
	return
