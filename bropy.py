#!/usr/bin/env python
from shutil import copyfile
import os
import datetime
from dateutil.parser import parse
import gzip
#Edit these to change location of bro stuff
basedata = '/opt/bro/share/bro/policy/misc/baseline.data'
basescr = '/opt/bro/share/bro/policy/misc/baselinereport.bro'
broconfig = '/opt/bro/share/bro/site/local.bro'
noticelog = '/nsm/bro/logs/current/notice.log'
logfiles = []
currbase = {}
addbase = {}
loop = True

#TODO read file based on user input after checking if it exists
#TODO Allow subnet other than /32 to be appended to line, maybe even tag a line for review later(grouping of rules)
#TODO allow for comments
#TODO extend checks for protected hosts src > unk destination
#TODO Change install to accept custom bro directory

#Create list of files to import, based on lastrun time (stored at bottom of baseline.data)
def loglist():
	lastrun = os.popen('tail -n1 ' + basedata).read()
	cutoff = parse(lastrun.lstrip('#Lastrun').rstrip('\n'))
	logfiles = os.popen('find /nsm/bro/logs -name notice* -type f -newermt "'+ str(cutoff) + '"').read().rstrip('\n').split('\n')
	print "These will be parsed:\n"
	for x in logfiles:
		print x
	return logfiles
#Read in all the rules from currently hardcoded 'baseline.data'.
def readrules():
	with open(basedata) as f:
		for line in f:
			if not line.startswith("#"):
				key  = str(line.split('\t')[0:3])
				val = str(line.split('\t')[3].rstrip('\n'))
				if len(line.split('\t')) > 4:
					remark = str(line.split('\t')[4].rstrip('\n'))
				currbase[str(key).strip("[]").replace("'","")] = val
	return
#Adds list of rules currently stored in addbase to baseline.data
#TODO Accept user input for filename
def writerules():
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
		os.system('nsm_sensor_ps-restart --only-bro')
	else:
		print "Restart skipped, be sure to restart Bro to take advantage of new rules. Try 'sudo nsm_sensor_ps-restart --only-bro'\n"
	return
#Reads the bro notice.log and adds them to addbase dict.
#TODO: accept userinput for notice.log
def readlerts():
	logfiles = loglist()
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

#Banner stuff
def banner():
	print "_" * 30
	print "Welcome to Bropy!"
	print "A python wrapper for generating network baselines"
	print "\n"
	print "Bropy allows you to:\n"
	print "   1 - Automatically update your baseline, based on the contents of your Bro notice.log (Not Recommended)\n"
	print "   2 - Step through alerts in your Bro notice.log and update the baseline by answering questions\n"
	print "   3 - Add the BaselineReport script to your current bro install\n"
	print "   4 - Quit\n"

#Read alerts, add to baseline, automagically
def autoupdate():
	print " Option 1 selected, Auto Baseline In Progress"
	readrules()
	readlerts()
	writerules()
	print "All Done... Hope there weren't any bad guys in there :("
	exit()

#Step through alerts, adding them via menu
def stepupdate():
	print "Scanning for Alerts...."
	readlerts()
	print "Please answer each question with y or n"
	drops = []
	for x in addbase:
		loop = True
		while loop:
			print "Should {} be allowed to connect to {} ?".format(addbase[x], x)
		 	ans = raw_input("y/n?")
			if ans not in ['y','n']:
				print 'Try again'
			elif ans == 'y':
				loop = False
			elif ans == 'n':
				drops.append(x)
				loop = False
	print "Answers complete. baseline.data updated with the following lines"
	if len(drops) > 0:
		for x in drops:
			del addbase[x]
	readrules()
	writerules()
	exit()

#install my script
def betainst():
	mynet = raw_input('What subnets would you like to protect?(Enter comma separated list of subnets w/CIDR)\ni.e. 192.168.24.0/24,10.10.10.0/24\n')
	print 'You entered ' + mynet + '. If this is incorrect, manually edit the file located at ' + basescr
	doit = "sed -i '/global protected/cglobal protected: set[subnet] = {" + mynet + "};' baselinereport.bro"
	os.system(doit)
	if 'baselinereport.bro' in open(broconfig).read():
		print "Script is already mentioned in /opt/bro/share/bro/site/local.bro ... Skipping"
	else:
		print "Adding line to " + broconfig
		with open(broconfig,"a") as myfile:
			myfile.write("#Baseline Reporting Script\n@load misc/baselinereport.bro")
	if os.path.exists(basedata):
		if qry_yn('Baseline Data already exists, Overwrite?'):
			print "Overwriting with sample baseline data file at " + basedata
			copyfile('baseline.data',basedata)
		else:
			print "Skipping..."
	else:
		print "Copying sample baseline data file to " + basedata
		copyfile('baseline.data',basedata)
	if os.path.exists(basescr):
		if qry_yn('Baseline script found...Overwrite?'):
			print "Overwriting script at " + basescr
			copyfile('baselinereport.bro',basescr)
		else:
			print "Skipping..."
	else:
		print "Copying Baseline report script to " + basescr
		copyfile('baselinereport.bro',basescr)
	if qry_yn('Bro must be restarted to complete installation. Restart Bro now?'):
		os.system('nsm_sensor_ps-restart --only-bro')
		print "Install complete."
	else:
		print "Install finished, be sure to restart Bro to begin logging.\nTry 'sudo nsm_sensor_ps-restart'"
	exit()
def menu():
	while loop:
		banner()
		ans = raw_input("Choose one : [1-4]")
		if not ans.isdigit():
			print "Invalid Choice"
		elif int(ans) == 1:
			autoupdate()
		elif int(ans) == 2:
			stepupdate()
		elif int(ans) == 3:
			betainst()
		elif int(ans) == 4:
			print "Goodbye"
			exit()
		elif int(ans) == 5:
			print "Magic, let's test my func"
			loglist()
			print logfiles
			exit()
		else:
			print "Invalid Selection"

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
#######################EXECUTION After This ###########################
menu()
