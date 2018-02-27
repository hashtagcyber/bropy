#!/usr/bin/env python
from shutil import copyfile
import os
import datetime
from dateutil.parser import parse
import ConfigParser

from modules.bropy_logs import *
from modules.bropy_rules import *
from modules.bropy_conparse import *
from modules.bropy_menus import *
from modules.bropy_install import *

#Use bropy.cfg to configure file locations
config = ConfigParser.ConfigParser()
config.read('./etc/bropy.cfg')
broinstalldir = config.get('DEFAULT','broinstalldir')
basedata = config.get('DEFAULT','basedata')
basescr = config.get('DEFAULT','basescr')
broconfig = config.get('DEFAULT','broconfig')
noticelog = config.get('DEFAULT','noticelog')
brologdir = config.get('DEFAULT','brologdir')
logfiles = []
currbase = {}
addbase = {}
loop = True

#TODO read file based on user input after checking if it exists
#TODO Allow subnet other than /32 to be appended to line, maybe even tag a line for review later(grouping of rules)
#TODO allow for comments
#TODO extend checks for protected hosts src > unk destination

def procconn():
	print "Generating rules list based on conn logs at " + brologdir
	conresults = raw_input("Enter filename for results: ")
	confiles = conlist(brologdir)
	connrules = mkrules(broinstalldir,confiles)
	writeconrules(conresults,connrules)
	print "Done. Saved as "+conresults+" in the local directory.\n"
	exit()
#create files for each host
def hostrules():
	print "Generating host lists..."
	addbase = readlerts(basedata,brologdir,noticelog)
	currbase = readrules(basedata)
	mkhostrules(addbase,currbase)
	exit()
#Read alerts, add to baseline, automagically
def autoupdate():
	print "Auto Update selected, Auto Baseline In Progress"
	currbase = readrules(basedata)
	addbase = readlerts(basedata,brologdir,noticelog)
	writerules(broinstalldir,basedata,addbase,currbase)
	print "All Done... Hope there weren't any bad guys in there :("
	exit()

#Step through alerts, adding them via menu
def stepupdate():
	print "Scanning for Alerts...."
	addbase = readlerts(basedata,brologdir,noticelog)
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
	currbase = readrules(basedata)
	writerules(broinstalldir,basedata,addbase,currbase)
	exit()

#install my script
def betainst():
	mynet = getprotectsubnet().split(',')
	while not checkprotectedinput(mynet,basescr):
		print "Sorry, invalid subnet"
		mynet = getprotectsubnet()
	doit = "sed -i '/global protected/cglobal protected: set[subnet] = {" + ','.join(mynet) + "};' ./etc/baselinereport.bro"
	os.system(doit)
#	doit = "sed -i 's/\/opt\/bro/"+broinstalldir.replace('/','\/')+"/g' "+"./etc/baselinereport.bro"
#	os.system(doit)
	if 'baselinereport.bro' in open(broconfig).read():
		print "Script is already mentioned in "+broinstalldir+"/share/bro/site/local.bro ... Skipping"
	else:
		print "Adding line to " + broconfig
		with open(broconfig,"a") as myfile:
			myfile.write("#Baseline Reporting Script\n@load misc/baselinereport.bro")
	if os.path.exists(basedata):
		if qry_yn('Baseline Data already exists, Overwrite?'):
			print "Overwriting with sample baseline data file at " + basedata
			copyfile('./etc/baseline.data',basedata)
		else:
			print "Skipping..."
	else:
		print "Copying sample baseline data file to " + basedata
		copyfile('./etc/baseline.data',basedata)
	if os.path.exists(basescr):
		if qry_yn('Baseline script found...Overwrite?'):
			print "Overwriting script at " + basescr
			copyfile('./etc/baselinereport.bro',basescr)
		else:
			print "Skipping..."
	else:
		print "Copying Baseline report script to " + basescr
		copyfile('./etc/baselinereport.bro',basescr)
	if qry_yn('Bro must be restarted to complete installation. Restart Bro now?'):
		os.system(broinstalldir+'/bin/broctl restart')
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
			stepupdate()
		elif int(ans) == 2:
			automenu()
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

def automenu():
        while loop:
                autobanner()
                ans = raw_input("Choose one : [1-3]")
                if not ans.isdigit():
                        print "Invalid Choice"
                elif int(ans) == 1:
                        autoupdate()
                elif int(ans) == 2:
                        hostrules()
                elif int(ans) == 3:
                        procconn()
                elif int(ans) == 4:
                	menu()
		else:
                        print "Invalid Selection"

#######################EXECUTION After This ###########################
menu()
