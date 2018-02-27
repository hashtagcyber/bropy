#!/usr/bin/env python
def getprotectsubnet():
        mynet = raw_input('What subnets would you like to protect?(Enter comma separated list of subnets w/CIDR)\ni.e. 192.168.24.0/24,10.10.10.0/24\n')
        return mynet
def checksubnet(x, basescr):
	p = x.split('.')
        if len(p) == 4:
		p[3] = p[3].split('/')[0]
                if x.split('.')[3].find('/') != -1:
			for item in p:
				if int(item) > 254:
					return False
                        print 'You entered ' + x + '. If this is incorrect, manually edit the file located at ' + basescr
                        return True
                else:
                        return False
        else:
                return False

def checkprotectedinput(protectedlist,basescr):
    for x in protectedlist:
        if not checksubnet(x, basescr):
            return False
    return True
