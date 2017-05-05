# bropy
Basic Anomaly IDS capabilities with Python and Bro

Awesome quality video of me doing a terrible job talking about Bropy... https://www.youtube.com/watch?v=hz2eAWV54i0

CHANGELOG
-Moved "autobaseline" to an advanced menu
-Added advanced menu that:
	- generates per host lists of potential rules for review
-Now using bropy.cfg to set directory parameters.(Current setting is for /usr/local because I installed from source, will update and set defaults to SecurityOnion later)
-Now using modules to do log processing and rule generation (modules/bropy_logs.py,modules/bropy_rules.py)

TODO
-Move more stuff to modules to make bropy.py cleaner
-Allow for custom subnets when generating rules (may need to import another module for subnet testing)
-Allow for comments at Y/N time (i.e. "MYSQL port for dbsvr")

-Add advanced menu that:
	- generates lists (per host or total) using current conn logs (no need to collect first using baselinereport.bro)
	- generate lists using NETFLOW data (this is gonna take some work)

