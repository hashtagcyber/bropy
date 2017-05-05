# bropy
Basic Anomaly IDS capabilities with Python and Bro

Awesome quality video of me doing a terrible job talking about Bropy... https://www.youtube.com/watch?v=hz2eAWV54i0

CHANGELOG

-Bropy can now generate a list for each host it detects (usefull for handing out to sysadmins to Q/C entries)

-Bropy can now parse conn.logs directly to generate a list of all services. Check out the "advanced" option

-Now using bropy.cfg to set directory parameters.
	(Default setting is for SecurityOnion, if you did a custom install, you'll need to edit bropy/etc/bropy.cfg)

-Now using modules to do log processing and rule generatin.o
	(modules/bropy_logs.py,modules/bropy_rules.py)

-Rules are now sorted by IP Destination (Kinda, 21 comes after 100)

-"Auto baseline" is now in the advanced menu... Don't do it.

TODO

-Move more stuff to modules to make bropy.py cleaner

-Allow for custom subnets when generating rules (may need to import another module for subnet testing)

-Allow for comments at Y/N time (i.e. "MYSQL port for dbsvr")

-Generate lists using NETFLOW data (this is gonna take some work)

