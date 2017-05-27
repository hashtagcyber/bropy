#!/usr/bin/env python
def banner():
        print "_" * 30
        print "Welcome to Bropy!"
        print "A python wrapper for generating network baselines"
        print "\n"
        print "Bropy allows you to:\n"
        print "   1 - Step through alerts in your Bro notice.log and update the baseline by answering questions\n"
        print "   2 - Advanced Options\n"
        print "   3 - Install Bropy\n"
        print "   4 - Quit\n"
def autobanner():
        print "_" * 30
        print "Welcome to Bropy!"
        print "_"*10 + " Advanced "+ "_"*10
        print "   1 - Create an auto-baseline (Don't do it)\n"
        print "   2 - Create a rule doc per host for analysis\n"
        print "   3 - Generate potential rules from conn logs\n"
        print "   4 - Main Menu\n"
        print "_"*30

