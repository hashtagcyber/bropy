#Baseline Logger/Alert script for Bro.
#Requires baseline.data file to exist in same directory as the script.This is the file you need to update in order to make the script work.
#You need the notice module loaded in order to actually get the logs. 
#Running from cli using bro baseline.bro -r <pcap file> will test your configuration against a pcap, but alerts will go to the notice.log in your current directory.
#Consider copying this script to /usr/local/bro/share/bro/policy/misc/baselinereport.bro and adding "@load misc/baselinereport" to your /usr/local/bro/share/bro/site/local.bro file
#Also checkout bro_agent for SGUIL that will allow you to push bro's notice.logs into SGUIL
#Written By @HashtagCyber, originally for a workshop I presented @BSidesJackson 2016.
#Shoutout to @Killswitch_GUI for convincing my to start speaking, and @Chirontech for supporting me.
#
#TODO: Check destination if ipsrc in protectedhosts
#Create a new notice type for our script
export {
	redef enum Notice::Type += {
		TrafficBaselineException,
		};
	}
#Setup records for the table import. This table is keyed based on the destination IP and Port. Input::add_table doesn't like the \ in the port protocol#So we have to split port and protocol into two different columns
type Idx: record {
	destip: addr;
	destport: port&type_column="pro";
};
#Setup second record that holds the list of IP addresses that are "authorized" to communicate with the host on the port.
# This field is accessed by adding $ips to the database query
#
type Val: record {
	ips: set[subnet];
};
#Define the table, hosts, to index on an ip address and port pair
global hosts: table[addr,port] of Val = table();
global protected: set[subnet] = {156.22.10.0/24};

#load the table from file "baseline.data" and send the data to the table defined above
event bro_init()
{
	Input::add_table([$source="/usr/local/bro/share/bro/policy/misc/baseline.data", $name="hosts", $idx=Idx, $val=Val, $destination=hosts]);
}
#When the table finishes loading, tell me about it, mostly for debugging
event Input::end_of_data(name:string, source:string)
{
	print "Yay,table is loadededed now";
}
#Whenever bro sees a new connection, do someing
event new_connection(c:connection)
	{
# Check the destinatition to see if i event need to continue...
	if ([c$id$resp_h] in protected)
		{
#Check if the destination,destport pair is in the table 
		if ([c$id$resp_h,c$id$resp_p] !in hosts)
#If it's not, the destination isn't in the table, and it should be. Probably not a major issue, but you should update the table to prevent this
			{
			print "Unbaselined Host identified! ", c$id$resp_h;
#	#This writes the notice to the notice.log file
			NOTICE([$note=TrafficBaselineException,$conn=c,$msg=fmt("New DestIP:DPort detected.  %s on %s from host: %s. Investigate and Update Baseline", c$id$resp_h, c$id$resp_p, c$id$orig_h),$identifier=cat(c$id$resp_h,c$id$resp_p,c$id$orig_h)]);
		}
#If the destination is in the baseline, check to see if the source is
		else
			{
			if (c$id$orig_h !in hosts[c$id$resp_h,c$id$resp_p]$ips)
				{
#If it isn't, this is someone we don't know/trust accessing ports they shouldn't.Log this to notice.log
				print "Unknown connection to baselined host";
				local note=TrafficBaselineException;
				local message=fmt("Unknown IPSRC connecting to baselined host. %s on port %s from %s .Investigate, and possibly include an entry for this host under the line for %s .", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$resp_h);
				local n: Notice::Info = Notice::Info($note=note,$msg=message,$conn=c,$identifier=cat(c$id$resp_h,c$id$resp_p,c$id$orig_h));
				NOTICE(n);
				}	
}}}
