# SpamPD

__NOTE: please see Download section for official release versions.  The repository version IS NOT THOUROUGHLY TESTED.__

__Testers wanted!__

spampd is a program used within an e-mail delivery system to scan messages for possible Unsolicited Commercial E-mail (UCE, aka spam) content. 
It uses an excellent program called SpamAssassin (SA) to do the actual message scanning. spampd acts as a transparent SMTP/LMTP proxy between 
two mail servers, and during the transaction it passes the mail through SA. If SA decides the mail could be spam, then spampd will ask SA to 
add some headers and a report to the message indicating it's spam and why. spampd is written in Perl and should theoretically run on any 
platform supported by Perl and SpamAssassin.

More information is available at <a href="http://www.worlddesign.com/index.cfm/page/rd/mta/spampd.htm">here</a>.

