# SpamPD

Originally released in May of 2002, SpamPD is a program used within an e-mail delivery system to scan messages for possible Unsolicited Commercial E-mail (UCE, aka spam) content. 
It uses an excellent program called <a href="https://spamassassin.apache.org/" target="_new">SpamAssassin</a> (SA) to do the actual message scanning. SpamPD acts as a transparent SMTP/LMTP proxy between 
two mail servers, and during the transaction it passes the mail through SA. If SA decides the mail could be spam, then SpamPD will ask SA to 
add some headers and a report to the message indicating it's spam and why. SpamPD is written in Perl and should theoretically run on any 
platform supported by Perl and SpamAssassin.

Check the [Releases](https://github.com/mpaperno/spampd/releases) area for latest versions, and see the old 
<a href="https://github.com/mpaperno/spampd/downloads">Downloads</a> section for older releases. 
Recently the Debian package version was added to this repo as a branch, and those tags will also show up in the Releases page.

Please read the [POD file](https://github.com/mpaperno/spampd/blob/master/spampd.pod) for full documentation of the many available options. 
See the [changelog](https://github.com/mpaperno/spampd/blob/master/changelog.txt) for version history.

More historic background information is available <a href="http://www.worlddesign.com/index.cfm/page/rd/mta/spampd.htm">here</a>.

Linux packages data courtesy of Repology:

<a href="https://repology.org/metapackage/spampd/versions" target="_new">
    <img src="https://repology.org/badge/vertical-allrepos/spampd.svg?minversion=2.60&header=Latest+release+v2.60" alt="Packaging status">
</a>
