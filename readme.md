# SpamPD - Spam Proxy Daemon

Originally released in May of 2002, _SpamPD_ is a program used within an e-mail delivery system to scan messages for possible Unsolicited Commercial E-mail (UCE, aka spam) content.
It uses an excellent program called <a href="https://spamassassin.apache.org/" target="_new">SpamAssassin</a> (SA) to do the actual message scanning. SpamPD acts as a transparent SMTP/LMTP proxy between
two mail servers, and during the transaction it passes the mail through SA. If SA decides the mail could be spam, then SpamPD will ask SA to
add some headers and a report to the message indicating it's spam and why.

SpamPD is written in Perl and should theoretically run on any platform supported by Perl and SpamAssassin.

Here's an un-solicited comment someone sent regarding *SpamPD* performance:

> Just to let you know: We have the SA/spampd combo up an running in a high volume environment. With 3 KAT-B Server (4x 2,5 GHz Xeon MP
with Hyperthreading, 3 GB RAM) we handle 15.000 to 20.000 Mails/h (Hour!) with room to spare. We had some performance issues with the
Bayes databases but now everything runs smoothly.

Check the [Releases](https://github.com/mpaperno/spampd/releases) area for latest versions,
and see the "previous-versions" folder for some more ancient ones. <br/>
(Note that the Debian package version was added to this repo as a branch, and those tags will also show up in the Releases page.)

Please read the [POD file](https://github.com/mpaperno/spampd/blob/master/spampd.pod) for full documentation of the many available options.
See the [changelog](https://github.com/mpaperno/spampd/blob/master/changelog.txt) for full version history.

## Package status

**HELP!** Debian package maintainer needed. Please see [GitHub Issue 46](https://github.com/mpaperno/spampd/issues/46).

Linux packages data courtesy of Repology:

<a href="https://repology.org/metapackage/spampd/versions" target="_new">
    <img src="https://repology.org/badge/vertical-allrepos/spampd.svg?minversion=2.61&header=Latest+release+v2.62" alt="Packaging status">
</a>

<h2>Usage</h2>
<p><i>SpamPD</i> was initially designed as a content filter mechanism for use with the <a href="http://www.postfix.org/"><i>Postfix</i></a> MTA.
However, it has no inherent dependencies on <i>Postfix</i> or any other MTA.
Some more specific setup information is provided <a href="https://github.com/mpaperno/spampd/blob/master/spampd.pod#installation-and-configuration">in the included documentation</a>.</p>

<h2>Version 2 Architecture</h2>
<p>Version 2 of <i>SpamPD</i> is a major rewrite of the underlying methods. <i>SpamPD</i>
 no longer acts as a relay server but more as a "transparent" proxy
server. That is, it never actually takes responsibility for the mail at
any point. Instead, the origination and destination mail servers speak
directly to each other. If a failure occurs within <i>SpamPD</i>
 (or SpamAssassin) during a transaction, then the mail servers will
disconnect and the sending server is still responsible for retrying the
message for as long as it is configured to do so. Responsibility for
mail delivery always lies with the 2 mail servers, which would be "real"
 MTAs and not a 500 line Perl script :-) This removes a major problem
with version 1 of <i>SpamPD</i>, and makes this a <u>recommended upgrade</u>.</p>
<p>While this is a much safer technique than previously employed, it does remove a possible feature which some users of <i>SpamPD</i>
 have implemented (sorry guys). That is redirecting spam to a spamtrap
address instead of letting the message through to the original
recipient. This is due to the fact that the recipient information is
passed on to the destination server before the message data is scanned
for spam. On the other hand it presents the possibility of rejecting
spam at the S/LMTP level without having to generate bounce notices and
such.</p>

<p><i>SpamPD</i> now fully supports the LMTP
 protocol (due to the nature of it's new transparency). Logging has been
 improved and is now more compatible with <code>spamd</code>.
 New parameters added: --children, --local-only, --childtimeout,
--satimeout, --dose, --log-rules-hit, --add-sc-header, and --hostname.
Three parameters are now deprecated: --dead-letters, --heloname, and
--stop-at-threshold.</p>
<p>More details and further changes are documented in the <a href="https://github.com/mpaperno/spampd/blob/master/changelog.txt">change log</a>.</p>

<h2>More Information</h2>

<p>If you aren't familiar with <a href="http://www.SpamAssassin.org/">SpamAssassin</a>,
 then you should definitely start there (or end up there) first. There
is a very helpful users discussion list for SA (see their site). For <a href="http://www.postfix.org/">Postfix</a> setup, be sure to read the FILTER_README document that is included with the distribution. <i>SpamPD</i> is meant to be used as an "advanced content filtering" method (some examples are included with the <i>SpamPD</i>
 documentation). Postfix also has a helpful users discussion list. Make
sure you do your homework before you ask other people to help you!</p>

<p>Be sure to check out the <a href="https://github.com/mpaperno/spampd/blob/master/spampd.pod"><i>SpamPD</i> documentation</a>, the <a href="https://github.com/mpaperno/spampd/blob/master/changelog.txt">change log</a>, as well as comments in the <a href="https://github.com/mpaperno/spampd/blob/master/spampd.pl">actual code.</a></p>

<h2>Credits</h2>
<p><i>SpamPD</i> is written and maintained by Maxim Paperno (<a href="https://github.com/mpaperno">https://github.com/mpaperno</a>).</p>
<p><i>SpamPD</i> contains code written by
Bennecode Todd (Copyright (C) 2001 Morgan Stanley Dean Witter) and is used
 in accordance with the GNU General Public License. The code is in the
form of two Perl modules which have been included in the program. Also
his <code>smtpproxy</code> example program served as inspiration for this version of <i>SpamPD</i>.</p>
<p><i>SpamPD</i> version 1 was based on code by Dave Carrigan named <a href="http://www.rudedog.org/assassind/"><code>assassind</code></a>. Trace amounts of his code or documentation may still remain. Thanks to him for the original inspiration and code.</p>
<p>Various people have contributed patches, bug reports, and ideas, all
of whom I would like to thank. I have tried to include credits in code
comments, documentation, and in the change log, as appropriate.</p>

<h2>Copyright, License, &amp; Disclaimer</h2>
<p>Copyright Maxim Paperno; All rights reserved.</p>
<p>Portions are Copyright © 2001 Morgan Stanley Dean Witter as mentioned above in the CREDITS section.</p>
<p>This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by the
 Free Software Foundation; either version 2 of the License, or (at your
option) any later version.</p>
<p>This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 Public License for more details.</p>
<p>The GNU GPL can be found at <a href="https://www.gnu.org/licenses/" target="_blank">https://www.gnu.org/licenses/</a></p>
