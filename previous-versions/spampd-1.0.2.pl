#! /usr/bin/perl

# spampd - spam proxy daemon
#
# v1.0.2 - added 'local-only' (13-Apr-03)
# v1.0.1 - minor bug fix (3-Feb-03)
# v1.0.0 - initial release (May 2002)
#
# Original assassind code by and Copyright (c) 2002 Dave Carrigan
#(see http://www.rudedog.org/assassind/)
# Changed and renamed to spampd by Maxim Paperno (MPaperno@WorldDesign.com)
#   whose contributions are placed in the Public Domain.
#(see http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm)
#
# 1.0.2 update:
# - added 'local-only' parameter to pass on to SA which turns off all network-based tests (DNS, Razor, etc).
#
# 1.0.1 update: 
# - fixed minor but substantial bug preventing child processes 
# from exiting properly since the counter wasn't being incremented (d'oh!).
# Thanks to Mark Blackman for pointing this out.
#
# - fixed typo in pod docs (Thx to James Sizemore for pointing out)
#
# Changes to assassind (1.0.0 initial release of spampd):
# A different message rewriting method (using 
#   Mail::SpamAssassin::NoMailAudit instead of Dave Carrigan's 
#   custom headers and Mail::Audit); 
# Adding more options for message handling, network/protocol options, 
#   some options to pass on to SpamAssassin (such as whitelist usage);
# More orientation to being used as a content filter for the 
#   Postfix MTA, mostly by changing some default values; 
# Documentation changes;
#

package SpamPD;

use strict;
use Net::Server::PreFork;
use IO::File;
use Getopt::Long;
use Net::SMTP;
use Net::SMTP::Server::Client;
use Mail::SpamAssassin;
use Mail::SpamAssassin::NoMailAudit;
use Error qw(:try);

our @ISA = qw(Net::Server::PreFork);
our $VERSION = '1.0.1';

sub dead_letter {
  my($self, $client, $message) = @_;

  my $filename = join("/", $self->{spampd}->{dead_letters},
		      sprintf("spampd.%d.%d.%f.dead", time(), $$, rand));

  my $dead = IO::File->new;
  unless ($dead->open(">$filename")) {
    $self->log(0, "Can't open dead letter file $filename: $!");
    return;
  }
  chmod 0600, $filename;

  try {
    if (defined $message) {
      $dead->print($message, "\r\n") or
	throw Error -text => "Can't print to dead letter: $!";
    }
    foreach (@{$client->{TO}}) {
      $dead->print("TO $_\r\n") or
	throw Error -text => "Can't print to dead letter: $!";
    }
    $dead->print("FROM ", $client->{FROM}, "\r\n\r\n") or
	throw Error -text => "Can't print to dead letter: $!";
    $dead->print($client->{MSG}) or
	throw Error -text => "Can't print to dead letter: $!";
  } catch Error with {
    my $e = shift;
    $self->log(0, "Warning!!!! Couldn't print dead letter: " . $e->stringify);
  };

  unless ($dead->close) {
    $self->log(0, "Warning!!!! Could not close the dead letter file: $!");
  }
}

sub relay_message {
  my($self, $client) = @_;
	
	my $start = time;
    my $msg_resp;

    # Now read in message
    my $message = $client->{MSG};
    
    # Skip processing message over n KB
    if ( length($message) < ($self->{spampd}->{maxsize} * 1024) ) {
    
		# prep the message (is this necessary?)
		my @msglines = split (/\r?\n/, $message);
		my $arraycont = @msglines; for(0..$arraycont) { $msglines[$_] .= "\r\n"; }

		# Audit the message
	    my $mail = Mail::SpamAssassin::NoMailAudit->new (
	                            data => \@msglines
	                     );

	    my $assassin = $self->{spampd}->{assassin};
	    # Check spamminess
	    my $status = $assassin->check($mail);
		#  Rewrite mail if high spam factor or option --tagall
		if ( $status->is_spam || $self->{spampd}->{tagall} ) { 
			$status->rewrite_mail; 
		}

	    # Build the message to send back
	    $msg_resp = join '',$mail->header,"\n",@{$mail->body};
    
		# Log what we did, FWIW
	    my $was_it_spam;
	    if($status->is_spam) { $was_it_spam = 'identified spam'; } else { $was_it_spam = 'clean message'; }
	    my $msg_score = int($status->get_hits);
	    my $msg_threshold = int($status->get_required_hits);
		$self->log(2, "$was_it_spam ($msg_score/$msg_threshold) in ". sprintf("%3d", time - $start) ." seconds.");

	    $status->finish();
    
    } else {
    
    	$msg_resp = $message;
		$self->log(2, "Scanning skipped due to size (". length($message) .")");

    }

  my $smtp = Net::SMTP->new($self->{spampd}->{relayhost}, Hello => $self->{spampd}->{heloname});
  unless (defined $smtp) {
    $self->log(1, "Connection to SMTP server failed");
    $self->dead_letter($client);
    return;
  }

  try {
    $smtp->mail($client->{FROM});
    throw Error -text => sprintf("Relay failed; server said %s %s",
				 $smtp->code, $smtp->message) unless $smtp->ok;

    foreach (@{$client->{TO}}) {
      $smtp->recipient($_);
      throw Error -text => sprintf("Relay failed; server said %s %s",
				   $smtp->code, $smtp->message) unless $smtp->ok;
    }

    $smtp->data($msg_resp);
    throw Error -text => sprintf("Relay failed; server said %s %s",
				 $smtp->code, $smtp->message) unless $smtp->ok;

    $smtp->quit;
    throw Error -text => sprintf("Relay failed; server said %s %s",
				 $smtp->code, $smtp->message) unless $smtp->ok;
    $self->log(4, "Message relayed successfully.");
  } catch Error with {
    my $e = shift;
    $self->dead_letter($client, $e->stringify);
  };
}

sub process_request {
  my $self = shift;
  my $client = Net::SMTP::Server::Client->new($self->{server}->{client});
  if ($client->process) {
    $self->log(2, "Received message from '".$client->{FROM}."'");
    $SIG{TERM} = sub {
      $self->dead_letter($client, "Process interrupted by SIGTERM");
    };
    $self->relay_message($client);
    $SIG{TERM} = sub { exit 0; };
  } else {
    $self->log(1, "An error occurred while receiving message");
  }
  $self->{spampd}->{instance} = 1 unless defined $self->{spampd}->{instance};
  exit 0 if $self->{spampd}->{instance}++ > $self->{spampd}->{maxrequests};
}

my $relayhost = '127.0.0.1';
my $host = '127.0.0.1';
my $port = 10025;
my $maxrequests = 20;
my $dead_letters = '/var/tmp';
my $pidfile = '/var/run/spampd.pid';
my $user = 'mail';
my $group = 'mail';
my $tagall = 0;
my $maxsize = 64;
my $heloname = 'spampd.localdomain';

my %options = (port => \$port,
	       host => \$host,
	       relayhost => \$relayhost,
	       'dead-letters' => \$dead_letters,
	       pid => \$pidfile,
	       user => \$user,
	       group => \$group,
	       maxrequests => \$maxrequests,
		   maxsize => \$maxsize,
		   heloname => \$heloname
		   );

usage(1) unless GetOptions(\%options,
			   'port=i',
			   'host=s',
			   'relayhost=s',
			   'maxrequests=i',
			   'dead-letters=s',
			   'user=s',
			   'group=s',
			   'pid=s',
			   'maxsize=i',
			   'heloname=s',
			   'tagall',
			   'auto-whitelist',
			   'stop-at-threshold',
			   'debug',
			   'help',
			   'local-only');
			   
usage(0) if $options{help};
if ( $options{tagall} ) { $tagall = 1; }

my $assassin = Mail::SpamAssassin->new({
						'dont_copy_prefs' => 1,
						'stop_at_threshold' => $options{'stop_at_threshold'} || 0,
  						'debug' => $options{'debug'} || 0,
  						'local_tests_only' => $options{'local-only'} || 0 });
						
$options{'auto-whitelist'} and eval {
   require Mail::SpamAssassin::DBBasedAddrList;

   # create a factory for the persistent address list
   my $addrlistfactory = Mail::SpamAssassin::DBBasedAddrList->new();
   $assassin->set_persistent_address_list_factory ($addrlistfactory);
};

$assassin->compile_now();
$/ = "\n";			# argh, Razor resets this!  Bad Razor!

my $server = bless {
		    server => {host => $host,
			       port => [ $port ],
			       log_file => 'Sys::Syslog',
			       syslog_ident => 'spampd',
			       syslog_facility => 'mail',
			       background => 1,
			       pid_file => $pidfile,
			       user => $user,
			       group => $group,
			      },
		    spampd => {maxrequests => $maxrequests,
				  relayhost => $relayhost,
				  dead_letters => $dead_letters,
				  tagall => $tagall,
				  maxsize => $maxsize,
				  assassin => $assassin,
				  heloname => $heloname,
				 },
		   }, 'SpamPD';
$server->run;

sub usage {
  print <<EOF ;
usage: $0 [ options ]

Options:
  --port=n                 Port to listen on. Defaults to 10025.
  --host=host              Hostname/IP to listen on. Default is 127.0.0.1
  --relayhost=host[:port]  Host to relay mail to. 
	                          Defaults to 127.0.0.1 on port 25.
  --heloname=hostname      Hostname to use in HELO command when sending mail. 
                              Defaults to 'spampd.localdomain'.

  --maxrequests=n          Maximum requests that each child can process before
                               exiting. Defaults to 20.
  --pid=filename           Store the daemon's process ID in this file. 
                              Default is /var/run/spampd.pid
  --user=username          Specifies the user that the daemon runs as.
                               Default is mail.
  --group=groupname        Specifies the group that the daemon runs as.
                               Default is mail.
  --dead-letters=path      Path to store letters that couldn't be relayed.
                              Defaults to /var/tmp.

  --maxsize=n              Maximum size of mail to scan (in KB).
                               Default is 64KB.
  --tagall                 Tag all messages with a header, not just spam.
 
  --auto-whitelist         Use the SA global auto-whitelist feature.
  --stop-at-threshold      Use SA feature to stop scanning once score
                               threshold is reached.
  --local-only             Turn off all SA network-based tests (DNS, Razor, etc).
  --debug                  Turn on SA debugging.
						   
  --help                   This message
EOF
  exit shift;
}

=pod

=head1 NAME

spampd - Spam Proxy Daemon

=head1 SYNOPSIS

B<spampd>
[B<--port=n>]
[B<--host=host>]
[B<--relayhost=hostname[:port]>]
[B<--heloname=hostname>]
[B<--user=username>]
[B<--group=groupname>]
[B<--maxrequests=n>]
[B<--dead-letters=/path>]
[B<--pid=filename>]
[B<--maxsize=n>]
[B<--tagall>]
[B<--auto-whitelist>]
[B<--stop-at-threshold>]
[B<--local-only>]
[B<--debug>]

B<spampd> B<--help>

=head1 DESCRIPTION

I<spampd> is a relaying SMTP proxy that filters spam using
SpamAssassin (http://www.SpamAssassin.org). The proxy is designed
to be robust in the face of exceptional errors, and will (hopefully) 
never lose a message.

I<spampd> uses SpamAssassin to modify (tag) relayed messages based on 
their spam score, so all SA settings apply. This is described in the SA 
documentation.  I<spampd> will by default only tell SA to tag a 
message if it exceeds the spam threshold score, however you can have 
it rewrite all messages passing through by adding the --tagall option 
(see SA for how non-spam messages are tagged).

I<spampd> logs all aspects of its operation to syslog(8), using the
mail syslog facility.

=head1 REQUIRES

Perl modules:

B<Error>

B<Mail::SpamAssassin>

B<Net::Server>

B<Net::SMTP>


=head1 OPERATION

I<spampd> is meant to operate as an SMTP mail relay which passes
each message through SpamAssassin for analysis.  Note that I<spampd>
does not do anything other than check for spam, so it is not suitable as
an anti-relay system.  It is meant to work in conjunction with your
regular mail system.  Typically one would pipe any messages they wanted
scanned through I<spampd> after initial acceptance by your MX host.
This is especially useful for using Postfix's (http://www.postfix.org) 
advanced content filtering mechanism, although certainly not limited to 
that application.

Please re-read the second sentence in the above paragraph.  You should NOT
enable I<spampd> to listen on a public interface (IP address) unless you
know exactly what you're doing!

Here are some simple examples (square brackets in the "diagrams" indicate
physical machines):

=over 5

=item Running between firewall/gateway and internal mail server

The firewall/gateway MTA would be configured to forward all of its mail 
to the port that I<spampd> listens on, and I<spampd> would relay its 
messages to port 25 of your internal server. I<spampd> could either 
run on its own host (and listen on any port) or it could run on either 
mail server (and listen on any port except port 25).

Internet -> [ MX gateway (@inter.net.host:25) -> 
    I<spampd> (@localhost:2025) ] ->
	Internal mail (@private.host.ip:25)


=item Using Postfix advanced content filtering

Please see the FILTER_README that came with the Postfix distribution.  You
need to have a version of Postfix which supports this.

Internet -> [ I<Postfix> (@inter.net.host:25) -> 
    I<spampd> (@localhost:10025) -> 
    I<Postfix> (@localhost:10026) ] -> final delivery

=back

Note that these examples only show incoming mail delivery.  Since it is 
usually unnecessary to scan mail coming from your network (right?),
it may be desirable to set up a separate outbound route which bypasses
I<spampd>.

=head1 OPTIONS

=over 5

=item B<--port=n>

Specifies what port I<spampd> listens on. By default, it listens on
port 10025.

=item B<--host=ip>

Specifies what interface/IP I<spampd> listens on. By default, it listens on
127.0.0.1 (localhost). 

B<Important!> You should NOT enable I<spampd> to listen on a
public interface (IP address) unless you know exactly what you're doing!

=item B<--relayhost=hostname[:port]>

Specifies the hostname where I<spampd> will relay all
messages. Defaults to 127.0.0.1. If the port is not provided, that
defaults to 25.

=item B<--heloname=hostname>

Hostname to use in HELO command when sending mail. Default is 
'spampd.localdomain'. The HELO name may show up in the
Received headers of any processed message, depending on your setup.

=item B<--user=username>

=item B<--group=groupname>

Specifies the user and group that the proxy will run as. Default is
I<mail>/I<mail>.

=item B<--maxrequests=n>

I<spampd> works by forking child servers to handle each message. The
B<maxrequests> parameter specifies how many requests will be handled
before the child exits. Since a child never gives back memory, a large
message can cause it to become quite bloated; the only way to reclaim
the memory is for the child to exit. The default is 20.

=item B<--dead-letters=/path>

Specifies the directory where I<spampd> will store any message that
it fails to deliver. The default is F</var/tmp>. You should periodically
examine this directory to see if there are any messages that couldn't be
delivered.

B<Important!> This path should not be on the same partition as your mail
server's message spool, because if your mail server rejects a message
because of a full disk, I<spampd> will not be able to save the
message, and it will be lost.

=item B<--pid=filename>

Specifies a filename where I<spampd> will write its process ID so
that it is easy to kill it later. The directory that will contain this
file must be writable by the I<spampd> user. The default is
F</var/run/spampd.pid>.

=item B<--tagall>

Tells I<spampd> to have SpamAssassin add headers to all scanned mail,
not just spam.  By default I<spampd> will only rewrite messages which 
exceed the spam threshold score (as defined in the SA settings).

=item B<--maxsize=n>

The maximum message size to send to SpamAssassin, in KB.  By default messages
over 64KB are not scanned at all, and an appropriate message is logged
indicating this.  This includes headers.

=item B<--auto-whitelist>

Turns on the SpamAssassin global whitelist feature.  See the SA docs. Note
that per-user whitelists are not available.

=item B<--stop-at-threshold>

Turns on the SpamAssassin (v2.20 and up) "stop at threshold" feature which 
stops any further scanning of a message once the minimum spam score 
is reached. See the SA docs for more info.

=item B<--local-only>

Turn off all SA network-based tests (DNS, Razor, etc).

=item B<--debug>

Turns on SpamAssassin debug messages.

=item B<--help>

Prints usage information.

=back

=head1 EXAMPLES

=over 5

=item Running between firewall/gateway and internal mail server


I<spampd> listens on port 10025 on the same host as the internal mail server.

  spampd --host=192.168.1.10

Same as above but I<spampd> runs on port 10025 of the same host as 
the firewall/gateway and passes messages on to the internal mail server 
on another host.

  spampd --relayhost=192.168.1.10

=item Using Postfix advanced content filtering example
and the SA auto-whitelist feature

  spampd --port=10025 --relayhost=127.0.0.1:10026 --auto-whitelist

=back

=head1 AUTHORS

Based on I<assassind> by Dave Carrigan, <dave@rudedog.org>
see http://www.rudedog.org/assassind/

Modified and renamed to I<spampd> (to avoid confusion) by 
Maxim Paperno, <MPaperno@WorldDesign.com>.  My modifications are mostly
based on code included with the SpamAssassin distribution, namely spamd
and spamproxy.

=head1 COPYRIGHT AND DISCLAIMER

Portions of this program are Copyright © 2002, Dave Carrigan, all rights
reserved. Other contributions can be considered Public Domain property.
This program is free software; you can redistribute it and/or
modify it under the same terms as Perl.

This program is distributed "as is", without warranty of any kind,
either expressed or implied, including, but not limited to, the implied
warranties of merchantability and fitness for a particular purpose.  The
entire risk as to the quality and performance of the program is with
you. Should the program prove defective, you assume the cost of all
necessary servicing, repair or correction.

=head1 BUGS

Due to the nature of Perl's SMTP::Server module, an SMTP message is
stored completely in memory. However, as soon as the module receives its
entire message data from the SMTP client, it returns a 250, signifying
to the client that the message has been delivered. This means
that there is a period of time where the message is vulnerable to being
lost if the I<spampd> process is killed before it has relayed or
saved the message. Caveat Emptor!

No message loop protection.

Net::SMTP::Server::Client has a "problem" with spaces in email addresses.
For example during the SMTP dialog, if a mail is 
FROM:<"some spammer"@some.dom.ain> the address gets truncated after
the first space to just '<"some' .  This causes a problem when relaying
the message to the receiving server, because the sender address is now
in an illegal format. The mail is then rejected, and it ends
up in the dead-letters directory.  I have actually seen this happen several
times, and of course they were bogus messages each time.  I don't believe
there are any legitimate envelope email addresses with spaces in them,
so don't see this as much of an issue (except that it's un elegant).


=head1 TO DO

Add option for extracting recipient address(es) and using SpamAssassin's
SQL lookup capability check for user-specific preferences.

Deal with above bugs.

=head1 SEE ALSO

perl(1), Spam::Assassin(3), http://www.spamassassin.org/, 
http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm, http://www.rudedog.org/assassind/
