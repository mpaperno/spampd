#! /usr/bin/perl

######################
# SpamPD - spam proxy daemon
#
# v2.00  - 8-June-03
# v1.0.2 - 13-Apr-03
# v1.0.1 - 3-Feb-03
# v1.0.0 - May 2002
#
# spampd is Copyright (c) 2002 by World Design Group and Maxim Paperno
#  (see http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm)
#
# Written and maintained by Maxim Paperno (MPaperno@WorldDesign.com)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    The GNU GPL can be found at http://www.fsf.org/copyleft/gpl.html
#
# spampd v2 uses two Perl modules by Bennett Todd and Copyright (C) 2001 Morgan 
#   Stanley Dean Witter. These are also distributed under the GNU GPL (see
#   module code for more details). Both modules have been slightly modified 
#   from the originals and are included in this file under new names.
#
# spampd v1 was based on code by Dave Carrigan named assassind. Trace amounts
#   of his code or documentation may still remain. Thanks to him for the
#   original inspiration and code. (see http://www.rudedog.org/assassind/)
#
######################


################################################################################
package SpamPD::Server;

#   Originally known as MSDW::SMTP::Server
#
#   This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#   is distributed according to the terms of the GNU Public License
#   as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#   Modified for use in SpamPD by Maxim Paperno (June, 2003)
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Bennett Todd <bet@rahul.net>

# =item DESCRIPTION
#
# This server simply gathers the SMTP acquired information (envelope
# sender and recipient, and data) into unparsed memory buffers (or a
# file for the data), and returns control to the caller to explicitly
# acknowlege each command or request. Since acknowlegement or failure
# are driven explicitly from the caller, this module can be used to
# create a robust SMTP content scanning proxy, transparent or not as
# desired.
#
# =cut

use strict;
use IO::File;
#use IO::Socket;

# =item new(interface => $interface, port => $port);

# The #interface and port to listen on must be specified. The interface
# must be a valid numeric IP address (0.0.0.0 to listen on all
# interfaces, as usual); the port must be numeric. If this call
# succeeds, it returns a server structure with an open
# IO::Socket::INET in it, ready to listen on. If it fails it dies, so
# if you want anything other than an exit with an explanatory error
# message, wrap the constructor call in an eval block and pull the
# error out of $@ as usual. This is also the case for all other
# methods; they succeed or they die.
#
# =cut

sub new {
	
# This now emulates Net::SMTP::Server::Client for use with Net::Server which
# passes an already open socket.

    my($this, $socket) = @_;
    
    my $class = ref($this) || $this;
    my $self = {};
    $self->{sock} = $socket;
    
    bless($self, $class);
    
    die "$0: socket bind failure: $!\n" unless defined $self->{sock};
    $self->{state} = 'just bound';
    return $self;
 
#    Original code, removed by MP for spampd use
#
#     my ($this, @opts) = @_;
#     my $class = ref($this) || $this;
#     my $self = bless { @opts }, $class;
#     $self->{sock} = IO::Socket::INET->new(
# 	LocalAddr => $self->{interface},
# 	LocalPort => $self->{port},
# 	Proto => 'tcp',
# 	Type => SOCK_STREAM,
# 	Listen => 65536,
# 	Reuse => 1,
#     );
#     die "$0: socket bind failure: $!\n" unless defined $self->{sock};
#     $self->{state} = 'just bound',
#     return $self;
    
}

# =item accept([debug => FD]);
#
# accept takes optional args and returns nothing. If an error occurs
# it dies, otherwise it returns when a client connects to this server.
# This is factored out as a separate entry point to allow preforking
# (e.g. Apache-style) or fork-per-client strategies to be implemented
# on the common protocol core. If a filehandle is passed for debugging
# it will receive a complete trace of the entire SMTP dialogue, data
# and all. Note that nothing in this module sends anything to the
# client, including the initial login banner; all such backtalk must
# come from the calling program.
#
# =cut

# sub accept {
#     my ($self, @opts) = @_;
#     %$self = (%$self, @opts);
#     #($self->{"s"}, $self->{peeraddr}) = $self->{sock}->accept
#     $self->{"s"} = $self->{sock}
# 	  or die "$0: accept failure: $!\n";
#     $self->{state} = ' accepted';
# }


# =item chat;
#
# The chat method carries the SMTP dialogue up to the point where any
# acknowlegement must be made. If chat returns true, then its return
# value is the previous SMTP command. If the return value begins with
# 'mail' (case insensitive), then the attribute 'from' has been filled
# in, and may be checked; if the return value begins with 'rcpt' then
# both from and to have been been filled in with scalars, and should
# be checked, then either 'ok' or 'fail' should be called to accept
# or reject the given sender/recipient pair. If the return value is
# 'data', then the attributes from and to are populated; in this case,
# the 'to' attribute is a reference to an anonymous array containing
# all the recipients for this data. If the return value is '.', then
# the 'data' attribute (which may be pre-populated in the "new" or
# "accept" methods if desired) is a reference to a filehandle; if it's
# created automatically by this module it will point to an unlinked
# tmp file in /tmp. If chat returns false, the SMTP dialogue has been
# completed and the socket closed; this server is ready to exit or to
# accept again, as appropriate for the server style.
#
# The return value from chat is also remembered inside the server
# structure in the "state" attribute.
#
# =cut

sub chat {
    my ($self) = @_;
    local(*_);
    if ($self->{state} !~ /^data/i) {
		return 0 unless defined($_ = $self->_getline);
		s/[\r\n]*$//;
		$self->{state} = $_;
		if (s/^helo\s+//i) {
		    s/\s*$//;s/\s+/ /g;
		    $self->{helo} = $_;
		} elsif (s/^rset\s*//i) {
		    delete $self->{to};
		    delete $self->{data};
		    delete $self->{recipients};
		} elsif (s/^mail\s+from:\s*//i) {
		    delete $self->{to};
		    delete $self->{data};
		    delete $self->{recipients};
		    s/\s*$//;
		    $self->{from} = $_;
		} elsif (s/^rcpt\s+to:\s*//i) {
		    s/\s*$//; s/\s+/ /g;
		    $self->{to} = $_;
		    push @{$self->{recipients}}, $_;
		} elsif (/^data/i) {
		    $self->{to} = $self->{recipients};
		}
    } else {
		if (defined($self->{data})) {
		    $self->{data}->seek(0, 0);
		    $self->{data}->truncate(0);
		    # $self->{data} = undef;
		} else {
		    $self->{data} = IO::File->new_tmpfile;
		    # $self->{data} = undef;
		}
		while (defined($_ = $self->_getline)) {
		    if ($_ eq ".\r\n") {
			  $self->{data}->seek(0,0);
			  return $self->{state} = '.';
		    }
		    s/^\.\./\./;
		    $self->{data}->print($_) or die "$0: write error saving data\n";
		    # $self->{data} .= $_;
		}
		return(0);
    }
    return $self->{state};
}

# =item ok([message]);
#
# Approves of the data given to date, either the recipient or the
# data, in the context of the sender [and, for data, recipients]
# already given and available as attributes. If a message is given, it
# will be sent instead of the internal default.
#
# =cut

sub ok {
    my ($self, @msg) = @_;
    @msg = ("250 ok.") unless @msg;
    $self->_print("@msg\r\n") or
	  die "$0: write error acknowledging $self->{state}: $!\n";
}

# =item fail([message]);
#
# Rejects the current info; if processing from, rejects the sender; if
# processing 'to', rejects the current recipient; if processing data,
# rejects the entire message. If a message is specified it means the
# exact same thing as "ok" --- simply send that message to the sender.
#
# =cut

sub fail {
    my ($self, @msg) = @_;
    @msg = ("550 no.") unless @msg;
    $self->_print("@msg\r\n") or
	  die "$0: write error acknowledging $self->{state}: $!\n";
}

# utility functions

sub _getline {
    my ($self) = @_;
    local ($/) = "\r\n";
    my $tmp = $self->{sock}->getline;
    if ( defined $self->{debug} ) {
      $self->{debug}->print($tmp) if ($tmp);
    }
    return $tmp;
}

sub _print {
    my ($self, @msg) = @_;
    $self->{debug}->print(@msg) if defined $self->{debug};
    $self->{sock}->print(@msg);
}

1;

################################################################################
package SpamPD::Client;

#   Originally known as MSDW::SMTP::Client
#
#   This code is Copyright (C) 2001 Morgan Stanley Dean Witter, and
#   is distributed according to the terms of the GNU Public License
#   as found at <URL:http://www.fsf.org/copyleft/gpl.html>.
#
#   Modified for use in SpamPD by Maxim Paperno (June, 2003)
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
# Written by Bennett Todd <bet@rahul.net>

# =head1 DESCRIPTION
#
# MSDW::SMTP::Client provides a very lean SMTP client implementation;
# the only protocol-specific knowlege it has is the structure of SMTP
# multiline responses. All specifics lie in the hands of the calling
# program; this makes it appropriate for a semi-transparent SMTP
# proxy, passing commands between a talker and a listener.
#
# =cut

use strict;
use IO::Socket;

# =item new(interface => $interface, port => $port[, timeout = 300]);
#
# The interface and port to talk to must be specified. The interface
# must be a valid numeric IP address; the port must be numeric. If
# this call succeeds, it returns a client structure with an open
# IO::Socket::INET in it, ready to talk to. If it fails it dies,
# so if you want anything other than an exit with an explanatory
# error message, wrap the constructor call in an eval block and pull
# the error out of $@ as usual. This is also the case for all other
# methods; they succeed or they die. The timeout parameter is passed
# on into the IO::Socket::INET constructor.
#
# =cut

sub new {
    my ($this, @opts) = @_;
    my $class = ref($this) || $this;
    my $self = bless { timeout => 300, @opts }, $class;
    $self->{sock} = IO::Socket::INET->new(
			PeerAddr => $self->{interface},
			PeerPort => $self->{port},
			Timeout => $self->{timeout},
			Proto => 'tcp',
			Type => SOCK_STREAM,
	    );
    die "$0: socket connect failure: $!\n" unless defined $self->{sock};
    return $self;
}

# =item hear
#
# hear collects a complete SMTP response and returns it with trailing
# CRLF removed; for multi-line responses, intermediate CRLFs are left
# intact. Returns undef if EOF is seen before a complete reply is
# collected.
#
# =cut

sub hear {
    my ($self) = @_;
    my ($tmp, $reply);
    return undef unless $tmp = $self->{sock}->getline;
    while ($tmp =~ /^\d{3}-/) {
		$reply .= $tmp;
		return undef unless $tmp = $self->{sock}->getline;
    }
    $reply .= $tmp;
    $reply =~ s/\r\n$//;
    return $reply;
}

# =item say("command text")
#
# say sends an SMTP command, appending CRLF.
#
# =cut

sub say {
    my ($self, @msg) = @_;
    return unless @msg;
    $self->{sock}->print("@msg", "\r\n") or die "$0: write error: $!";
}

# =item yammer(FILEHANDLE)
#
# yammer takes a filehandle (which should be positioned at the
# beginning of the file, remember to $fh->seek(0,0) if you've just
# written it) and sends its contents as the contents of DATA. This
# should only be invoked after a $client->say("data") and a
# $client->hear to collect the reply to the data command. It will send
# the trailing "." as well. It will perform leading-dot-doubling in
# accordance with the SMTP protocol spec, where "leading dot" is
# defined in terms of CR-LF terminated lines --- i.e. the data should
# contain CR-LF data without the leading-dot-quoting. The filehandle
# will be left at EOF.
#
# =cut

sub yammer {
    my ($self, $fh) = (@_);
    local (*_);
    local ($/) = "\r\n";
    while (<$fh>) {
	  s/^\./../;
	  $self->{sock}->print($_) or die "$0: write error: $!\n";
    }
    $self->{sock}->print(".\r\n") or die "$0: write error: $!\n";
}

1;


################################################################################
package SpamPD;

use strict;
use Net::Server::PreFork;
use IO::File;
use Getopt::Long;
# use Net::SMTP;
# use Net::SMTP::Server::Client;
use Mail::SpamAssassin;
use Mail::SpamAssassin::NoMailAudit;
# use Error qw(:try);

BEGIN { 
	import SpamPD::Server;
	import SpamPD::Client;
}

use vars qw(@ISA $VERSION);
our @ISA = qw(Net::Server::PreFork);
our $VERSION = '2.00';

sub process_message {
	my ($self, $fh) = @_;
	
	my $start = time;

    # this gets info about the message file
    (my $dev,my $ino,my $mode,my $nlink,my $uid,
    	my $gid,my $rdev,my $size,
		my $atime,my $mtime,my $ctime,
		my $blksize,my $blocks) = $fh->stat or die "Can't stat mail file: $!";
    
    # Only process message under --maxsize KB
    if ( $size < ($self->{spampd}->{maxsize} * 1024) ) {
	    
		# read message into array of lines to feed to SA
		# notes in the SA::NoMailAudit code indicate it should take a
		# filehandle... but that doesn't seem to work
	    my(@msglines);
	    $fh->seek(0,0) or die "Can't rewind message file: $!";
		while (<$fh>) { push(@msglines,$_); }
    
		# Audit the message
	    my $mail = Mail::SpamAssassin::NoMailAudit->new (
	                            data => \@msglines
	                     );

	    # use the assassin object created during startup
	    my $assassin = $self->{spampd}->{assassin};
	    
	    # Check spamminess
	    my $status = $assassin->check($mail);
	    
		#  Rewrite mail if high spam factor or option --tagall
		if ( $status->is_spam || $self->{spampd}->{tagall} ) { 
			$status->rewrite_mail; 
			
		    # Build the new message to relay
		    my $msg_resp = join '',$mail->header,"\r\n",@{$mail->body};
		    my @resplines = split(/\r?\n/, $msg_resp);
		    my $arraycont = @resplines; 
		    $fh->seek(0,0) or die "Can't rewind message file: $!";
		    $fh->truncate(0) or die "Can't truncate message file: $!";
			for (0..$arraycont) { $fh->print($resplines[$_] . "\r\n"); }
    
		}

		# Log what we did
	    my $was_it_spam = 'clean message';
	    if($status->is_spam) { $was_it_spam = 'identified spam'; }
	    my $msg_score = sprintf("%.1f",$status->get_hits);
	    my $msg_threshold = sprintf("%.1f",$status->get_required_hits);
		$self->log(2, "$was_it_spam ($msg_score/$msg_threshold) in ". 
							sprintf("%.1f", time - $start) ." seconds.");

	    $status->finish();
    
    } else {
    
		$self->log(2, "Scanning skipped due to size (". $size / 1024 ."KB)");

    }
    
    return 1;

}

sub process_request {
  my $self = shift;
  my $msg;
  	
  eval {
	
	local $SIG{ALRM} = sub { die "Child server process timed out!\n" };
	my $timeout = $self->{spampd}->{childtimeout};
	
	# start a timeout alarm  
	alarm($timeout);
	
	# start an smtp server
	my $smtp_server = SpamPD::Server->new($self->{server}->{client});
	unless ( defined $smtp_server ) {
	  die "WARNING!! Failed to create listening Server: $!"; }
	
	# start an smtp "client" (really a sending server)
	my $client = SpamPD::Client->new(interface => $self->{spampd}->{relayhost}, 
					   port => $self->{spampd}->{relayport});
	unless ( defined $client ) {
	  die "WARNING!! Failed to create sending Client: $!"; }

	# pass on initial client response
	$smtp_server->ok($client->hear)
		or die "WARNING!! Error in initial server->ok(client->hear): $!";
		
	# while loop over incoming data from the server
	while ( my $what = $smtp_server->chat ) {
		
	  # until end of DATA is sent, just pass the commands on transparently
	  if ($what ne '.') {
		  
	    $client->say($what)
		  or die "WARNING!! Failure in client->say(what): $!";

	  # but once the data is sent now we want to process it
	  } else {

		# spam checking routine - message might be rewritten here
	    $self->process_message($smtp_server->{data})
	    	or die "WARNING!! Error processing message (process_message(data)): $!";
	    
	    # $self->log(0, $smtp_server->{data}); #debug
	
	    # need to give the client a rewound file
	    $smtp_server->{data}->seek(0,0)
			or die "WARNING!! Can't rewind mail file: $!";
	    
	    # now send the data on through the client
	    $client->yammer($smtp_server->{data})
		  or die "WARNING!! Failure in client->yammer(smtp_server->{data}): $!";
		  
		#close the file
		$smtp_server->{data}->close
			or die "WARNING!! Couldn't close smtp_server->{data} temp file: $!";

	  }

	  # pass on whatever the relayhost said in response
	  $smtp_server->ok($client->hear)
		or die "WARNING!! Error in server->ok(client->hear): $!";
	  
	  # restart the timeout alarm  
	  alarm($timeout);
		
	} # server ends connection

    # close connections
    $client->{sock}->close
			or die "WARNING!! Couldn't close client->{sock}: $!";
    $smtp_server->{sock}->close
			or die "WARNING!! Couldn't close smtp_server->{sock}: $!";

  }; # end eval block
  
  alarm(0);  # stop the timer
  # check for error in eval block
  if ($@ ne '') {
	  chomp($@);
	  $msg = "WARNING!! Error in process_request eval block: $@";
	  $self->log(0, $msg);
	  die ($msg . "\n");
  }
  
  $self->{spampd}->{instance} = 1 unless defined $self->{spampd}->{instance};
  exit 0 if $self->{spampd}->{instance}++ > $self->{spampd}->{maxrequests};
}

my $relayhost = '127.0.0.1'; # relay to ip
my $relayport = 25; # relay to port
my $host = '127.0.0.1'; # listen on ip
my $port = 10025; # listen on port
my $maxrequests = 20; # max requests handled by child b4 dying
my $childtimeout = 5*60; # child process per-command timeout in seconds
my $pidfile = '/var/run/spampd.pid'; # write pid to file
my $user = 'mail'; # user to run as
my $group = 'mail'; # group to run as
my $tagall = 0; # mark-up all msgs with SA, not just spam
my $maxsize = 64; # max. msg size to scan with SA, in KB.

# the following are deprecated as of v.2
my $heloname = '';
my $dead_letters = '';

my %options = (port => \$port,
	       host => \$host,
	       relayhost => \$relayhost,
	       relayport => \$relayport,
	       'dead-letters' => \$dead_letters,
	       pid => \$pidfile,
	       user => \$user,
	       group => \$group,
	       maxrequests => \$maxrequests,
	       maxsize => \$maxsize,
	       heloname => \$heloname,
	       childtimeout => \$childtimeout
	      );

usage(1) unless GetOptions(\%options,
		   'port=i',
		   'host=s',
		   'relayhost=s',
		   'relayport=i',
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
		   'local-only',
		   'childtimeout=i');
			   
usage(0) if $options{help};

if ( $options{tagall} ) { $tagall = 1; }

my @tmp = split (/:/, $relayhost);
$relayhost = $tmp[0];
if ( $tmp[1] ) { $relayport = $tmp[1]; }

@tmp = split (/:/, $host);
$host = $tmp[0];
if ( $tmp[1] ) { $port = $tmp[1]; }


my $assassin = Mail::SpamAssassin->new({
		'dont_copy_prefs' => 1,
		'debug' => $options{'debug'} || 0,
		'local_tests_only' => $options{'local-only'} || 0 });

# 'stop_at_threshold' => $options{'stop_at_threshold'} || 0,
			
$options{'auto-whitelist'} and eval {
   require Mail::SpamAssassin::DBBasedAddrList;

   # create a factory for the persistent address list
   my $addrlistfactory = Mail::SpamAssassin::DBBasedAddrList->new();
   $assassin->set_persistent_address_list_factory ($addrlistfactory);
};

$assassin->compile_now();

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
    spampd => { maxrequests => $maxrequests,
		relayhost => $relayhost,
		relayport => $relayport,
		tagall => $tagall,
		maxsize => $maxsize,
		assassin => $assassin,
		childtimeout => $childtimeout
		},
   }, 'SpamPD';
		   
# call Net::Server to do the rest
$server->run;

exit 1;  # shouldn't need this

sub usage {
  print <<EOF ;
usage: $0 [ options ]

Options:
  --host=host[:port]       Hostname/IP and optional port to listen on. 
	                          Default is 127.0.0.1 port 10025
  --port=n                 Port to listen on (alternate syntax to above).
  --relayhost=host[:port]  Host to relay mail to. 
	                          Default is 127.0.0.1 port 25.
  --relayport=n            Port to relay to (alternate syntax to above).
  
  --maxrequests=n          Maximum requests that each child can process before
                               exiting. Default is 20.
  --childtimeout=n         Time out children after this many seconds during
                               transactions (each S/LMTP command including the
                               time it takes to send the data). 
                               Default is 300 seconds (5min).
                               
  --pid=filename           Store the daemon's process ID in this file. 
                              Default is /var/run/spampd.pid
  --user=username          Specifies the user that the daemon runs as.
                               Default is mail.
  --group=groupname        Specifies the group that the daemon runs as.
                               Default is mail.

  --maxsize=n              Maximum size of mail to scan (in KB).
                               Default is 64KB.
  --tagall                 Tag all messages with a header, not just spam.
 
  --auto-whitelist         Use the SA global auto-whitelist feature.
  --local-only             Turn off all SA network-based tests (RBL, Razor, etc).
  --debug                  Turn on SA debugging (sent to STDERR).
						   
  --help                   This message
  
Deprecated Options (still accepted for backwards compatibility):
  --heloname=hostname      No longer used in spampd v.2
  --dead-letters=path      No longer used in spampd v.2
  --stop-at-threshold      No longer implemented in SpamAssassin
EOF
  exit shift;
}

__END__

=pod

=head1 Name

spampd - Spam Proxy Daemon (version 2)

=head1 Synopsis

B<spampd>
[B<--host=host[:port]>]
[B<--relayhost=hostname[:port]>]
[B<--user=username>]
[B<--group=groupname>]
[B<--maxrequests=n>]
[B<--childtimeout=n>]
[B<--pid=filename>]
[B<--maxsize=n>]
[B<--tagall>]
[B<--auto-whitelist>]
[B<--local-only>]
[B<--debug>]

B<spampd> B<--help>

=head1 Description

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

The latest version can be found at 
http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm

=head1 Requires

=over 5

Perl modules:

=item B<Mail::SpamAssassin>

=item B<Net::Server::PreFork>

=item B<IO::File>

=item B<IO::Socket>

=back

=head1 Operation

I<spampd> is meant to operate as an SMTP mail proxy which passes
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
know exactly what you're doing!  It is very easy to set up an open relay this
way.

Note that I<spampd> U<replaces> I<spamd> from the I<SpamAssassin> distribution
in function. You do not need to run I<spamd> in order for I<spampd> to function.

Here are some simple examples (square brackets in the "diagrams" indicate
physical machines):


B<Running between firewall/gateway and internal mail server>

=over 3

The firewall/gateway MTA would be configured to forward all of its mail 
to the port that I<spampd> listens on, and I<spampd> would relay its 
messages to port 25 of your internal server. I<spampd> could either 
run on its own host (and listen on any port) or it could run on either 
mail server (and listen on any port except port 25).

Internet -> [ MX gateway (@inter.net.host:25) -> 
	I<spampd> (@localhost:2025) ] ->
	Internal mail (@private.host.ip:25)

=back

B<Using Postfix advanced content filtering>

=over 3

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


=head1 Installation

I<spampd> can be run directly from the command prompt if desired.  This is
useful for testing purposes, but for long term use you probably want to put
it somewhere like /usr/bin or /usr/local/bin and execute it at system startup.
For example on Red Hat-style Linux system one can use a script in 
/etc/rc.d/init.d to start I<spampd> (a sample script is available on the 
I<spampd> Web page @ http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm).

Note that I<spampd> B<replaces> I<spamd> from the I<SpamAssassin> distribution
in function. You do not need to run I<spamd> in order for I<spampd> to function.
This has apparently been the source of some confusion, so now you know.

=head2 Postfix-specific Notes

Here is a typical setup for Postfix "advanced" content filtering as described
in the FILTER_README that came with the Postfix distribution:

 F</etc/postfix/master.cf>:
 
 smtp	inet	n	-	y	-	-	smtpd
 	-o content_filter=smtp:localhost:10025
	-o myhostname=mx.example.com

 localhost:10026	inet	n	-	n	-	10	smtpd
 	-o content_filter=
 	-o myhostname=mx-int.example.com

The first entry is the main public-facing MTA which uses localhost:10025
as the content filter for all mail.	The second entry receives mail from
the content filter and does final delivery.  Both smtpd instances use
the same Postfix F<main.cf> file.  I<spampd> is the process that listens on
localhost:10025 and then connects to the Postfix listener on localhost:10026.
Note that the C<myhostname> options must be different between the two instances,
otherwise Postfix will think it's talking to itself and abort sending.

For the above example you can simply start I<spampd> like this:

 spampd --host=localhost:10025 --relayhost=localhost:10026

=head1 Options

=over 5

=item B<--host=ip or hostname[:port]>

Specifies what hostname/IP and port I<spampd> listens on. By default, it listens
on 127.0.0.1 (localhost) on port 10025. 

B<Important!> You should NOT enable I<spampd> to listen on a
public interface (IP address) unless you know exactly what you're doing!

=item B<--port=n>

Specifies what port I<spampd> listens on. By default, it listens on
port 10025. This is an alternate to using the above --host=ip:port notation.

=item B<--relayhost=ip or hostname[:port]>

Specifies the hostname where I<spampd> will relay all
messages. Defaults to 127.0.0.1. If the port is not provided, that
defaults to 25.

=item B<--relayport=n>

Specifies what port I<spampd> will relay to. Default is 35. This is an 
alternate to using the above --relayhost=ip:port notation.

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

=item B<--childtimeout=n>

This is the number of seconds to allow each child server before it times out
a transaction. In an SMTP transaction the timer is reset for every command. This
timeout includes time it would take to send the message data, so it should not
be too short.  Default is 300 seconds (5 minutes).

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

=item B<--local-only>

Turn off all SA network-based tests (DNS, Razor, etc).

=item B<--debug>

Turns on SpamAssassin debug messages.

=item B<--help>

Prints usage information.

=back

=head2 Deprecated Options

=over 5

The following options are no longer used but still accepted for backwards
compatibility with I<spampd> v1:

=item  B<--dead-letters>

=item  B<--heloname>

=item  B<--stop-at-threshold>

=back

=head1 Examples

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

=head1 Credits

I<spampd> is written and maintained by Maxim Paperno <MPaperno@WorldDesign.com>.
See http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm for latest info.

I<spampd> v2 uses two Perl modules by Bennett Todd and Copyright (C) 2001 Morgan 
Stanley Dean Witter. These are distributed under the GNU GPL (see
module code for more details). Both modules have been slightly modified 
from the originals and are included in this file under new names.

Also thanks to Bennet Todd for the example smtpproxy script which helped create
this version of I<spampd>.  See http://bent.latency.net/smtpprox/ .

I<spampd> v1 was based on code by Dave Carrigan named assassind. Trace amounts
of his code or documentation may still remain. Thanks to him for the
original inspiration and code. See http://www.rudedog.org/assassind/ .

Also thanks to I<spamd> (included with SpamAssassin) and 
I<amavisd-new> (http://www.ijs.si/software/amavisd/) for some tricks.

=head1 Copyright and Disclaimer

I<spampd> is Copyright (c) 2002 by World Design Group and Maxim Paperno

Portions are Copyright (C) 2001 Morgan Stanley Dean Witter as mentioned above
in the CREDITS section.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    The GNU GPL can be found at http://www.fsf.org/copyleft/gpl.html


=head1 Bugs

None known.  Please report any to MPaperno@WorldDesign.com.

=head1 To Do

Add configurable option for rejecting mail outright based on spam score.
It would be nice to make this program safe enough to sit in front of a mail 
server such as Postfix and be able to reject mail before it enters our systems.
The only real problem is that Postfix will see localhost as the connecting
client, so that disables any client-based checks Postfix can do and creates a 
possible relay hole if localhost is trusted.

Make it handle LMTP protocol.

=head1 See Also

perl(1), Spam::Assassin(3), L<http://www.spamassassin.org/>, 
L<http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm>
