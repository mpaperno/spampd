#!/usr/bin/perl -w

############################################################
# This code is a merging of spamd (copyright 2001 by Craig Hughes)
# and spamproxyd by Ian R. Justman.
# Like spamproxyd, it is written with Postfix "advanced" content
# filtering in mind.  See FILTER_README in the Postfix distribution
# for more information on how to set this up.
#
# The primary difference between spamproxyd and spampd is that
# spampd acutally tags the spams and sends them on, even making
# use of the auto-whitelist feature (and soon the SQL lookups
# based on the recipient email address, maybe). 
#
# The primary difference between spamd and spampd is that spampd
# talks SMTP protocol for its I/O stream (via Net::SMTP::Server
# and Mail::SpamAssassin::SMTP::SmartHost).
#
# WARNING: Use at your own risk.  Basically I have no idea what
# I'm doing with the process forking stuff, I just copied it and
# messed around until it worked (for me, YMMV).  Also the demonizing
# stuff seems screwy when you go to kill the daemon (at least via inet.d
# script), but it does exit and clean up so no harm seems to be done.
#
# Development/production environment is RH Linux 7.x on various x86 hardware.
#
# BUG: for some reason the log and warn (if -D) messages don't print during
# SIGTERM or when a child dies (after processing it's allotted # of msgs).
# I have no idea why (see above)
#
# spampd is licensed for use under the terms of the Perl Artistic License
#
############################################################

# use lib '../lib';	# added by jm for use inside the distro
use strict;
# use Socket;
use Carp;
use Net::SMTP::Server;
use Net::SMTP::Server::Client;
use Mail::SpamAssassin;
use Mail::SpamAssassin::NoMailAudit;
use Mail::SpamAssassin::SMTP::SmartHost;
use Net::DNS;
use Sys::Syslog qw(:DEFAULT setlogsock);
use POSIX qw(setsid);
use Getopt::Std;
use POSIX ":sys_wait_h";

my %resphash = (
		EX_OK          => 0,  # no problems
		EX_USAGE       => 64, # command line usage error
		EX_DATAERR     => 65, # data format error
		EX_NOINPUT     => 66, # cannot open input
		EX_NOUSER      => 67, # addressee unknown
		EX_NOHOST      => 68, # host name unknown
		EX_UNAVAILABLE => 69, # service unavailable
		EX_SOFTWARE    => 70, # internal software error
		EX_OSERR       => 71, # system error (e.g., can't fork)
		EX_OSFILE      => 72, # critical OS file missing
		EX_CANTCREAT   => 73, # can't create (user) output file
		EX_IOERR       => 74, # input/output error
		EX_TEMPFAIL    => 75, # temp failure; user is invited to retry
		EX_PROTOCOL    => 76, # remote error in protocol
		EX_NOPERM      => 77, # permission denied
		EX_CONFIG      => 78, # configuration error
		);

sub usage
{
    warn <<EOUSAGE;

Usage: spampd [options]

Options:

  -w              Use auto-whitelists.
  -a			  Tag all messages (not just spam)
  -h              Print this usage message and exit
  -q              Enable SQL config (currently inactive)
  -s facility     Specify the syslog facility (default: mail)
  -u username     Run as named user, instead of running as current user
  -g hostname     Use specified hostname in the SMTP HELO command when 
  					forwarding mail (Default: spamfilter.localdomain)
  
Source:
  -i ipaddr       Listen on the specified IP address (default: 127.0.0.1,
                  use 0.0.0.0 to listen on all available addresses)
  -p port         Listen on the specific port (default: 10025)
  
Destination: 
  -t ipaddr		  Use specified IP address as relay (To) host (default: 127.0.0.1)
  -v port		  Use specified port on the relay host specified with -t (default: 10026)
  
Process Control:
  -d		  	  Daemonize, detach from parent process
  -C			  Number of child processes to create (Default: 4)
  -m			  Minumum number of connections to handle per child before exiting (Default: 5)
  -M			  Maximum number of connections to handle per child before exiting (Default: 10)
  
SpamAssassin passthrough flags:
  -D              Print debugging messages (some from spampd also)
  -L              Use local tests only (no DNS or other network lookups)
  -P              Die upon user errors (does not exist or user = root) instead of
                  running as 'nobody' with defaults.
  -F 0|1          remove/add 'From ' line at start of output (default: 1)


EOUSAGE
    exit $resphash{EX_USAGE};
}

use vars qw{
    $opt_d $opt_h $opt_L $opt_p $opt_A $opt_x $opt_s $opt_D $opt_u
    $opt_P $opt_c $opt_a $opt_i $opt_q $opt_F $opt_t $opt_v $opt_C
	$opt_m $opt_M $opt_w $opt_g
};

getopts('wacdhg:i:p:qs:t:u:v:xA:DLPF:C:m:M:') or usage();

$opt_h and usage();

my $log_facility = 'mail';
if($opt_s) { $log_facility = $opt_s; }

my $dontcopy = 1;
if ($opt_c) { $dontcopy = 0; }

my $relayServer = "127.0.0.1";
if ($opt_t) { $relayServer = $opt_t; }
my $relayPort = "10026";
if ($opt_v) { $relayPort = $opt_v; }

my $smarthost = $relayServer . ":" . $relayPort;

my $children = 4;
if ($opt_C) { $children = $opt_C; }
my $minperchild = 5;
if ($opt_m) { $minperchild = $opt_m; }
my $maxperchild = 10;
if ($opt_M) { $maxperchild = $opt_M; }

my $port = $opt_p || 10025;
my $addr = $opt_i || '127.0.0.1';

my $myhelo = $opt_g || 'spamfilter.localdomain';

($port) = $port =~ /^(\d+)$/ or die "invalid port";


#if (defined $ENV{'HOME'}) {
#    delete $ENV{'HOME'}; # we do not want to use this when running spamd
#}

my $spamtest = Mail::SpamAssassin->new({
    dont_copy_prefs => $dontcopy,
    local_tests_only => $opt_L,
    debug => $opt_D,
    paranoid => ($opt_P || 0),
});

$opt_w and eval
{
    require Mail::SpamAssassin::DBBasedAddrList;

    # create a factory for the persistent address list
    my $addrlistfactory = Mail::SpamAssassin::DBBasedAddrList->new();
    $spamtest->set_persistent_address_list_factory ($addrlistfactory);
};

sub logmsg; # forward declaration

setlogsock('unix');

# Use Net::SMTP::Server here to talk regular SMTP
my $server = new Net::SMTP::Server($addr, $port) ||
  die "Unable to create server: $! : $addr, $port\n";

# support non-root use (after we bind to the port)
my $setuid_to_user = 0;
if ($opt_u) {
    my $uuid = getpwnam($opt_u);
    if (!defined $uuid || $uuid == 0) {
		die "fatal: cannot run as nonexistent user or root with -u option\n";
    }
    $> = $uuid;		# effective uid
    $< = $uuid;		# real uid. we now cannot setuid anymore
    if ($> != $uuid) {
		die "fatal: setuid to uid $uuid failed\n";
    }
}

$spamtest->compile_now();	# ensure all modules etc. are loaded
$/ = "\n";			# argh, Razor resets this!  Bad Razor!

$opt_d and daemonize();

my $current_user;

if ($opt_D) {
    warn "server started on port $port\n";
    warn "server pid: $$\n";
}
logmsg "server started on $addr:$port; server pid: $$\n";

# Ian R. Justman writes in spamproxyd:
# This is the preforking and option-parsiong section taken from the MSDW
# smtpproxy code by Bennett Todd.  Any comments from that code are not my
# own comments (marked with "[MSDW]") unless otherwise noted.
#
# Depending on your platform, you may need his patch which uses
# IPC/semaphores to get information which may be required to allow two
# simultaneous instances to accept() a connection, which can be obtained at
# http://bent.latency.net/smtpprox/smtpprox-semaphore-patch.  It is best to
# apply the patch to the original script, then port it to this one.
#
# --irj

# [MSDW]
# This should allow a kill on the parent to also blow away the
# children, I hope
my %children;
use vars qw($please_die);
$please_die = 0;
$SIG{INT} = sub { $please_die = 1; };
$SIG{TERM} = sub { $please_die = 1; }; # logmsg "server killed by SIGTERM, shutting down";

# [MSDW]
# This sets up the parent process

PARENT: while (1) {
    while (scalar(keys %children) >= $children) {
        my $child = wait;
        delete $children{$child} if exists $children{$child};
        if ($please_die) { kill 15, keys %children; exit 0; }
    }
    my $pid = fork;
    die "$0: fork failed: $!\n" unless defined $pid;
    last PARENT if $pid == 0;
    $children{$pid} = 1;
    select(undef, undef, undef, 0.1);
    if ($please_die) { kill 15, keys %children; exit 0; }
}

# [MSDW]
# This block is a child service daemon. It inherited the bound
# socket created by SMTP::Server->new, it will service a random
# number of connection requests in [minperchild..maxperchild] then
# exit

my $lives = $minperchild + (rand($maxperchild - $minperchild));

while(my $conn = $server->accept()) {

    my $client = new Net::SMTP::Server::Client($conn) ||
      next;

    my $start = time;

    # [MSDW]
    # Process the client.  This command will block until
    # the connecting client completes the SMTP transaction.
    $client->process || next;

# we'll have to revisit this later
#		    if ($opt_q) {
#			handle_user_sql($1);
#		    }

    my $resp = "EX_OK";

    # Now read in message
    my $message = $client->{MSG};
	my @msglines = split ("\r\n", $message);
	my $arraycont = @msglines; for(0..$arraycont) { $msglines[$_] .= "\r\n"; }
	# Audit the message
    my $mail = Mail::SpamAssassin::NoMailAudit->new (
                            data => \@msglines,
                            add_From_line => $opt_F
                     );

    # Check spamminess and rewrite mail if high spam factor or option -a (tag All)
    my $status = $spamtest->check($mail);
	if ( $status->is_spam || $opt_a ) { 
		$status->rewrite_mail; 
	}

    # Build the message to send back
    my $msg_resp = join '',$mail->header,"\n",@{$mail->body};

	# Relay the (rewritten) message through perl SmartHost module
	my $relay = new Mail::SpamAssassin::SMTP::SmartHost($client->{FROM},
                                             $client->{TO},
                                             $msg_resp,
                                             "$smarthost",
											 "$myhelo");

	# Log what we did, FWIW
    my $was_it_spam;
    if($status->is_spam) { $was_it_spam = 'identified spam'; } else { $was_it_spam = 'clean message'; }
    my $msg_score = int($status->get_hits);
    my $msg_threshold = int($status->get_required_hits);
    #$current_user ||= '(unknown)';
    logmsg "$was_it_spam ($msg_score/$msg_threshold) in ".
			sprintf("%3d", time - $start) ." seconds.\n";

    $status->finish();	# added by jm to allow GC'ing
    
    # Zap this instance if this child's processing limit has been reached.
    # --irj
    delete $server->{"s"};
    if ($lives-- <= 0) {
    	if ($opt_D) {
		    warn "killing child process\n";
		}
    	exit 0; 
    }
}

sub handle_user_sql
{
    $current_user = shift;
    $spamtest->load_scoreonly_sql ($current_user);
    return 1;
}

sub logmsg
{
    openlog('spamd','cons,pid',$log_facility);
    syslog('info',"@_");
    if ($opt_D) { warn "logmsg: @_\n"; }
}

sub kill_handler
{
    my ($sig) = @_;
    logmsg "server killed by SIG$sig, shutting down";
    $please_die = 1;
    return 1;
    #close Server;
    #exit 0;
}

use POSIX 'setsid';
sub daemonize
{
    chdir '/' or die "Can't chdir to '/': $!";
    open STDIN,'/dev/null' or die "Can't read '/dev/null': $!";
    open STDOUT,'>/dev/null' or die "Can't write '/dev/null': $!";
    defined(my $pid=fork) or die "Can't fork: $!";
    exit if $pid;
    setsid or die "Can't start new session: $!";
    open STDERR,'>&STDOUT' or die "Can't duplicate stdout: $!";
}

=head1 NAME

spampd - daemonized version of spamassassin with SMTP IO interface

=head1 SYNOPSIS

spampd [options]

=head1 OPTIONS

=over

=item B<-w>

Use auto-whitelists.  These will automatically create a list of
senders whose messages are to be considered non-spam by monitoring the total
number of received messages which weren't tagged as spam from that sender.
Once a threshold is exceeded, further messages from that sender will be given a
non-spam bonus (in case you correspond with people who occasionally swear in
their emails).

=item B<-a>

Tag All messages with SpamAssassin X-Spam-Status header, even if non spam. Default
is to tag spam only.

=item B<-d>

Detach from starting process and run in background (daemonize).

=item B<-h>

Print a brief help message, then exit without further action.

=item B<-i> I<ipaddress>

Tells spamd to listen on the specified IP address [defaults to 127.0.0.1].  Use
0.0.0.0 to listen on all interfaces.

=item B<-p> I<port>

Optionally specifies the port number for the server to listen on.

=item B<-t> I<ipaddress>

Use specified IP address as relay (To) host (default: 127.0.0.1)

=item B<-v> I<port>

Use specified port on the relay host specified with -t (default: 10026)

=item B<-g> I<hostname>

Use specified hostname in the SMTP HELO greeting to the relay host (default: spamfilter.localdomain)

=item B<-q>

Turn on SQL lookups even when per-user config files have been disabled
with B<-x>. this is useful for spamd hosts which don't have user's
home directories but do want to load user preferences from an SQL
database.

=item B<-s> I<facility>

Specify the syslog facility to use (default: mail).

=item B<-u> I<username>

Run as the named user.  The alternative, default behaviour is to setuid() to
the user running C<spamc>, if C<spamd> is running as root.

=item B<-D>

Print debugging messages

=item B<-C>

Number of child processes to create (Default: 4)

=item B<-m>

Minumum number of connections to handle per child before exiting (Default: 5)

=item B<-M>

Maximum number of connections to handle per child before exiting (Default: 10)

=item B<-L>

Perform only local tests on all mail.  In other words, skip DNS and other
network tests.  Works the same as the C<-L> flag to C<spamassassin(1)>.

=item B<-P>

Die on user errors (for the user passed from spamc) instead of falling back to
user I<nobody> and using the default configuration.

=item B<-F> I<0 | 1>

Ensure that the output email message either always starts with a 'From ' line
(I<1>) for UNIX mbox format, or ensure that this line is stripped from the
output (I<0>).  (default: 1)

=back

=head1 DESCRIPTION

The purpose of this program is to provide a daemonized version of the
spamassassin executable.  The goal is improving throughput performance for
automated mail checking.

This version uses SMTP as the I/O transport.  It is inteded to be used as a 
Postfix content_filter or other transport agent.

This code is a merging of spamd (copyright 2001 by Craig Hughes)
and spamproxyd by Ian R. Justman.
Like spamproxyd, it is written with Postfix "advanced" content
filtering in mind.  See FILTER_README in the Postfix distribution
for more information on how to set this up.

The primary difference between spamproxyd and spampd is that
spampd acutally tags the spams and sends them on, even making
use of the auto-whitelist feature (and soon the SQL lookups
based on the recipient email address, maybe). 

The primary difference between spamd and spampd is that spampd
talks SMTP protocol for its I/O stream (via Net::SMTP::Server
and Mail::SpamAssassin::SMTP::SmartHost).

WARNING: Use at your own risk.  Basically I have no idea what
I'm doing with the process forking stuff, I just copied it and
messed around until it worked (for me, YMMV).  Also the demonizing
stuff seems screwy when you go to kill the daemon (at least via inet.d
script), but it does exit and clean up so no harm seems to be done.

Development/production environment is RH Linux 7.x on various x86 hardware.

BUG: for some reason the log and warn (if -D) messages don't print during
SIGTERM or when a child dies (after processing it's allotted # of msgs).
I have no idea why (see above)

=head1 SEE ALSO

spamassassin(1)
Mail::SpamAssassin(3)

=head1 AUTHOR

Maxim Paperno E<lt>MPaperno@worldDesign.comE<gt>

=head1 CREDITS

Justin Mason and Craig Hughes for B<Mail::SpamAssassin>
and B<spamd>

Ian R. Justman for his B<spamproxyd> implementation

Habeeb J. "MacGyver" Dihu for his B<Net::SMTP::Server> code

Bennett Todd for the perforking code and option-parsing code from his
    pacakge, smtpproxy (used via spamproxyd code)

=head1 PREREQUISITES

C<Mail::SpamAssassin>
C<Mail::SpamAssassin::SMTP::SmartHost>

=cut
