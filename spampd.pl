#!/usr/bin/perl -T

######################
# SpamPD - Spam Proxy Daemon
#
# v2.61  - 06-Aug-21
# v2.60  - 26-Jul-21
# v2.53  - 25-Feb-19
# v2.52  - 10-Nov-18
# v2.51  - 01-May-18
# v2.50  - 30-Apr-18
# v2.42  - 08-Dec-13
# v2.41  - 11-Aug-10
# v2.40  - 10-Jan-09
# v2.32  - 02-Feb-06
# v2.30  - 31-Oct-05
# v2.21  - 23-Oct-05
# v2.20  - 05-Oct-04
# v2.13  - 24-Nov-03
# v2.12  - 15-Nov-03
# v2.11  - 15-Jul-03
# v2.10  - 01-Jul-03
# v2.00  - 10-Jun-03
# v1.0.2 - 13-Apr-03
# v1.0.1 - 03-Feb-03
# v1.0.0 - May 2002
#
# spampd is Copyright (c) Maxim Paperno; All Rights Reserved.
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
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see L<https://www.gnu.org/licenses/>.
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
# acknowledge each command or request. Since acknowledgement or failure
# are driven explicitly from the caller, this module can be used to
# create a robust SMTP content scanning proxy, transparent or not as
# desired.
#
# =cut

use strict;
use warnings;
use IO::File ();

# =item new(socket => $socket);
#
# Changed by MP: This now emulates Net::SMTP::Server::Client for use with
#   Net::Server which passes an already open socket.
# The $socket to listen on must be specified. If this call
# succeeds, it returns a server structure. If it fails it dies, so
# if you want anything other than an exit with an explanatory error
# message, wrap the constructor call in an eval block and pull the
# error out of $@ as usual. This is also the case for all other
# methods; they succeed or they die.
#
# =cut

sub new {
  my ($this, $socket) = @_;
  my $class = ref($this) || $this || die "Missing class";
  die "Invalid $socket argument in ".__PACKAGE__."->new()" unless defined $socket;
  return bless {
    sock  => $socket,
    state => 'started',
    proto => 'unknown',
    helo  => 'unknown.host',
  }, $class;
}

# =item chat;
#
# The chat method carries the SMTP dialogue up to the point where any
# acknowledgement must be made. If chat returns true, then its return
# value is the previous SMTP command. If the return value begins with
# 'mail' (case insensitive), then the attribute 'from' has been filled
# in, and may be checked; if the return value begins with 'rcpt' then
# both from and to have been been filled in with scalars, and should
# be checked, then C<reply("(2|5)50 [OK|Error]")> should be called to accept
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
  local (*_);
  if ($self->{state} !~ /^data/i) {
    return 0 unless defined($_ = $self->_getline);
    s/[\r\n]*$//;
    $self->{state} = $_;
    if (/^(l|h)?he?lo\s+/i) {  # mp: find helo|ehlo|lhlo
      # mp: determine protocol
      if (s/^helo\s+//i) {
        $self->{proto} = "smtp";
      }
      elsif (s/^ehlo\s+//i) {
        $self->{proto} = "esmtp";
      }
      elsif (s/^lhlo\s+//i) {
        $self->{proto} = "lmtp";
      }

      s/\s*$//;
      s/\s+/ /g;
      $self->{helo} = $_;
    }
    elsif (s/^rset\s*//i) {
      delete $self->{to};
      delete $self->{data};
      delete $self->{recipients};
    }
    elsif (s/^mail\s+from:\s*//i) {
      delete $self->{to};
      delete $self->{data};
      delete $self->{recipients};
      s/\s*$//;
      $self->{from} = $_;
    }
    elsif (s/^rcpt\s+to:\s*//i) {
      s/\s*$//; s/\s+/ /g;
      $self->{to} = $_;
      push @{$self->{recipients}}, $_;
    }
    elsif (/^data/i) {
      $self->{to} = $self->{recipients};
    }
  }
  else {
    if (defined($self->{data})) {
      $self->{data}->seek(0, 0);
      $self->{data}->truncate(0);
    }
    else {
      $self->{data} = IO::File->new_tmpfile;
    }
    while (defined($_ = $self->_getline)) {
      if ($_ eq ".\r\n") {
        $self->{data}->seek(0, 0);
        return $self->{state} = '.';
      }
      s/^\.\./\./;
      $self->{data}->print($_) or die "Server error while saving data: $!\n";
    }
    return 0;
  }
  return $self->{state};
}

# =item reply([message]);
#
# Send a response back to the connected peer. Default message is a confirmation
# response: "250 ok."
#
# =cut

sub reply {
  my ($self, @msg) = @_;
  @msg = ("250 ok.") unless @msg;
  chomp(@msg);
  $self->{sock}->print("@msg\r\n") or
    die "Server error while sending response '@msg' (state = $self->{state}): $!\n";
  # $self->{debug}->print(@msg) if defined $self->{debug};
}

# utility functions

sub _getline {
  my ($self) = @_;
  local ($/) = "\r\n";
  my $tmp = $self->{sock}->getline;
  if (defined $self->{debug}) {
    $self->{debug}->print($tmp) if ($tmp);
  }
  return $tmp;
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
# the only protocol-specific knowledge it has is the structure of SMTP
# multiline responses. All specifics lie in the hands of the calling
# program; this makes it appropriate for a semi-transparent SMTP
# proxy, passing commands between a talker and a listener.
#
# =cut

use strict;
use warnings;

# =item new([interface => $interface, port => $port] | [unix_socket => $unix_socket] [, timeout = 300]);
#
# The interface and port, OR a UNIX socket to talk to must be specified. If
# this call succeeds, it returns a client structure with an open
# IO::Socket::IP or IO::Socket::UNIX in it, ready to talk to.
# If it fails it dies, so if you want anything other than an exit with an
# explanatory error message, wrap the constructor call in an eval block and pull
# the error out of $@ as usual. This is also the case for all other
# methods; they succeed or they die. The timeout parameter is passed
# on into the IO::Socket::IP/UNIX constructor.
#
# =cut

sub new {
  my ($this, @opts) = @_;
  my $class = ref($this) || $this;
  my $self = bless {timeout => 300, @opts}, $class;
  if ($self->{unix_socket}) {
    require IO::Socket::UNIX;
    $self->{sock} = IO::Socket::UNIX->new(
      Peer    => $self->{unix_socket},
      Timeout => $self->{timeout},
      Type    => IO::Socket::UNIX->SOCK_STREAM,
    );
  }
  else {
    require IO::Socket::IP;
    $self->{sock} = IO::Socket::IP->new(
      PeerAddr => $self->{interface},
      PeerPort => $self->{port},
      Timeout  => $self->{timeout},
      Proto    => 'tcp',
      Type     => IO::Socket::IP->SOCK_STREAM,
    );
  }
  die "Client connection failure to ". ($self->{unix_socket} || $self->{interface}) .": $!\n" unless defined $self->{sock};
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
  return unless $tmp = $self->{sock}->getline;
  while ($tmp =~ /^\d{3}-/) {
    $reply .= $tmp;
    return unless $tmp = $self->{sock}->getline;
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
  chomp(@msg);
  $self->_print("@msg", "\r\n");
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
  $self->{sock}->autoflush(0);  # use fewer writes (thx to Sam Horrocks for the tip)
  while (<$fh>) {
    s/^\./../;
    $self->_print($_);
  }
  $self->{sock}->autoflush(1);  # restore unbuffered socket operation
  $self->_print(".\r\n");
}

sub _print {
  return unless @_ > 1;
  shift()->{sock}->print(@_) or die "Client socket write error: $!\n";
}

1;


################################################################################
package SpamPD;

use strict;
use warnings;

BEGIN {
  require Net::Server;
  Net::Server->VERSION(0.89);

  # use included modules
  import SpamPD::Server;
  import SpamPD::Client;
}

use Getopt::Long qw(GetOptions);
use Time::HiRes qw(time);
use Mail::SpamAssassin ();
use Mail::SpamAssassin::Client ();

our $VERSION = '2.611';

# ISA will change to a Net::Server "flavor" at runtime based on options.
our @ISA = qw(Net::Server);

use constant {
  # Logging type constants: low byte for destination(s), high byte for logger type.
  LOG_NONE => 0, LOG_SYSLOG => 0x01, LOG_FILE => 0x02, LOG_STDERR => 0x04, LOG_TYPE_MASK => 0xFF,
  LOGGER_DEFAULT => 0, LOGGER_SA => 0x0100, LOGGER_L4P => 0x0200, LOGGER_TYPE_MASK => 0xFF00,
  # Map Net::Server logging levels to SpamAssassin::Logger level names.
  SA_LOG_LEVELS => {0 => 'error', 1 => 'warn', 2 => 'notice', 3 => 'info', 4 => 'dbg'},
};

##################   RUN   ######################

unless (caller) {
  # Create, init, and go.
  SpamPD->new()->init()->run();
  exit 1;  # shouldn't get here
}

##################   SETUP   ######################

# Create ourselves and set defaults for options.
sub new {
  my $class = shift || die "Missing class.";
  return bless {
    server => {
      host              => '127.0.0.1',           # listen on ip
      port              => 10025,                 # listen on port
      min_servers       => undef,                 # min num of servers to always have running (undef means use same value as max_servers, otherwise means run as PreFork)
      min_spare_servers => 1,                     # min num of servers just sitting there (only used when running as PreFork)
      max_spare_servers => 4,                     # max num of servers just sitting there (only used when running as PreFork)
      max_servers       => 5,                     # max number of child processes (servers) to spawn
      max_requests      => 20,                    # max requests handled by child b4 dying
      pid_file          => '/var/run/spampd.pid', # write pid to file
      user              => 'mail',                # user to run as
      group             => 'mail',                # group to run as
      log_file          => undef,                 # log destination (undef means log to use write_to_log_hook() with stderr fallback)
      syslog_logsock    => undef,                 # syslog socket (undef means for Sys::Syslog to decide)
      syslog_ident      => 'spampd',              # syslog identity
      syslog_facility   => 'mail',                # syslog facility
      log_level         => 2,                     # log level for Net::Server (in the range 0-4) (--debug option sets this to 4)
      background        => 1,                     # specifies whether to 'daemonize' and fork into background (--[no]detach option)
      setsid            => 0,                     # use POSIX::setsid() command to truly daemonize.
      leave_children_open_on_hup => 1,            # this lets any busy children finish processing before exiting, using old SA object
    },
    spampd => {
      socket            => undef,                 # listen on socket (saved for setting permissions after binding)
      socket_mode       => undef,                 # listening socket permissions (octal)
      relayhost         => '127.0.0.1',           # relay to ip
      relayport         => 25,                    # relay to port
      relaysocket       => undef,                 # relay to socket
      childtimeout      => 6 * 60,                # child process per-command timeout in seconds
      satimeout         => 285,                   # SA timeout in seconds (15s less than Postfix default for smtp_data_done_timeout)
      tagall            => 0,                     # mark-up all msgs with SA, not just spam
      maxsize           => 64,                    # max. msg size to scan with SA, in KB.
      rh                => 0,                     # log which rules were hit
      dose              => 0,                     # die-on-sa-errors flag
      envelopeheaders   => 0,                     # Set X-Envelope-To & X-Envelope-From headers in the mail before passing it to SA (--seh option)
      setenvelopefrom   => 0,                     # Set X-Envelope-From header only (--sef option)
      sa_awl            => 0,                     # SA auto-whitelist (deprecated)
      logtype           => LOG_SYSLOG,            # logging destination and logger type (--logfile option)
      sa_version        => $Mail::SpamAssassin::VERSION,  # may be used while processing messages
      sa_client         => 0,                     # specifies wether to use SA client instead of embedded SA instance
      runtime_stats     => undef,                 # variables hash for status tracking, can be used as values in user-provided template strings (defined in init())
      # default child name template
      child_name_templ  => '%base_name: child #%child_count(%child_status) ' .
                           '[req %req_count/%req_max, time lst/avg/ttl %(req_time_last).3f/%(req_time_avg).3f/%(req_time_ttl).3f, ham/spm %req_ham/%req_spam] ' .
                           '[SA %sa_ver/%sa_rls_ver]',
    },
    # this hash is eventually passed to SpamAssassin->new() so it must use valid SA option names. This also becomes the SA object afterwards.
    assassin => {
      debug                => 0,                  # debug flag, can be boolean or a list to pass to SA (--debug option)
      local_tests_only     => 0,                  # disable SA network tests (--local-only flag)
      userstate_dir        =>
        '/var/spool/spamassassin/spampd',         # home directory for SA files and plugins (--homedir option)
      home_dir_for_helpers => '',                 # this will be set to the same as userstate_dir once options are parsed
      username             => '',                 # this will be set to the same user as we're running as once options are parsed
      userprefs_filename   => undef,              # add this config file for SA "user_prefs" settings (--saconfig option)
      dont_copy_prefs      => 1,                  # tell SA not to copy user pref file into its working dir
    },
    assassinc => {
      socketpath  => undef,
      port        => 783,
      host        => '127.0.0.1',
      username    => undef,
      timeout     => 30,
    }
  }, $class;
}

# Set the actual Net::Server flavor type we'll run as.
sub set_server_type {
  my $self = shift;
  # Default behavior is to run as PreForkSimple unless min_servers is set and is != max_servers.
  if ($self->{server}->{min_servers} && $self->{server}->{min_servers} != $self->{server}->{max_servers}) {
    require Net::Server::PreFork;
    @SpamPD::ISA = qw(Net::Server::PreFork);
  }
  else {
    require Net::Server::PreForkSimple;
    @SpamPD::ISA = qw(Net::Server::PreForkSimple);
  }
}

##################   INIT   ######################

sub init {
  my $self = shift;
  my ($spd_p, $sa_p, $sa_c) = ($self->{spampd}, $self->{assassin}, $self->{assassinc});

  # Clean up environment.
  delete @ENV{qw(IFS CDPATH ENV BASH_ENV HOME)};
  eval {
    # Try to safely untaint the PATH instead of resetting it. Also prevents SA from duplicating this step when it starts.
    require Mail::SpamAssassin::Util;
    Mail::SpamAssassin::Util::clean_path_in_taint_mode();
  } or do {
    $ENV{'PATH'} = '/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin';
  };

  # Untaint $0 and each member of @ARGV, and save untainted copies for HUPping. This saves the original
  #   command line, including any configuration files, which would be re-read upon a HUP. commandline() is in Net::Server.
  $self->commandline([untaint_var($0), @{untaint_var(\@ARGV)}]);

  # Set the logger type. SA v3.1.0 changed debug logging to be more granular and introduced Logger module which we can use.
  $spd_p->{logtype} |= eval {
    require Mail::SpamAssassin::Logger;
    LOGGER_SA;
  } or LOGGER_DEFAULT;

  # We actually call Getopt::Long::GetOptions twice. First time is to check for presence of config file option(s).
  # If we get any, then we parse the file(s) into @ARGV, in front of any existing @ARGV options (so command-line overrides).
  $self->handle_initial_opts();

  # save final ARGV for debug (handle_main_opts() will clear @ARGV)
  my @startup_args = @ARGV;

  # Now process all the actual options passed on @ARGV (including anything from config files).
  # Options on the actual command line will override anything loaded from the file(s).
  $self->handle_main_opts();

  # Configure logging ASAP, unless just showing debug info.
  $self->setup_logging() if !$spd_p->{show_dbg};

  # Validate options.
  my (@errs, @warns) = $self->validate_main_opts();
  if (@errs) {
    $self->err("CONFIG ERROR! ".$_."\n") for @errs;
    $self->server_close(1) if $self->is_reloading();
    $self->server_exit(1);
  }
  $self->wrn("CONFIG WARNING! ".$_."\n") for @warns;

  # If debug output requested, do it now and exit.
  $self->show_debug($spd_p->{show_dbg}, {$self->options_map()}, \@startup_args) && exit(0) if $spd_p->{show_dbg};

  my $sa_rules_ver;
  if ($spd_p->{sa_client}) {
    $sa_c = Mail::SpamAssassin::Client->new($sa_c);
    $self->{assassinc} = $sa_c;
    $self->inf("Pinging sa daemon");
    if ($sa_c->ping()){
      $self->inf("Connected successfully with sa daemon");
    }
  } else {
    # Create and set up SpamAssassin object. This replaces our SpamPD->{assassin} property with the actual object instance.
    $sa_p = Mail::SpamAssassin->new($sa_p);

    $spd_p->{sa_awl} and eval {
      require Mail::SpamAssassin::DBBasedAddrList;
      # create a factory for the persistent address list
      my $addrlistfactory = Mail::SpamAssassin::DBBasedAddrList->new();
      $sa_p->set_persistent_address_list_factory($addrlistfactory);
    };

    $sa_p->compile_now(!!$sa_p->{userprefs_filename});
    # Get the SA "rules update version" for logging and child process name (since v3.4.0).
    # https://github.com/apache/spamassassin/blob/3.4/build/announcements/3.4.0.txt#L334
    # https://github.com/apache/spamassassin/blob/3.4/lib/Mail/SpamAssassin/PerMsgStatus.pm#L1597
    
    ($spd_p->{sa_version} >= 3.0040) and eval {
      $sa_rules_ver = Mail::SpamAssassin::PerMsgStatus->new($sa_p)->get_tag("RULESVERSION");
    };
  }


  # Set up statistics hash. This is currently used for report formatting, eg. in child process name.
  my $ns_type = (split(':', $self->net_server_type()))[-1];
  $spd_p->{runtime_stats} = {
    base_name     => eval { ($0 =~ m/^.*?([\w-]+)(?:\.[\w-]+)*$/) ? $1 : "spampd"; },
    spampd_ver    => $self->VERSION(),
    perl_ver      => sprintf("%vd", $^V), # (split(/v/, $^V))[-1];
    ns_ver        => Net::Server->VERSION(),
    ns_typ        => $ns_type,
    ns_typ_acr    => do { (my $tmp = $ns_type) =~ s/[a-z]//g; $tmp },
    sa_ver        => Mail::SpamAssassin::Version(),
    sa_rls_ver    => $sa_rules_ver || "(unknown)",
    child_count   => 0,   # total # of children launched
    child_status  => "D", # (C)onnected, or (D)isconnected
    req_count     => 0,   # num of requests child has processed so far
    req_max       => $self->{server}->{max_requests},  # maximum child requests
    req_time_last => 0,   # [s] time to process the last message
    req_time_ttl  => 0,   # [s] total processing time for this child
    req_time_avg  => 0,   # [s] average processing time for this child (req_time_ttl / req_count)
    req_ham       => 0,   # count of ham messages scored by child
    req_spam      => 0,   # count of spam messages scored by child
  };

  my $template = ' v%spampd_ver [Perl %perl_ver, Net::Server::%ns_typ %ns_ver, SA %sa_ver, rules v%sa_rls_ver] ';
  $self->inf(ref($self) . $self->format_stats_string($template) . ($self->is_reloading() ? "reloading": "starting") . " with: @startup_args \n");

  # Redirect all errors to logger (must do this after SA is compiled, otherwise for some reason we get strange SA errors if anything actually dies).
  # $SIG{__DIE__}  = sub { return if $^S; chomp(my $m = $_[0]); $self->fatal($m); };

  # clean up a bit
  delete $spd_p->{config_files};
  delete $spd_p->{logspec};
  delete $spd_p->{show_dbg};
  delete $spd_p->{sa_awl};

  return $self;
}

sub initial_options_map {
  my $self = shift;
  my $spd_p = $self->{spampd};
  my %options = (
    'conf|config|cfg|conf-file|config-file|cfg-file=s@' => \$spd_p->{config_files},
  );
  # Also a good place to check for help/version/show option(s), but not if we're HUPping.
  # These all cause an exit(0) (--show is processed later but still exits).
  if (!$self->is_reloading()) {
    my ($q2, $q3, $q4) = ("|??", "|???", "|????");
    # https://github.com/mpaperno/spampd/issues/30#issuecomment-889110122
    $q2 = $q3 = $q4 = "" if ($Getopt::Long::VERSION < 2.39);
    %options = (
      %options,
      'show=s@'           => \$spd_p->{show_dbg},
      'help|h|?:s'        => sub { $self->usage(0, 1, $_[1]); },
      'hh'.$q2.':s'       => sub { $self->usage(0, 2, $_[1]); },
      'hhh'.$q3.':s'      => sub { $self->usage(0, 3, $_[1]); },
      'hhhh'.$q4.'|man:s' => sub { $self->usage(0, 4, $_[1]); },
      'version|vers'      => sub { $self->version(); },
    );
  }
  return %options;
}

sub handle_initial_opts {
  my $self = shift;
  my %options = $_[0] || $self->initial_options_map();
  my $spd_p = $self->{spampd};

  # Configure Getopt::Long to pass through any unknown options.
  Getopt::Long::Configure(qw(ignore_case no_permute no_auto_abbrev no_require_order pass_through));
  # Check for config file option(s) only.
  GetOptions(%options);

  # Handle "--show <things>"
  if ($spd_p->{show_dbg}) {
    my $shw = \@{$spd_p->{show_dbg}};
    trimmed(@$shw = split(/,/, join(',', @$shw)));  # could be a CSV list
    if (@$shw && grep(/^(def(aults?)?|all)$/i, @$shw)) {
      # Handle "--show defaults" debugging request here (while we still know them).
      @$shw = grep {$_ !~ /^def(aults?)?$/i} @$shw;   # remove "defaults" from list
      # show defaults and exit here if that's all the user wanted to see
      $self->print_options({$self->options_map()}, 'default', (@$shw ? -1 : 0));
    }
  }

  # Handle config files. Note that options on the actual command line will override anything loaded from the file(s).
  if (defined($spd_p->{config_files})) {
    # files could be passed as a list separated by ":"
    trimmed(@{$spd_p->{config_files}} = split(/:/, join(':', @{$spd_p->{config_files}})));
    $self->inf("Loading config from file(s): @{$spd_p->{config_files}} \n");
    read_args_from_file(\@{$spd_p->{config_files}}, \@ARGV);
  }
}

# Main command-line options mapping; this is for Getopt::Long::GetOptions and also to generate config dumps.
sub options_map {
  my $self = $_[0];
  my ($srv_p, $spd_p, $sa_p, $sa_c) = ($self->{server}, $self->{spampd}, $self->{assassin}, $self->{assassinc});
  $spd_p->{logspec} = logtype2logfile($spd_p->{logtype}, $srv_p->{log_file}); # set a valid default for print_options()

  # To support setting boolean options with "--opt", "--opt=1|0", as well as the "no-" prefix,
  #   we make them accept an optional integer and add the "no" variants manually. Because Getopt::Long doesn't support that :(
  # Anything that isn't a direct reference to value (eg. a sub) will not be shown in "--show defaults|config" listings.
  return (
    # Net::Server
    'host=s'                   => \$srv_p->{host},
    'port=i'                   => \$srv_p->{port},
    'min-servers|mns=i'        => \$srv_p->{min_servers},
    'min-spare|mnsp=i'         => \$srv_p->{min_spare_servers},
    'max-spare|mxsp=i'         => \$srv_p->{max_spare_servers},
    'max-servers|mxs=i'        => \$srv_p->{max_servers},
    'children|c=i'             => sub { $srv_p->{max_servers} = $_[1]; },
    'maxrequests|mr|r=i'       => \$srv_p->{max_requests},
    'pid|p=s'                  => \$srv_p->{pid_file},
    'user|u=s'                 => \$srv_p->{user},
    'group|g=s'                => \$srv_p->{group},
    'logsock|ls=s'             => \$srv_p->{syslog_logsock},
    'logident|li=s'            => \$srv_p->{syslog_ident},
    'logfacility|lf=s'         => \$srv_p->{syslog_facility},
    'detach:1'                 => \$srv_p->{background},
    'no-detach|nodetach'       => sub { $srv_p->{background} = 0; },
    'setsid:1'                 => \$srv_p->{setsid},
    'no-setsid|nosetsid'       => sub { $srv_p->{setsid} = 0; },
    # SpamPD
    'socket=s'                 => \$spd_p->{socket},
    'socket-perms=s'           => \$spd_p->{socket_mode},
    'relayhost=s'              => \$spd_p->{relayhost},
    'relayport=i'              => \$spd_p->{relayport},
    'relaysocket=s'            => \$spd_p->{relaysocket},
    'childtimeout=i'           => \$spd_p->{childtimeout},
    'satimeout=i'              => \$spd_p->{satimeout},
    'maxsize=i'                => \$spd_p->{maxsize},
    'logfile|o=s@'             => \$spd_p->{logspec},
    'tagall|a:1'               => \$spd_p->{tagall},
    'no-tagall|no-a'           => sub { $spd_p->{tagall} = 0; },
    'log-rules-hit|rh:1'       => \$spd_p->{rh},
    'no-log-rules-hit|no-rh'   => sub { $spd_p->{rh} = 0; },
    'dose:1'                   => \$spd_p->{dose},
    'no-dose|nodose'           => sub { $spd_p->{dose} = 0; },
    'auto-whitelist|aw:1'      => \$spd_p->{sa_awl},
    'set-envelope-headers|seh:1'     => \$spd_p->{envelopeheaders},
    'no-set-envelope-headers|no-seh' => sub { $spd_p->{envelopeheaders} = 0; },
    'set-envelope-from|sef:1'        => \$spd_p->{setenvelopefrom},
    'no-set-envelope-from|no-sef'    => sub { $spd_p->{setenvelopefrom} = 0; },
    'child-name-template|cnt:s'      => \$spd_p->{child_name_templ},
    'saclient:1'              => \$spd_p->{sa_client},
    'no-saclient|nosaclient'  => sub { $spd_p->{sa_client} = 0; },
    # SA
    'debug|d:s'                => \$sa_p->{debug},
    'saconfig=s'               => \$sa_p->{userprefs_filename},
    'homedir=s'                => \$sa_p->{userstate_dir},
    'local-only|l:1'           => \$sa_p->{local_tests_only},
    'no-local-only|no-l'       => sub { $sa_p->{local_tests_only} = 0; },
    # SA Client
    'sa-host=s'                => \$sa_c->{host},
    'sa-port=i'                => \$sa_c->{port},
    'sa-socketpath=s'          => \$sa_c->{socketpath},
    'sa-username=s'            => \$sa_c->{username},
    # others
    'dead-letters=s'           => \&deprecated_opt,
    'heloname=s'               => \&deprecated_opt,
    'stop-at-threshold'        => \&deprecated_opt,
    'add-sc-header|ash'        => \&deprecated_opt,
    'hostname=s'               => \&deprecated_opt,
  );
}

sub handle_main_opts {
  my $self = shift;
  my %options = $_[0] || $self->options_map();
  my ($srv_p, $spd_p, $sa_p, $sa_c) = ($self->{server}, $self->{spampd}, $self->{assassin}, $self->{assassinc});

  # Reconfigure GoL for stricter parsing and check for all other options on ARGV, including anything parsed from config file(s).
  Getopt::Long::Configure(qw(ignore_case no_permute no_bundling auto_abbrev require_order no_pass_through));
  GetOptions(%options) or ($self->is_reloading ? $self->fatal("Could not parse command line!\n") : $self->usage(1));

  $self->set_server_type();  # decide who we are

  # These paths are already untainted but do a more careful check JIC.
  for ($spd_p->{socket}, $spd_p->{relaysocket}, $srv_p->{pid_file}, $sa_p->{userprefs_filename})
    { $_ = untaint_path($_); }

  # set up logging specs based on options ($logspec is only an array if --logfile option(s) existed)
  if (ref($spd_p->{logspec}) eq 'ARRAY') {
    $spd_p->{logtype} &= ~LOG_TYPE_MASK;  # reset the low byte containing LOG_<type> constant
    ($spd_p->{logtype}, $srv_p->{log_file}) = logfile2logtype($spd_p->{logspec}, $spd_p->{logtype});
  }
  # elsif (!$srv_p->{background}) {
  #   # set default logging to stderr if not daemonizing and user didn't specify.
  #   $spd_p->{logtype} = $spd_p->{logtype} & (~LOG_TYPE_MASK) | LOG_STDERR;
  # }

  # fixup listening socket/host/port if needed
  if ($spd_p->{socket}) {
    # Net::Server wants UNIX sockets passed via port option.
    $srv_p->{port} = join('|', $spd_p->{socket}, 'unix');
  }
  elsif ($srv_p->{host}) {
    # Set IP host/port if they're passed together. A port as part of the host option wins over port option.
    my @tmp = split(/:(\d+)$/, $srv_p->{host});  # this split should handle IPv6 addresses also.
    $srv_p->{host} = $tmp[0];
    $srv_p->{port} = $tmp[1] if $tmp[1];
  }

  # Set misc. options based on other options.
  $srv_p->{setsid}= 0 if !$srv_p->{background};
  $sa_p->{home_dir_for_helpers} = $sa_p->{userstate_dir};
  $sa_p->{username} = $srv_p->{user};

  # Set SA Client timeout
  $sa_c->{timeout} = $spd_p->{satimeout}
}

sub validate_main_opts {
  my $self = shift;
  my ($srv_p, $spd_p) = ($self->{server}, $self->{spampd});
  my (@errs, @warns) = (@_ ? $_[0] : (), @_ > 1 ? $_[1] : ());

  (@errs, @warns) = $self->validate_server_type_opts(@errs, @warns);

  if ($self->{spampd}->{sa_awl} && $spd_p->{sa_version} >= 3)
    { push (@errs, "Option --auto-whitelist is deprecated with SpamAssassin v3.0+. Use SA configuration file instead."); }

  # Validate that required modules for relay server exist (better now than later).
  if ($spd_p->{relaysocket}) {
    eval { require IO::Socket::UNIX; }
    or push (@errs, "Error loading IO::Socket::UNIX module, required for --relaysocket option.\n\t$@");
  }
  else {
    eval { require IO::Socket::IP; }
    or push (@errs, "Error loading IO::Socket::IP module, required for --relayhost option.\n\t$@");
  }

  return (@errs, @warns);
}

sub validate_server_type_opts {
  my $self = shift;
  return $self->validate_prefork_opts(@_)       if $self->isa(qw(Net::Server::PreFork));  # must check before Simple (PreFork inherits from it)
  return $self->validate_preforksimple_opts(@_) if $self->isa(qw(Net::Server::PreForkSimple));
  return @_;
}

sub validate_preforksimple_opts {
  my ($self, @errs, @warns) = @_;

  if ($self->{server}->{max_servers} < 1)
    { push (@errs, "Option '--max-servers' (or '--children') ($self->{server}->{max_servers}) must be greater than zero!"); }
  return (@errs, @warns);
}

sub validate_prefork_opts {
  my ($self, @errs, @warns) = @_;
  my $prop = $self->{server};

  # Even though Net::Server::PreFork validates all these options also,
  #   their error messages can be confusing and in some cases just wrong.
  if ($prop->{min_servers} < 1) {
    push (@errs, "Option '--min-servers' ($prop->{min_servers}) must be greater than zero!");
  }
  elsif ($prop->{max_servers} < 1) {
    push (@errs, "Option '--max-servers' (or '--children') ($prop->{max_servers}) must be greater than zero!");
  }
  elsif ($prop->{max_servers} < $prop->{min_servers}) {
    push (@errs, "Option '--max-servers' (or --children) ($prop->{max_servers}) must be >= '--min-servers' ($prop->{min_servers})!");
  }
  else {
    if ($prop->{max_spare_servers} >= $prop->{max_servers})
      { push (@errs, "Option '--max-spare' ($prop->{max_spare_servers}) must be < '--max-servers' ($prop->{max_servers})."); }

    if (my $ms = $prop->{min_spare_servers}) {
      if ($ms > $prop->{min_servers})
        { push (@errs, "Option '--min-spare' ($ms) must be <= '--min-servers' ($prop->{min_servers})"); }
      if ($ms > $prop->{max_spare_servers})
        { push (@errs, "Option '--min-spare' ($ms) must be <= '--max-spare' ($prop->{max_spare_servers})"); }
    }
  }
  return (@errs, @warns);
}

sub setup_logging {
  my $self = shift;
  my ($srv_p, $ltype, $debug) = ($self->{server}, $self->{spampd}->{logtype}, \$self->{assassin}->{debug});

  if ($ltype & LOG_SYSLOG) {
    # Need to validate logsock option otherwise SA Logger barfs. In theory this check could be made more adaptive based on OS or something.
    if ($srv_p->{syslog_logsock} && $srv_p->{syslog_logsock} !~ /^(native|eventlog|tcp|udp|inet|unix|stream|pipe|console)$/) {
      $self->wrn("WARNING! Option '--logsock' parameter \"$srv_p->{syslog_logsock}\" not recognized, reverting to default.\n");
      $srv_p->{syslog_logsock} = undef;
    }
    # set log socket default for HP-UX and SunOS (thanks to Kurt Andersen for the 'uname -s' fix)
    # `uname` throws errors (and fails anyway) when HUPping, so we do not repeat it, but do "cache" any new default in our 'commandline'.
    if (!($srv_p->{syslog_logsock} || $self->is_reloading())) {
      eval { push(@{$srv_p->{commandline}}, "--logsock=" . ($srv_p->{syslog_logsock} = "inet")) if (`uname -s` =~ /HP\-UX|SunOS/); };
    }
  }

  # Configure debugging
  if ($$debug ne '0') {
    $srv_p->{log_level} = 4;  # set Net::Server log level to debug
    # SA since v3.1.0 can do granular debug logging based "channels" which can be passed to us via --debug option parameters.
    # --debug can also be specified w/out any parameters, in which case we enable the "all" channel.
    if ($ltype & LOGGER_SA) { $$debug = 'all' if (!$$debug || $$debug eq '1'); }
    else { $$debug = 1; }  # In case of old SA version, just set the debug flag to true.
  }

  if ($ltype & LOGGER_SA) {
    # Add SA logging facilities
    Mail::SpamAssassin::Logger::add_facilities($$debug);
    my $have_log = 0;
    # Add syslog method?
    if ($ltype & LOG_SYSLOG) {
      $have_log = Mail::SpamAssassin::Logger::add(
        method => 'syslog',
        socket => $srv_p->{syslog_logsock},
        facility => $srv_p->{syslog_facility},
        ident => $srv_p->{syslog_ident}
      );
    }
    # Add file method?
    if (($ltype & LOG_FILE) && Mail::SpamAssassin::Logger::add(method => 'file', filename => $srv_p->{log_file})) {
      $have_log = 1;
      push(@{$srv_p->{chown_files}}, $srv_p->{log_file});  # make sure we own the file
    }
    # Stderr logger method is active by default, remove it unless we need it.
    if (!($ltype & LOG_STDERR) && $have_log) {
      Mail::SpamAssassin::Logger::remove('stderr');
    }
    $$debug = undef;   # clear this otherwise SA will re-add the facilities in new()
    $srv_p->{log_file} = undef;  # disable Net::Server logging (use our write_to_log_hook() instead)
  }
  # using Net::Server default logging
  elsif ($ltype & LOG_SYSLOG) {
    $srv_p->{log_file} = 'Sys::Syslog';
  }
  elsif ($ltype & LOG_STDERR) {
    $srv_p->{log_file} = undef;  # tells Net::Server to log to stderr
  }

  # Redirect all warnings to logger
  $SIG{__WARN__} = sub { $self->wrn($_[0]); };
}


##################   SERVER METHODS   ######################

sub audit {
  my ($self, $msglines) = @_;
  my $prop = $self->{spampd};
  my $status;
  # Audit the message
  if ($prop->{sa_client}) {
    $status = $self->{assassinc}->process(\$msglines);
    return {
      'is_spam'    => $status->{isspam} eq "True",
      'score'     => $status->{score},
      'threshold' => $status->{threshold},
      'message'   => $status->{message},
      'report'    => $status->{report}
    };
  }
  my $assassin = $self->{assassin};
  my ($mail, $msg_resp);
  if ($prop->{sa_version} >= 3) {
    $mail = $assassin->parse(\$msglines, 0);
  }
  elsif ($prop->{sa_version} >= 2.70) {
    $mail = Mail::SpamAssassin::MsgParser->parse(\$msglines);
  }
  else {
    $mail = Mail::SpamAssassin::NoMailAudit->new(data => \$msglines);
  }

  # Check spamminess (returns Mail::SpamAssassin:PerMsgStatus object)
  my $result = $assassin->check($mail);
  # use Mail::SpamAssassin:PerMsgStatus object to rewrite message
  if ($prop->{sa_version} >= 3) {
    # inject _SPAMPDVERSION_ as a "template tag" (macro) for SA add_header
    $result->set_tag("SPAMPDVERSION", $self->VERSION) if ($prop->{sa_version} >= 3.0020);
    $msg_resp = $result->rewrite_mail;
  }
  else {
    # SA versions prior to 3 need to get the response in a different manner
    $result->rewrite_mail;
    $msg_resp = join '', $mail->header, "\r\n", @{$mail->body};
  }
  $status = {
    'is_spam'    => $result->is_spam,
    'score'     => $result->get_hits,
    'threshold' => $result->get_required_hits,
    'message'   => $msg_resp,
    'report'    => $result->get_names_of_tests_hit
  };
  $mail->finish();
  $result->finish();
  return $status;
}

sub process_message {
  my ($self, $fh) = @_;
  my $prop = $self->{spampd};

  # output lists with a , delimeter by default
  local ($") = ",";

  # start a timer
  my $start = time;
  # use the assassin object created during startup
  my $assassin   = $self->{assassin};

  # this gets info about the message temp file
  my $size = ($fh->stat)[7] or die "Can't stat mail file: $!";

  # Only process message under --maxsize KB
  if ($size >= ($prop->{maxsize} * 1024)) {
    $self->inf("skipped large message (" . $size / 1024 . "KB)");
    return 1;
  }

  my (@msglines, $msgid, $sender, $recips, $tmp, $mail, $msg_resp);
  my $inhdr      = 1;
  my $addedenvto = 0;
  my $envfrom    = !($prop->{envelopeheaders} || $prop->{setenvelopefrom});
  my $envto      = !$prop->{envelopeheaders};

  $recips = "@{$self->{smtp_server}->{to}}";
  if ("$self->{smtp_server}->{from}" =~ /(\<.*?\>)/) { $sender = $1; }
  $recips ||= "(unknown)";
  $sender ||= "(unknown)";

  ## read message into array of lines to feed to SA

  # loop over message file content
  $fh->seek(0, 0) or die "Can't rewind message file: $!";
  while (<$fh>) {
    if ($inhdr) {
      # we look for and possibly set some headers before handing to SA
      if (/^\r?\n$/) {
        # outside of msg header after first blank line
        $inhdr = 0;
        if (!$envfrom) {
          unshift(@msglines, "X-Envelope-From: $sender\r\n");
          $self->dbg("Added X-Envelope-From") ;
        }
        if (!$envto) {
          unshift(@msglines, "X-Envelope-To: $recips\r\n");
          $addedenvto = 1;  # we remove this header later
          $self->dbg("Added X-Envelope-To");
        }
      }
      else {
        # still inside headers, check for some we're interested in
        $envto   = $envto || (/^(?:X-)?Envelope-To: /);
        $envfrom = $envfrom || (/^(?:X-)?Envelope-From: /);
        # find the Message-ID for logging (code is mostly from spamd)
        if (/^Message-Id:\s+(.*?)\s*$/i) {
          $msgid = $1;
          while ($msgid =~ s/\([^\(\)]*\)//) { }  # remove comments and
          $msgid =~ s/^\s+|\s+$//g;               # leading and trailing spaces
          $msgid =~ s/\s+/ /g;                    # collapse whitespaces
          $msgid =~ s/^.*?<(.*?)>.*$/$1/;         # keep only the id itself
          $msgid =~ s/[^\x21-\x7e]/?/g;           # replace all weird chars
          $msgid =~ s/[<>]/?/g;                   # plus all dangling angle brackets
          $msgid =~ s/^(.+)$/<$1>/;               # re-bracket the id (if not empty)
        }
      }
    }
    # add the line to our result array
    push(@msglines, $_);
  }

  $msgid ||= "(unknown)";

  $self->inf("processing message $msgid for " . $recips);

  eval {

    local $SIG{ALRM} = sub { die "Timed out!\n" };

    # save previous timer and start new
    my $previous_alarm = alarm($prop->{satimeout});

    # Audit the message
    my $status = $self->audit(@msglines);
    undef @msglines;
    $self->dbg("Returned from checking by SpamAssassin");

    #  Rewrite mail if high spam factor or options --tagall
    if ($status->{is_spam} || $prop->{tagall}) {
      my $msg_resp = $status->{message};
      # remove the envelope-to header if we added it
      if ($addedenvto) {
        $self->dbg("Removing X-Envelope-To");
        $msg_resp =~ s/^X-Envelope-To: .+\r?\n//m;
      }

      # Write the modified mail back to the original file.
      # Pause the timeout alarm while we do this (no point in timing
      # out here and leaving a half-written file).
      my $pause_alarm = alarm(0);
      $fh->seek(0, 0) or die "Can't rewind message file: $!";
      $fh->truncate(0) or die "Can't truncate message file: $!";
      $fh->print($msg_resp)
        or die "Can't print to message file: $!";
      #restart the alarm
      alarm($pause_alarm);
    }  # end rewrite mail

    # Track some statistics
    my $stats = $prop->{runtime_stats};
    my $was_it_spam;
    my $time_d = time - $start;
    $stats->{req_time_last} = $time_d;
    $stats->{req_time_ttl} += $time_d;
    $stats->{req_time_avg} = $stats->{req_time_ttl} / $self->{server}->{requests};
    if ($status->{is_spam}) {
      ++$stats->{req_spam};
      $was_it_spam = 'identified spam';
    }
    else {
      ++$stats->{req_ham};
      $was_it_spam = 'clean message';
    }

    # Log what we did
    my $msg_score     = sprintf("%.2f", $status->{score});
    my $msg_threshold = sprintf("%.2f", $status->{threshold});
    my $proc_time     = sprintf("%.2f", $time_d);
    $self->inf("$was_it_spam $msgid ($msg_score/$msg_threshold) from $sender for " .
                    "$recips in ${proc_time}s, $size bytes, with rules v$prop->{runtime_stats}->{sa_rls_ver}");

    # thanks to Kurt Andersen for this idea
    $self->inf("rules hit for $msgid: " . $status->{report}) if ($prop->{rh});

    # set the timeout alarm back to wherever it was at
    alarm($previous_alarm);

  };  # end eval block

  if ($@ ne '') {
    $self->wrn("WARNING!! SpamAssassin error on message $msgid: $@");
    return 0;
  }

  return 1;
}

sub process_request {
  my $self = shift;
  my $prop = $self->{spampd};
  my $rcpt_ok = 0;

  eval {

    # start a timeout alarm
    local $SIG{ALRM} = sub { die "Child server process timed out!\n" };
    alarm($prop->{childtimeout});

    # start an smtp server
    my $smtp_server = SpamPD::Server->new($self->{server}->{client});
    die "Failed to create listening Server: $!" unless (defined $smtp_server);

    $self->{smtp_server} = $smtp_server;

    $self->dbg("Initiated Server");

    # start an smtp "client" (really a sending server)
    my $client = SpamPD::Client->new(
      interface   => $prop->{relayhost},
      port        => $prop->{relayport},
      unix_socket => $prop->{relaysocket}
    );
    die "Failed to create sending Client: $!" unless (defined $client);

    $self->dbg("Initiated Client");

    # pass on initial client response
    # $client->hear can handle multiline responses so no need to loop
    $smtp_server->reply($client->hear);

    $self->dbg("smtp_server state: '" . $smtp_server->{state} . "'");

    # while loop over incoming data from the server
    while (my $what = $smtp_server->chat) {

      $self->dbg("smtp_server state: '" . $smtp_server->{state} . "'");

      # until end of DATA is sent, just pass the commands on transparently
      if ($what ne '.') {
        $client->say($what);
      }
      # but once the data is sent now we want to process it
      else {
        # spam checking routine - message might be rewritten here
        my $pmrescode = $self->process_message($smtp_server->{data});

        # pass on the messsage if exit code <> 0 or die-on-sa-errors flag is off
        if ($pmrescode or !$prop->{dose}) {
          # need to give the client a rewound file
          $smtp_server->{data}->seek(0, 0)
            or die "Can't rewind mail file: $!";
          # now send the data on through the client
          $client->yammer($smtp_server->{data});
        }
        else {
          $smtp_server->reply("450 Temporary failure processing message, please try again later");
          last;
        }

        #close the temp file
        $smtp_server->{data}->close
          or $self->wrn("WARNING!! Couldn't close smtp_server->{data} temp file: $!");

        $self->dbg("Finished sending DATA");
      }

      # pass on whatever the relayhost said in response
      # $client->hear can handle multiline responses so no need to loop
      my $destresp = $client->hear;
      $smtp_server->reply($destresp);

      $self->dbg("Destination response: '" . $destresp . "'");

      # if we're in data state but the response is an error, exit data state.
      # Shold not normally occur, but can happen. Thanks to Rodrigo Ventura for bug reports.
      if ($smtp_server->{state} =~ /^data/i and $destresp =~ /^[45]\d{2} /) {
        $smtp_server->{state} = "err_after_data";
        $self->dbg("Destination response indicates error after DATA command");
      }

      # patch for LMTP - multiple responses after . after DATA, done by Vladislav Kurz
      # we have to count sucessful RCPT commands and then read the same amount of responses
      if ($smtp_server->{proto} eq 'lmtp') {
        if ($smtp_server->{state} =~ /^(?:rset|mail)/i) {
          $rcpt_ok = 0;
        }
        elsif ($smtp_server->{state} =~ /^rcpt/i and $destresp =~ /^25/) {
          $rcpt_ok++;
        }
        elsif ($smtp_server->{state} eq '.') {
          while (--$rcpt_ok) {
            $destresp = $client->hear;
            $smtp_server->reply($destresp);
            $self->dbg("Destination response: '" . $destresp . "'");
          }
        }
      }

      # restart the timeout alarm
      alarm($prop->{childtimeout});

    }  # server ends connection

    # close connections
    $client->{sock}->close
      or die "Couldn't close Client socket: $!";
    $smtp_server->{sock}->close
      or die "Couldn't close Server socket: $!";

    $self->dbg("Closed connections");

  };  # end eval block

  alarm(0);  # stop the timer
  # check for error in eval block
  if ($@) {
    chomp($@);
    $self->err("WARNING!! Error in process_request eval block: $@");
    $self->{server}->{done} = 1;  # exit this child gracefully
  }
}

# Net::Server hook: After binding listening sockets
sub post_bind_hook {
  my $prop = $_[0]->{spampd};
  if (defined($prop->{socket}) and defined($prop->{socket_mode})) {
    chmod(oct($prop->{socket_mode}), $prop->{socket})
      or $_[0]->fatal("Couldn't chmod '$prop->{socket}' [$!]\n");
  }
}

# Net::Server hook: about to fork a new child
sub pre_fork_hook {
  return if $_[1];  # && $_[1] eq 'dequeue';
  ++$_[0]->{spampd}->{runtime_stats}->{child_count};
}

# Net::Server hook: new child starting
sub child_init_hook {
  return if $_[1];  # && $_[1] eq 'dequeue';
  # set process name to help clarify via process listing which is child/parent
  $_[0]->update_child_name();
}

# Net::Server hook: about to exit child process
sub child_finish_hook {
  return if $_[1];  # && $_[1] eq 'dequeue';
  $_[0]->dbg("Exiting child process after handling " . $_[0]->{server}->{requests} . " requests");
}

# Net::Server hook: new connection established
sub post_accept_hook {
  my $self = $_[0];
  $self->{spampd}->{runtime_stats}->{req_count} = $self->{server}->{requests};
  $self->{spampd}->{runtime_stats}->{child_status} = "C";
  $self->update_child_name();
}

# Net::Server hook: connection ended
sub post_client_connection_hook {
  $_[0]->{spampd}->{runtime_stats}->{child_status} = "D";
  $_[0]->update_child_name();
}

# Net::Server hook: called when we're using SA Logger or falling back to Net::Server logging.
sub write_to_log_hook {
  my ($self, $level, $msg) = @_;
  if ($self->{spampd}->{logtype} & LOGGER_SA)
    { Mail::SpamAssassin::Logger::log_message(SA_LOG_LEVELS->{$level}, $msg); }
  else
    { $self->SUPER::write_to_log_hook($level, $msg); }
}

# Net::Server override: default behavior on HUP is to delete $ENV{'PATH'}, but we like our PATH as it is.
sub hup_delete_env_keys { return ''; }

# Convenience logging aliases
sub err { shift()->log(0, @_); }
sub wrn { shift()->log(1, @_); }
sub inf { shift()->log(2, @_); }
sub nte { shift()->log(3, @_); }
sub dbg { shift()->log(4, @_); }


##################   FUNCTIONS   ######################

# =item read_args_from_file(<files array>, <dest array ref>)
# Loads all options from a list of files into destination array (typically \@ARGV).
# Options loaded from file(s) are placed before any existing items in the destination array
#  (this is done to preserve precedence of any command-line arguments). Options in subsequent
#  files will override (or add to) the same option in any previous file(s).
# All options found in files following a lone "--" separator are appended to the very end
#   of the destination array, after a "--" item. This is meant to mimick the behavior of
#   Getopt::Long passthrough argument handling.
sub read_args_from_file() {
  my ($config_files, $to_args) = @_;
  return if !($config_files && $to_args);
  my @extra_args;  # store any passthrough args to add at the end
  # loop over files in reverse order so that precedence is maintained
  for (reverse(@$config_files)) {
    # load arguments from file
    my ($args, $ptargs) = read_conf_file(untaint_path($_), '=');
    # add to beginning of array, this way command line arg override config files
    unshift(@{$to_args}, @{$args});
    unshift(@extra_args, @{$ptargs});  # save any passthrough args for later
  }
  # add any passthrough args at the end, after processing all the files
  if (@extra_args) {
    push(@{$to_args}, '--');  # separator for Getopt::Long
    push(@{$to_args}, @extra_args);
  }
}

# =item read_conf_file(file [, separator = "="] [, prefix = "--"])
# Parses a basic configuration file into an array of options suitable for use in a command line.
# By default the result key/value separator is an "=" sign. This can be overriden by providing a second argument.
#   If a blank value is passed as separator, the keys and values will be added as separate array items.
# Returns 2 arrays: one with all options before encountering a lone "--" separator, and another (possibly blank)
#   with any options found after the "--" separator. (This is for handling "passthrough" options since they must be
#   placed at the end of a command line. The actual "--" separator is not included. See Getopt::Long for more details
#   about passthrough options).
# Config files support commented and blank lines, with one name/value pair per line. Values are optional.
#   Preceeding option names with "-" or "--" is optional. An optional prefix (default "--") will be prepended to the
#   name if it does not begin with at least one "-". Names and values can be separated by space(s)/tab(s) or "=" sign.
#
sub read_conf_file {
  my ($file, $sep, $prfx) = @_;
  return ([], []) if !$file;
  my (@args, @ptargs);
  my $dest = \@args;
  $sep //= '=';
  $prfx //= '--';
  open(my $fh, '<', $file) or die "Couldn't open config file '$file' [$!]";
  while (defined(my $line = <$fh>)) {
    next if ($line !~ m/^\s* ((?:--?)?[\w\@-]+) (?:[=:\t ]+ (.+) \s*)?$/xo);
    ($dest = \@ptargs) && next if $1 eq '--';
    my $k = $1;
    my $v = $2 || "";
    $v =~ s/^"(.*)"$/$1/;
    $k = join('', $prfx, $k) if $prfx && substr($k, 0, 1) ne '-';
    $k = join($sep, $k, $v) if $sep && $v ne '';
    push (@{$dest}, $k);
    push (@{$dest}, $v) if !$sep && $v ne '';
  }
  close $fh;
  return (\@args, \@ptargs);
}

# Converts a string or array of --logfile options to a log type bitfield of LOG_* constants.
# Returns the log type and either an actual logfile name, or undef if there wasn't one.
sub logfile2logtype {
  my ($spec, $type, $sep) = @_;
  $spec = [$spec] if !ref($spec);
  $sep //= ":";
  $type //= 0;
  my $file;
  # Handle ":" record separator and trim values.
  trimmed(@$spec = split(qr($sep), join($sep, @$spec)));
  for (@$spec) {
    if ($_ eq 'syslog') {
      $type |= LOG_SYSLOG;
    }
    elsif ($_ eq 'stderr') {
      $type |= LOG_STDERR;
    }
    elsif ($_ = untaint_path($_)) {
      $type |= LOG_FILE;
      $file = $_;
    }
  }
  return ($type, $file);
}

# Converts a bitfield of logging type, plus optional file name, to an array/list
# of values which would be suitable for the commandline --logfile (-o) option.
sub logtype2logfile {
  my ($type, $file, $sep) = @_;
  my @ret;
  push(@ret, 'syslog') if ($type & LOG_SYSLOG);
  push(@ret, 'stderr') if ($type & LOG_STDERR);
  push(@ret, $file)    if ($type & LOG_FILE) && $file;
  my $q = @ret > 1 ? '"' : '';
  return wantarray ? @ret : $q.join($sep || ' : ', @ret).$q;
}

# Untaint a scalar (or ref to one) or an array ref (most code "borrowed" from spamd)
sub untaint_var {
  my $r = ref $_[0];
  if (!$r) {
    return if !defined($_[0]);
    local $1;
    $_[0] =~ /^(.*)$/;
    return $1;
  }
  my $arg = $_[0];
  if ($r eq 'ARRAY') {
    $_ = untaint_var($_) for @{$arg};
    return @{$arg} if wantarray;
  }
  elsif ($r eq 'SCALAR' || $r eq 'REF') {
    ${$arg} = untaint_var(${$arg});
  }
  else {
    warn "Not untainting a $r !\n";
  }
  return $_[0];
}

# Untaint a path/file value (most code "borrowed" from spamd)
sub untaint_path {
  my ($path) = @_;
  return unless defined($path);
  return '' if ($path eq '');
  my $chars = '-_a-z0-9.%=+,/:()\\@\\xA0-\\xFF\\\\';
  my $re = qr{^\s*([$chars][${chars}~ ]*)\z}io;
  local $1;
  return $1 if ($path =~ $re);
  warn "WARNING! Refusing to untaint suspicious path: '$path'\n";
  return '';
}

# Trims a string or array of strings. Modifies whatever was passed in!
sub trimmed { s{^\s+|\s+$}{}g foreach @_; };

sub deprecated_opt {
  warn "Note: option '".$_[0]."' is deprecated and will be ignored.\n";
}

# Try to display a temporary HTML file in a browser (used to show "--man html").
sub show_html_file {
  (my $tmpfile = shift) || return;  # should be a File::Temp type

  # if we get here, handle html output: first try to show it in a browser.
  my $disp_ok = eval {
    require HTML::Display;
    print "Using HTML::Display to display HTML.\n";
    HTML::Display::display(file => $tmpfile->filename());
  };
  # if HTML::Display is not installed, just try Debian or OSX style, or bail out.
  if (!$disp_ok) {
    my ($deb, $mac) = (-x "/usr/bin/x-www-browser"), ($^O =~ qr/darwin/i);
    if (my $cmdline = ($deb ? "x-www-browser " : ($mac ? "open " : undef))) {
      $cmdline .= $tmpfile->filename()." > /dev/null 2>&1" if $cmdline;
      if ($disp_ok = (system($cmdline) == 0))
        { print "Waiting to delete temp file...\n"; sleep 3; }
    }
  }
  if ($disp_ok) {
    $tmpfile->unlink_on_destroy(1);
    print "Removing temporary perldoc file ".$tmpfile->filename()."\n";
  }
  else {
    print "Unable to start a browser, open the generated HTML file manually.\n";
    print "Consider installing the HTML::Display Perl module.\n" if !defined($HTML::Display::VERSION);
  }
}

# =item sprintf_named(<format_string>, <value_hash_ref>)
# Like C<sprintf()> but with named parameter support. Converts named placeholders to printf-style
# positional arguments based on a passed hash of values. Supports all typical printf formatting options.
# Parameters are specified like: "Value of %(my_name)s is %(my_float_value).4f", with names in parenthesis,
# or simply "Value of %my_name is %my_value" with the default format being a string.
# Original code from https://metacpan.org/dist/Text-sprintfn/source/lib/Text/sprintfn.pm
# simplified and optimized for our humble needs.
sub sprintf_named {
  my ($format, $hash) = @_;
  my $regex = qr{( #all=1
    ( #fmt=2
      %
      (?| #npi=3
        \((\w+)\) | (\w+)
      )?
      # any format specifiers must follow a ")"
      (?:(?<=\))
        (#flags=4
          [ +0#-]+
        )?
        (#vflag=5
          \*?[v]
        )?
        (#width=6
          -?\d+ | \*\d+\$?
        )?
        (#dot=7
          \.?)
        (#prec=8
          (?: \d+ | \*)
        )?
        (#conv=9
          [%csduoxefgXEGbBpniDUOF]
        )?
      )?
    ) | % | [^%]+
  )}xs;

  my @args;
  my $replace = sub {
    my ($all, $fmt, $npi, $flags, $vflag, $width, $dot, $prec, $conv) = @_;
    if ($fmt && defined($npi) && defined(my $val = $hash->{$npi})) {
      push(@args, $val);
      return join("",
        grep {defined} ("%", $flags, $vflag, $width, $dot, $prec, $conv || "s")
      );
    }
    return $all;
  };
  $format =~ s/$regex/$replace->($1, $2, $3, $4, $5, $6, $7, $8, $9)/ge;
  # use Data::Dump; dd [$format, @args];
  return sprintf($format, @args);
}


##################   UTILITY METHODS   ######################

# returns true if server is being restarted with a SIGHUP.
sub is_reloading { return !!$ENV{'BOUND_SOCKETS'}; };

# set process name to a string formatted from user-specified template
sub update_child_name {
  my $self = $_[0];
  return if !$self->{spampd}->{child_name_templ};
  eval { $0 = $self->format_stats_string($self->{spampd}->{child_name_templ}); };
  $self->dbg("Error in update_child_name(): $@") if $@ ne '';
}

# Calls sprintf_named() on passed string with {$self->{spampd}->{runtime_stats} data hash.
# Returns results or blank string if error. Errors are logged to debug stream.
sub format_stats_string {
  my ($self, $string) = @_;
  my $ret = eval { sprintf_named($string, \%{$self->{spampd}->{runtime_stats}}); };
  $self->dbg("Error calling sprintf_named(): $@") if $@ ne '';
  # $self->dbg($ret);
  return $ret || "";
}

# =item print_options(\%options [, type = "default"] [, exit = -1])
# Prints out names and values from a hash of option {name => \$value} pairs, such as might
#   be passed to Getopt::Long::GetOptions(). Fairly limited, eg. it cannot handle hash values.
# Any value that is not a ref to a scalar or to an array ref is ignored. The first version of the
#   option name, before the first "|", is used as the option name. Any option spec is also excluded.
sub print_options {
  my ($self, $opts) = (shift, shift);
  my $type = ($_[0] && $_[0] !~ /^\d+$/ ? shift : 'default');
  my $exit = @_ ? $_[0] : -1;
  print "\n";
  print "# Configuration options for ".ref($self)." v".$self->VERSION." with ".$type." values.\n";
  print "# This format is suitable as a configuration file. Just remove\n".
        "# the '#' marks (comment characters) and change values as needed.\n\n" if $exit > -1;
  for my $k (sort keys %{$opts}) {
    my $v = $opts->{$k};
    next if ref($v) !~ /SCALAR|REF/;
    $k = $1 if $k =~ /([\w-]+).*/;
    $v = defined(${$v}) ? ${$v} : "(undefined)";
    $v = join(":", @{$v}) if ref($v) eq 'ARRAY';
    printf("# %-24s %s\n", $k, $v);
  }
  print "\n";
  exit $exit if $exit > -1;
}

# =item show_debug($what, [ \%options, \@startup_args | \$thing_to_dump [,\$another_thing[,...]] ])
# Debug helper, print some values and exit. $what can be an array or single string or CSV list.
# $what values: [ all | [vers(ion), conf(ig), argv, start(args), self] ] | obj(ect)
#   "all" means everything except "object".
#   "obj" means just dump the rest of the argument(s); ignores rest of $what, basically Data::Dumper->Dump(@_)
# Always returns true, even if there is an error, so can be used eg.: show_debug(...) && exit(0);
sub show_debug {
  eval {
    my ($self, $what, $opts, $clargs) = (shift, shift);
    my ($ok, @dumps, @dnames) = (0);
    $what = [$what] if !ref($what);
    trimmed(@$what = split(/,/, join(',', @$what)));
    if (grep(/^obj(ect)?$/i, @$what)) {
      push(@dumps, @_);
    }
    else {
      ($opts, $clargs) = @_;
      if (grep(/^(vers(ion)?|all)$/i, @$what))
        { $self->version(-1); $ok = 1; }
      if (grep(/^(conf(ig)?|all)$/i, @$what) && $opts)
        { $self->print_options($opts, 'current', -1); $ok = 1; }
      if (grep(/^(argv|all)$/i, @$what))
        { push(@dumps, \@ARGV);   push(@dnames, '*ARGV'); }
      if (grep(/^(start\w*|all)$/i, @$what))
        { push(@dumps, $clargs); push(@dnames, '*startup_args'); }
      if (grep(/^(self|all)$/i, @$what))
        { push(@dumps, %$self);   push(@dnames, qw(object *values object *values object *values)); }
    }
    if (@dumps) {
      eval {
        require Data::Dumper;
        no warnings 'once';  # https://github.com/mpaperno/spampd/issues/30#issuecomment-889117210
        $Data::Dumper::Quotekeys = 0;
        $Data::Dumper::Bless = '';
        $Data::Dumper::Sortkeys = 1;
        $Data::Dumper::Sparseseen = 1;
        print("\n". Data::Dumper->Dump(\@dumps, \@dnames) ."\n");
      };
      warn "Data::Dumper error:\n\t$@\n\n" if $@;
    }
    elsif (!$ok) {
      warn "Don't know how to show '@$what', sorry.\n\n";
    }
  };
  warn $@ if $@;
  return 1;
}

sub version {
  my ($self, $exit) = (shift, @_ ? $_[0] : 0);
  print __PACKAGE__." version $VERSION\n";
  print "  using ".$self->net_server_type()." ".Net::Server->VERSION()."\n";
  print "  using SpamAssassin ".Mail::SpamAssassin::Version()."\n";
  print "  using Perl ".(split(/v/, $^V))[-1]."\n\n";
  exit $exit if $exit > -1;
}

# =item usage([exit_value=2, [help_level=1, [help_format=man]]])
sub usage {
  my $self = shift;
  my ($exitval, $hlevel, $helpfmt) = @_;
  $exitval = 2 if !defined($exitval);
  $hlevel ||= 1;
  $helpfmt ||= 'man';
  my ($width, $indent, $quotes, $type, $vers) = (78, 2, "`", ref($self), $self->VERSION());
  my (@sections, $msg, $outfile, $pdoc_opts);

  eval {
    if ($helpfmt !~ /^txt$/i) {
      no warnings 'once';  # silence useless "$Pod::Usage::Formatter used only once: possible typo" warning
      $Pod::Usage::Formatter = 'Pod::Text::Termcap';
    }
    require Pod::Usage;
  } or die "Could not load Pod::Usage!\n\t$@";

  if ($hlevel == 4) {
    # decide which perldoc formatter (-o) to use (currently only works with full docs due to Pod::Usage behavior of -verbose < 2)
    if ($helpfmt =~ /^html?$/i) {
      eval {
        require File::Temp; require File::Spec;
        $outfile = File::Temp->new(
          TEMPLATE => "spampd_XXXXXX", SUFFIX => '.html', UNLINK => 0,
          DIR => untaint_path($ENV{'TMPDIR'} || File::Spec->tmpdir())
        );
        $pdoc_opts = "-o html -w index -d " . $outfile->filename() if $outfile;
      };
      warn "Could not create temp file for html output: $@\n" if $@;
    }
    elsif ($helpfmt =~ /^man$/i) {
      $pdoc_opts = "-o man -w quotes:$quotes -w section:8 -w release:".$vers." ".
                   "-w center:".$type." -w name:".lc($type);
    }
    elsif ($helpfmt =~ /^txt$/i) {
      $pdoc_opts = "-o text -T -w width:$width -w indent:$indent -w quotes:$quotes";
    }
  }
  else {
    push(@sections, "USAGE")    if $hlevel == 1 || $hlevel == 3;
    push(@sections, "SYNOPSIS") if $hlevel == 2;
    push(@sections, "OPTIONS")  if $hlevel == 3;
    $msg = "\n".$type." version ".$vers."\n";
  }

  Pod::Usage::pod2usage(
    -verbose => (@sections ? 99 : 2),
    -message => $msg,
    -sections => \@sections,
    -perldocopt => $pdoc_opts,
    -exitval => "NOEXIT",
    # text formatter options
    width => $width, indent => $indent, quotes => $quotes, errors => "none"
  );
  show_html_file($outfile) if $outfile;
  exit $exitval;
}

1;

__END__

##################   POD   ######################

=encoding UTF-8

=head1 NAME

SpamPD - Spam Proxy Daemon

=head1 VERSION

Documentation for SpamPD version 2.61.


=head1 DESCRIPTION

I<spampd> is an SMTP/LMTP proxy that marks (or tags) spam using
SpamAssassin (L<http://www.SpamAssassin.org/>). The proxy is designed
to be transparent to the sending and receiving mail servers and at no point
takes responsibility for the message itself. If a failure occurs within
I<spampd> (or SpamAssassin) then the mail servers will disconnect and the
sending server is still responsible for retrying the message for as long
as it is configured to do so.

I<spampd> uses SpamAssassin to modify (tag) relayed messages based on
their spam score, so all SA settings apply. This is described in the SA
documentation.  I<spampd> will by default only tell SA to tag a
message if it exceeds the spam threshold score, however you can have
it rewrite all messages passing through by adding the --tagall option
(see SA for how non-spam messages are tagged).

I<spampd> logs all aspects of its operation to syslog(8), using the
mail syslog facility.

The latest version can be found at L<https://github.com/mpaperno/spampd>.


=head1 SYNOPSIS

B<spampd> I<[ options ]>

Options:

  --config <filename>        Load options from file(s).

  --host <host>[:<port>]     Hostname/IP and optional port to listen on.
  --port <n>                 Port to listen on (alternate syntax to above).
  --socket <socketpath>      UNIX socket to listen on.
  --socket-perms <mode>      The octal mode to set on the UNIX socket.
  --relayhost <hst>[:<prt>]  Host and optional port to relay mail to.
  --relayport <n>            Port to relay to (alternate syntax to above).
  --relaysocket <sockpath>   UNIX socket to relay to.

  --min-servers | -mns  <n>  The minimum number of servers to keep running.
  --min-spare   | -mnsp <n>  The minimum number of servers to have waiting.
  --max-spare   | -mxsp <n>  The maximum number of servers to have waiting.
  --max-servers | -mxs  <n>  The maximum number of child servers to start.
  --maxrequests or -r <n>    Maximum requests that each child can process.
  --childtimeout <n>         Time out children after this many seconds.
  --satimeout <n>            Time out SpamAssassin after this many seconds.
  --child-name-template [s]  Template for formatting child process name.

  --pid   or -p <filename>   Store the daemon's process ID in this file.
  --user  or -u <user>       Specifies the user that the daemon runs as.
  --group or -g <group>      Specifies the group that the daemon runs as.

  --[no]detach               Detach from the console daemonize (default).
  --[no]setsid               Completely detach from stderr with setsid().

  --maxsize n                Maximum size of mail to scan (in KB).
  --dose                     (D)ie (o)n (s)pamAssassin (e)rrors.
  --tagall                   Tag all messages with SA headers, not just spam.
  --set-envelope-headers     Set X-Envelope-From and X-Envelope-To headers.
  --set-envelope-from        Set X-Envelope-From header only.

  --local-only or -L         Turn off all SA network-based tests.
  --homedir <path>           Use the specified directory as SA home.
  --saconfig <filename>      Use the file for SA "user_prefs" configuration.

  --logfile or -o <dest>     Destination for logs (syslog|stderr|<filename>).
  --logsock or -ls <sock>    Allows specifying the syslog socket type.
  --logident or -li <name>   Specify syslog identity name.
  --logfacility or -lf <nm>  Specify syslog facility (log name).
  --log-rules-hit or -rh     Log the names of each matched SA test per mail.
  --debug or -d [<areas>]    Controls extra debug logging.

  --help | -h | -?   [txt]   Show basic command-line usage.
          -hh | -??  [txt]   Show short option descriptions (this text).
         -hhh | -??? [txt]   Show usage summary and full option descriptions.
  --man [html|txt]           Show full docs a man page or HTML/plain text.
  --show defaults|<thing>    Print default option values or <thing> and exit.
  --version                  Print version information and exit.

Compatibility with previous SpamPD versions:

  --children or -c <n>       Same as --max-servers | -mxs (since v2.60).

Deprecated since SpamAssassin v3:

  --auto-whitelist or -aw    Use the SA global auto-whitelist feature.


=head1 REQUIRES

Perl modules:

=over 5

=item B<Mail::SpamAssassin>

=item B<Net::Server> (>= v0.89, v2.009+ recommended) with B<PreForkSimple> and/or B<PreFork> submodules.

=item B<IO::File>

=item B<Time::HiRes>

=item B<IO::Socket::IP> (if using TCP/IP sockets)

=item B<IO::Socket::UNIX> (if using UNIX sockets)

=back

=head1 OPERATION

I<spampd> is meant to operate as an S/LMTP mail proxy which passes
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

Here are some simple examples (square brackets in the "diagrams" indicate
physical machines):

=over 2

=item B<Running between firewall/gateway and internal mail server>

The firewall/gateway MTA would be configured to forward all of its mail
to the port that I<spampd> listens on, and I<spampd> would relay its
messages to port 25 of your internal server. I<spampd> could either
run on its own host (and listen on any port) or it could run on either
mail server (and listen on any port except port 25).

  Internet ->
  [ MX gateway (@inter.net.host:25) -> spampd (@localhost:2025) ] ->
  [ Internal mail (@private.host.ip:25) ]

=item B<Using Postfix advanced content filtering>

Please see the F<FILTER_README> that came with the Postfix distribution.  You
need to have a version of Postfix which supports this (ideally v.2 and up).

  Internet -> [ Postfix (@inter.net.host:25)  ->
                spampd (@localhost:10025)     ->
                Postfix (@localhost:10026)  ] -> final delivery

=back

Note that these examples only show incoming mail delivery.  Since it is
often unnecessary to scan mail coming from your network, it may be desirable
to set up a separate outbound route which bypasses I<spampd>.

=head2 Scalable Mode

Since v2.60 I<spampd> can optionally run in "scalable mode" which dynamically adjusts the number
of child servers which can process requests simultaneously. This is activated automatically if the
C<--min-servers> option is specifically set to be lower than C<--max-servers>.

Historically I<SpamPD> inherited from the module I<Net::Server::PreForkSimple> which only allows for
a static number of child servers to be running at once. This new option essentially allows for inheriting from
I<Net::Server::PreFork> which features dynamic allocation of child servers, with some tunable parameters.
(The reason I<PreFork> wasn't used to begin with is because older versions of it didn't seem to work...
it was an old TODO to try again later.)

Here is what the I<Net::Server::PreFork> documentation has to say (option names changed to match I<spampd>):

I<"This personality binds to one or more ports and then forks C<--min-servers> child process.  The server
will make sure that at any given time there are C<--min-spare> servers available to receive a client
request, up to C<--max-servers>. Each of these children will process up to C<--maxrequests> client
connections. This type is good for a heavily hit site, and should scale well for most applications.">

Some experimentation and tuning will likely be needed to get the best performance vs. efficiency. Keep in mind
that a SIGHUP sent to the parent process will reload configuration files and restart child servers gracefully
(handy for tuning a busy site).

See the documentation for C<--min-servers>, C<--max-servers>, C<--min-spare>, and C<--max-spare> options,
and also the section about L</"Other Net::Server Options"> for tuning parameters and links to further documentation.


=head1 INSTALLATION AND CONFIGURATION

I<spampd> can be run directly from the command prompt if desired.  This is
useful for testing purposes, but for long term use you probably want to put
it somewhere like /usr/bin or /usr/local/bin and execute it at system startup.
For example on Red Hat-style Linux system one can use a script in
/etc/rc.d/init.d to start I<spampd> (a L<sample script|https://github.com/mpaperno/spampd/tree/master/misc>
is available in the I<spampd> code repository).

I<spampd> is available as a B<package> for a significant number of Linux distributions,
including Debian and derivatives (Ubuntu, etc). This is typically the easiest/best way
to install and configure I<spampd> since it should already take into account any system
specifics for setting up and running as a daemon, etc.  Note however that packages
might not offer the latest version of I<spampd>. A good reference for available
packages and their versions can be found at L<https://repology.org/project/spampd/versions>.

I<spampd> is also used in the turnkey L<Mail-in-a-Box|https://mailinabox.email/>
project, which includes Postfix as the main MTA and Dovecot as the local delivery agent
with LMTP protocol. Even if you don't need the turnkey solution, it may be informative
to peruse the MIAB L<setup|https://github.com/mail-in-a-box/mailinabox/tree/master/setup> /
L<configuration|https://github.com/mail-in-a-box/mailinabox/tree/master/conf> files for reference.

All I<spampd> options have reasonable defaults, especially for a Postfix-centric
installation.  You may want to specify the C<--max-servers> option if you have an
especially beefy or weak server box because I<spampd> is a memory-hungry
program.  Check the L<"Options"> for details on this and all other parameters.

To show default values for all options, run C<spampd --show defaults>.

B<Since v2.61> I<spampd> injects a C<_SPAMPDVERSION_>
L<"template tag"|https://spamassassin.apache.org/doc/Mail_SpamAssassin_Conf.html#TEMPLATE-TAGS>
macro at message processing time. This can be used in an C<add_header> SA config file directive, for example.

  add_header all Filter-Version SpamAssassin _VERSION_ (_SUBVERSION_, Rules: _RULESVERSION_) / SpamPD _SPAMPDVERSION_

Note that B< I<spampd> replaces I<spamd> > from the I<SpamAssassin> distribution
in function. You do not need to run I<spamd> in order for I<spampd> to work.
This has apparently been the source of some confusion, so now you know.

=head2 Postfix-specific Notes

Here is a typical setup for Postfix "advanced" content filtering as described
in the F<FILTER_README> that came with the Postfix distribution (which you
really need to read):

F</etc/postfix/master.cf>:

  smtp             inet  n  -  y  -  -   smtpd
    -o content_filter=smtp:localhost:10025
    -o myhostname=mx.example.com

  localhost:10026  inet  n  -  n  -  10  smtpd
    -o content_filter=
    -o myhostname=mx-int.example.com

The first entry is the main public-facing MTA which uses localhost:10025
as the content filter for all mail. The second entry receives mail from
the content filter and does final delivery.  Both smtpd instances use
the same Postfix F<main.cf> file.  I<spampd> is the process that listens on
localhost:10025 and then connects to the Postfix listener on localhost:10026.
Note that the C<myhostname> options must be different between the two instances,
otherwise Postfix will think it's talking to itself and abort sending.

For the above example you can simply start I<spampd> like this:

 spampd --host=localhost:10025 --relayhost=localhost:10026

F<FILTER_README> from the Postfix distro has more details and examples of
various setups, including how to skip the content filter for outbound mail.

Another tip for Postfix when considering what timeout values to use for
--childtimout and --satimeout options is the following command:

C<# postconf | grep timeout>

This will return a list of useful timeout settings and their values.  For
explanations see the relevant C<man> page (smtp, smtpd, lmtp).  By default
I<spampd> is set up for the default Postfix timeout values.

The following guide has some more specific setup instructions:
B<L<Integrating SpamAssassin into Postfix using spampd|https://wiki.apache.org/spamassassin/IntegratePostfixViaSpampd>>


=head1 UPGRADING

Always consult the F<changelog.txt> file which should be included in the I<spampd> repository/distribution.

If upgrading from a version B<prior to 2.2>, please note that the --add-sc-header
option is no longer supported.  Use SA's built-in header manipulation features
instead (as of SA v2.6).

Upgrading from B<version 1> simply involves replacing the F<spampd> program file
with the latest one.  Note that the I<dead-letters> folder is no longer being
used and the --dead-letters option is no longer needed (though no errors are
thrown if it's present).  Check the L</OPTIONS> list below for a full list of new
and deprecated options.  Also be sure to check out the change log.

B<Since v2.60> I<spampd> has a new L</"Scalable Mode"> feature which varies the number of running
child servers based on demand. This is disabled by default. The option previosly known as
C<--children> (or C<-c>) is now called C<--max-servers> (or C<-mxs>), but the old style is still accepted.
See descriptions of the C<max-servers> and C<min-servers> options for details.

Also note that v2.60 added the ability to use a L</"CONFIGURATION FILE"> for specifying all options.


=head1 USAGE

  spampd [
    [ --config | --cfg | --config-file | --cfg-file [<filename>] ][...]

    [ --host <host>[:<port>]      | --socket <path> --socket-perms <mode> ]
    [ --relayhost <host>[:<port>] | --relaysocket <path>                  ]

    [--min-servers | -mns  <n>] [--saconfig  <file>] [--user  | -u <user>  ]
    [--min-spare   | -mnsp <n>] [--satimeout <n>   ] [--group | -g <group> ]
    [--max-spare   | -mxsp <n>] [--dose            ] [--pid   | -p <file>  ]
    [--max-servers | -mxs  <n>] [--maxsize   <n>   ] [--[no]detach         ]
    [--maxrequests | -r    <n>] [--local-only | -L ] [--[no]setsid         ]
    [--childtimeout        <n>] [--tagall     | -a ] [--log-rules-hit | -rh]
    [ --child-name-template | -cnt [<template>] ]    [--homedir <path>     ]
    [ [--set-envelope-headers | -seh] | [--set-envelope-from | -sef] ]

    [ --logfile | -o (syslog|stderr|<filename>) ][...]
    [ --logsock | -ls <socketpath>    ]  [ --logident    | -li <name> ]
    [ --debug   | -d [<area,...>|1|0] ]  [ --logfacility | -lf <name> ]
    [ --show ( all | (defaults, config, version, argv, start, self) ) ][...]
  ]
  spampd --version
  spampd [--help | -?] | -?? [txt] | -??? [txt] | [-???? | --man [html|txt]]

Options are case-insensitive. "=" can be used as name/value separator
instead of space (--name=value). "-" or "--" prefix can be used
for all options. Shortest unique option name can be used. All options must
be listed individually (no "bundling"). All boolean options can take an
optional argument of 1 or 0, or can be negated by adding a "no-" prefix
in front of the name. An option specified on the command line overrides the
same option loaded from config file(s).

=head1 OPTIONS

Please be sure to also read the general information about specifying option
arguments in the above L</"USAGE"> section.

To view B<default values> for all options, run C<spampd --show defaults>.

=over 5

=item B<--config> or B<-cfg> or B<--config-file> or B<--cfg-file> I<<filename>> C<new in v2.60>

Load options from one or more configuration file(s). This option can be specified
multiple times. The C<filename> can also be a list of files separated by a C<:>
(colon). If multiple files specify the same option, the last one loaded
will take precedence. Also any options specified on the actual command line will
take precedence (regardless of where they appear relative to the C<--config> option).
B<--config can only be specified on the command line>, one cannot use it within
another configuration file.

See L</"CONFIGURATION FILE"> section for more details.


=item B<--host> I<< (<ip>|<hostname>)[:<port>] >>

Specifies what hostname/IP and port I<spampd> listens on. By default, it listens
on 127.0.0.1 (localhost) on port 10025.

As of v2.60 this option can also handle IPv6 addresses in the form of
C<--host n:n:n> or, with port, C<--host [n:n:n]:port> (the square brackets are optional
in both forms but recommended in the latter case).

Note that the I<port> specified this way implicitly overrides the C<--port> option.

B<Important!> You should NOT enable I<spampd> to listen on a
public interface (IP address) unless you know exactly what you're doing!


=item B<--port> I<<n>>

Specifies what port I<spampd> listens on. This is an alternate to using the above
C<--host=ip:port> notation. Note that a I<port> specified in the C<--host> option
will override this one.


=item B<--socket> I<<socketpath>>

Specifies what UNIX socket I<spampd> listens on. If this is specified,
--host and --port are ignored.


=item B<--socket-perms> I<<mode>>

The file mode for the created UNIX socket (see --socket) in octal
format, e.g. 700 to specify acces only for the user I<spampd> is run as.


=item B<--relayhost> I<< (<ip>|<hostname>)[:<port>] >>

Specifies the hostname/IP to which I<spampd> will relay all
messages. Defaults to 127.0.0.1 (localhost) on port 25.

As of v2.60 this option can also handle IPv6 addresses in the form of
C<--relayhost n:n:n> or, with port, C<--relayhost [n:n:n]:port> (the square brackets
are optional in both forms but recommended in the latter case).

Note that the I<port> specified this way implicitly overrides the C<--relayport> option.


=item B<--relayport> I<<n>>

Specifies what port I<spampd> will relay to. This is an
alternate to using the above --relayhost=ip:port notation. Note that a I<port>
specified in the C<--relayhost> option will override this one.


=item B<--relaysocket> I<<socketpath>>

Specifies what UNIX socket spampd will relay to. If this is specified
--relayhost and --relayport will be ignored.


=item B<--user> or B<-u> I<<username>>

=item B<--group> or B<-g> I<<groupname>>

Specifies the user and/or group that the proxy will run as. Default is
I<mail>/I<mail>.


=item B<--children> or B<-c> I<<n>>

=item B<--max-servers> or B<-mxs> I<<n>> C<new in v2.60>

Number of child servers to start and maintain (where n > 0). Each child will
process up to C<--maxrequests> (below) before exiting and being replaced by
another child.  Keep this number low on systems w/out a lot of memory.
Note that there is always a parent process running, so if you specify 5 children you
will actually have 6 I<spampd> processes running.

B<Note:> If C<--min-servers> option is also set, and is less than C<--max-servers>,
then the server runs in L</"Scalable Mode"> and the meaning of this option changes.
In scalable mode, the number of actual running servers will fluctuate between C<--min-servers>
and C<--max-servers>, based on demand.

You may want to set your origination mail server to limit the
number of concurrent connections to I<spampd> to match this setting (for
Postfix this is the C<xxxx_destination_concurrency_limit> setting where
'xxxx' is the transport being used, usually 'smtp' or 'lmtp').

See also C<--min-servers>, C<--min-spare>, and C<--max-spare> options.


=item B<--min-servers> or B<-mns> I<<n>> C<new in v2.60>

Minimum number of child servers to start and maintain (where n > 0).

B<Note:> If this option is set, and it is less than C<--max-servers> option,
then the server runs in L</"Scalable Mode">. By default this option is undefined,
meaning I<spampd> runs only a set number of servers specified in C<--max-servers>.
In scalable mode, the number of actual running servers will fluctuate between C<--min-servers>
and C<--max-servers>, based on demand.

See also C<--max-servers>, C<--min-spare>, and C<--max-spare> options.


=item B<--min-spare> or B<-mnsp> I<<n>> C<new in v2.60>

The minimum number of servers to have waiting for requests.  Minimum
and maximum numbers should not be set to close to each other or the
server will fork and kill children too often. (I<- Copied from C<Net::Server::PreFork>>)

B<Note:> This option is only used when running in L</"Scalable Mode">. See C<--min-servers>
and C<--max-servers> options.


=item B<--max-spare> or B<-mxsp> I<<n>> C<new in v2.60>

The maximum number of servers to have waiting for requests. (I<- Copied from C<Net::Server::PreFork>>)

B<Note:> This option is only used when running in L</"Scalable Mode">. See C<--min-servers>
and C<--max-servers> options.


=item B<--maxrequests> or B<-mr> or B<-r> I<<n>>

I<spampd> works by forking child servers to handle each message. The
B<maxrequests> parameter specifies how many requests will be handled
before the child exits. Since a child never gives back memory, a large
message can cause it to become quite bloated; the only way to reclaim
the memory is for the child to exit.


=item B<--childtimeout> I<<n>>

This is the number of seconds to allow each child server before it times out
a transaction. In an S/LMTP transaction the timer is reset for every command.
This timeout includes time it would take to send the message data, so it should
not be too short.  Note that it's more likely the origination or destination
mail servers will timeout first, which is fine.  This is just a "sane" failsafe.


=item B<--satimeout> I<<n>>

This is the number of seconds to allow for processing a message with
SpamAssassin (including feeding it the message, analyzing it, and adding
the headers/report if necessary).

This should be less than your origination and destination servers' timeout
settings for the DATA command. (For Postfix this is set in C<(smtp|lmtp)_data_done_timeout>
and C<smtpd_timeout>). In the event of timeout while processing the message, the problem is
logged and the message is passed on anyway (w/out spam tagging, obviously).  To fail the
message with a temp 450 error, see the C<--dose> (die-on-sa-errors) option, below.


=item B<--child-name-template> or B<-cnt> I<[<template>]> C<new in v2.61>

Template for formatting child process name. Use a blank string (just the argument name
without a value) to leave the child process name unchanged (will be same as parent command line).

The template uses C<printf()> style formatting, but with named parameter placeholders.
For example (wrapped for clarity):

  %base_name: child #%child_count(%child_status)
  [req %req_count/%req_max, time lst/avg/ttl %(req_time_last).4f/%(req_time_avg).4f/%(req_time_ttl).4f,
  ham/spm %req_ham/%req_spam, rules v%sa_rls_ver)]'

Would produce something like:

  spampd: child #4(D) [req 8/30, time lst/avg/ttl 0.0222/0.0256/0.2045, ham/spm 3/5, rules v1891891]

Parameters are specified like: "Value of %(my_name)s is %(my_float_value).4f", with names
in parenthesis followed by a standard C<printf()> style formatting specifier (C<s> is default),
or simply as "Value of %my_name is %my_value" with the default format being a string
(works for numerics also). Keep in mind that any actual C<%> characters need to be escaped as C<%%>.
Formatting warnings will be logged as C<sprintf> errors (most likely a parameter was misspelled).

The following variables are available:

    base_name     # Base script name, eg. "spampd"
    spampd_ver    # SpamPD version, eg. "2.61"
    perl_ver      # Perl version, eg. "5.28.1"
    ns_ver        # Net::Server version, eg. "2.009"
    ns_typ        # Net::Server type, "PreFork" or "PreForkSimple"
    ns_typ_acr    # Net::Server type acronym, "PF" or "PFS"
    sa_ver        # SpamAassassin version, eg. "3.4.2"
    sa_rls_ver    # SpamAassassin rules update version, eg. "1891891" or "(unknown)"
    child_count   # total number of children launched so far (current child number)
    child_status  # child status, "C" for connected, or "D" for disconnected
    req_count     # number of requests child has processed so far
    req_max       # maximum child requests before exit
    req_time_last # [s] time to process the last message
    req_time_ttl  # [s] total processing time for this child
    req_time_avg  # [s] average processing time for this child (req_time_ttl / req_count)
    req_ham       # count of ham messages scored by child
    req_spam      # count of spam messages scored by child


=item B<--pid> or B<-p> I<<filename>>

Specifies a filename where I<spampd> will write its process ID so
that it is easy to kill it later. The directory that will contain this
file must be writable by the I<spampd> user.


=item B<--logfile> or B<-o> I<< (syslog|stderr|<filename>) >> C<new in v2.60>

Logging method to use. May be one or more of:

=over 5

=item *

C<syslog>: Use the system's syslogd (via Sys::Syslog). B<Default> setting.

=item *

C<stderr>: Direct all logging to stderr (if running in background mode
these may still end up in the default system log).

=item *

C<filename>: Use the specified file (the location must be accessible to the
user I<spampd> is running as). This can also be a device handle, eg: C</dev/tty0>
or even C</dev/null> to disable logging entirely.

=back

B<This option may be specified multiple times.> You may also specify multiple
destination by separating them with a C<:> (colon): C<--logfile stderr:/var/log/spampd.log>

Simultaneous logging to C<syslog>, C<stderr>, and one C<filename> is possible.
At this time only one log file can be used at a time (if several are specified
then the last one takes precedence).


=item B<--logsock> or B<-ls> I<<type>> C<new in v2.20>  C<updated in v2.60>

Syslog socket to use if C<--logfile> is set to I<syslog>.

C<Since v2.60:>

The I<type> can be any of the socket types or logging mechanisms as accepted by
the subroutine Sys::Syslog::setlogsock(). Depending on the version of Sys::Syslog and
the underlying operating system, one of the following values (or their subset) can
be used:

  native, tcp, udp, inet, unix, stream, pipe, console, eventlog (Win32 only)

The default behavior since I<spampd> v2.60 is to let I<Sys::Syslog> pick the default
syslog socket. This is the recommended usage for I<Sys::Syslog> (since v0.15), which chooses thusly:

  The default is to try native, tcp, udp, unix, pipe, stream, console. Under systems with the
  Win32 API, eventlog will be added as the first mechanism to try if Win32::EventLog is available.

For more information please consult the L<Sys::Syslog|https://metacpan.org/pod/Sys::Syslog> documentation.

To preserve backwards-compatibility, the default on HP-UX and SunOS (Solaris) systems is C<inet>.

C<Prior to v2.60:>

The default was C<unix> except on HP-UX and SunOS (Solaris) systems it is C<inet>.


=item B<--logident> or B<-li> I<<name>> C<new in v2.60>

Syslog identity name to use. This may also be used in log files written directly (w/out syslog).


=item B<--logfacility> or B<-lf> I<<name>> C<new in v2.60>

Syslog facility name to use. This is typically the name of the system-wide log file to be written to.


=item B<--[no]detach> I<[0|1]> C<new in v2.20>

Tells I<spampd> to detach from the console and fork into the background ("daemonize").
Using C<--nodetach> can be useful for running under control of some daemon management tools or testing from a command line.


=item B<--[no]setsid> I<[0|1]> C<new in v2.51>

If C<--setsid> is specified then I<spampd> will fork after the bind method to release
itself from the command line and then run the POSIX::setsid() command to truly
daemonize. Only used if C<--nodetach> isn't specified.


=item B<--maxsize> I<<n>>

The maximum message size to send to SpamAssassin, in KBytes. Messages
over this size are not scanned at all, and an appropriate message is logged
indicating this.  The size includes headers and attachments (if any).


=item B<--dose> I<[0|1]>

Acronym for (d)ie (o)n (s)pamAssassin (e)rrors. When disabled and I<spampd>
encounters a problem with processing the message through SpamAssassin (timeout
or other error), it will still pass the mail on to the destination server.
When enabled, the mail is instead rejected with a temporary error (code 450,
which means the origination server should keep retrying to send it). See the
related C<--satimeout> option, above.


=item B<--tagall> or B<-a> I<[0|1]>

Tells I<spampd> to have SpamAssassin add headers to all scanned mail,
not just spam.  Otherwise I<spampd> will only rewrite messages which
exceed the spam threshold score (as defined in the SA settings).  Note that
for this option to work as of SA-2.50, the I<always_add_report> and/or
I<always_add_headers> settings in your SpamAssassin F<local.cf> need to be
set to 1/true.


=item B<--log-rules-hit> or B<-rh> I<[0|1]>

Logs the names of each SpamAssassin rule which matched the message being
processed.  This list is returned by SA.


=item B<--set-envelope-headers> or B<-seh> I<[0|1]> C<new in v2.30>

Turns on addition of X-Envelope-To and X-Envelope-From headers to the mail
being scanned before it is passed to SpamAssassin. The idea is to help SA
process any blacklist/whitelist to/from directives on the actual
sender/recipients instead of the possibly bogus envelope headers. This
potentially exposes the list of all recipients of that mail (even BCC'd ones).
Therefore usage of this option is discouraged.

I<NOTE>: Even though I<spampd> tries to prevent this leakage by removing the
X-Envelope-To header after scanning, SpamAssassin itself might add headers
that report recipient(s) listed in X-Envelope-To.


=item B<--set-envelope-from> or B<-sef> I<[0|1]> C<new in v2.30>

Same as above option but only enables the addition of X-Envelope-From header.
For those that don't feel comfortable with the possible information exposure
of X-Envelope-To.  The above option overrides this one.


=item B<--local-only> or B<-L> I<[0|1]>

Turn off all SA network-based tests (DNS, Razor, etc).


=item B<--homedir> I<<directory>> C<new in v2.40>

Use the specified directory as home directory for the spamassassin process.
Things like the auto-whitelist and other plugin (razor/pyzor) files get
written to here. A good place for this is in the same
place your C<bayes_path> SA config setting points to (if any).  Make sure this
directory is accessible to the user that spampd is running as.

Thanks to Alexander Wirt for this fix.


=item B<--saconfig> I<<filename>>

Use the specified file for SpamAssassin configuration options in addition to the
default local.cf file.  Any options specified here will override the same
option from local.cf.


=item B<--debug> or B<-d> I<< [<area,...>|1|0] >> C<(updated in v2.60)>

Turns on SpamAssassin debug messages which print to the system mail log
(same log as spampd will log to).  Also turns on more verbose logging of
what spampd is doing (new in v2).  Also increases log level of Net::Server
to 4 (debug), adding yet more info (but not too much) (new in v2.2).

C<New in v2.60:>

Setting the value to 1 (one) is the same as using no parameter (eg. simply I<-d>).
The value of 0 (zero) disables debug logging.

The I<area> list is passed on directly to SpamAssassin and controls logging
facilities. If no I<area>s are listed (and debug logging is enabled), all
debugging information is printed (this equivalent to passing C<all> as the I<area>).
Diagnostic output can also be enabled for each area individually;
I<area> is the area of the code to instrument. For example, to produce
diagnostic output on bayes, learn, and dns, use:

    -d bayes,learn,dns

You can also disable specific areas with the "no" prefix:

    -d all,norules,nobayes

To show only I<spampd> debug messages (none from SpamAssassin), use:

    -d spampd

For more information about which I<areas> (aka I<channels> or I<facilities>) are available,
please see the documentation at:

L<SpamAssassin Wiki::DebugChannels|http://wiki.apache.org/spamassassin/DebugChannels>

L<Mail::SpamAssassin::Logger::add_facilities()|https://spamassassin.apache.org/doc/Mail_SpamAssassin_Logger.html#METHODS>


=item B<--show> I<<thing>>[,I<<thing>>[,...]] C<new in v2.60>

Meant primarily for debugging configuration settings (or code), this will print some information
to the console and then exit.

I<<thing>> may be one or more of:

=over 4

=item *

C<defaults>: Show default values for all options, in a format suitable for a config file.

=item *

C<config>: Shows option values after processing all given command-line arguments, including
anything loaded from config file(s).

=item *

C<start>: Shows the final configuration arguments after processing any config file(s).

=item *

C<version>: Same as C<--version> switch but runs after parsing all options and shows actual I<Net::Server> type
which would be used (I<PreFork> or I<PreForkSimple>).

=item *

C<argv>: Shows anything remaining on command line (@ARGV) after processing all known arguments
(this will be passed onto Net::Server).

=item *

C<self>: Dumps the whole SpamPD object, including all settings. Trés geek.

=item *

C<all>: Prints all of the above.

=back

Multiple C<thing>s may be specified by using the I<--show> option multiple times, or
separating the items with a comma: C<--show config,start,argv>.

Note that all I<thing> options besides C<defaults> and C<config> require the Perl module I<Data::Dumper> installed.


=item B<--version> C<new in v2.52>

Prints version information about SpamPD, Net::Server, SpamAssassin, and Perl.


=item B<--help> or B<-h> or B<-?> I<[txt]>

=item B<--hh> or B<-??> I<[txt]>

=item B<--hhh> or B<-???> I<[txt]>

=item B<--man> or B<-hhhh> or B<-????> I<[html|txt]>

Prints increasingly verbose usage information. By default help is displayed in
"terminal" (groff) format with some text styling applied. If you want to use
C<less> as a pager, provide it with the C<-R> switch, eg.:

  spampd --??? | less -R

Alternatively you can request plain-text format with the optional C<txt> value.

C<--man> displays the full documentation, optionally in C<html> or plain text
C<txt> formats (default is to use actual "man" format/display). HTML version is
saved to a temp file and an attempt is made to open it in the default system browser
(it is better if the browser is already opened). If available, the optional Perl
module I<HTML::Display> is used to (try to) open a browser.

=back

=head2 Other Net::Server Options

I<Net::Server> supports some other options which I<spampd> doesn't accept directly.
For example there are access control options, child process tuning, and a few more (see below).
Such options can be passed through to I<Net::Server> (and subtypes) by specifying them at the end
of the I<spampd> command line (or in a configuration file) following two dashes
C< -- > by themselves (this is a failry typicaly convention for passing options onto
another program). As an example, it may look something like this:

  spampd --host 10.0.0.1 -port 10025 -- --cidr_allow 10.0.0.0/24

The C<--cidr_allow> after the C< -- > is passed onto I<Net::Server>. If the C< -- > were
not there, you would get an error from I<spampd> about an unknown option.

To specify I<Net::Server> options in a configuration file, place them after two
dashes (C<-->) on a line by themselves. See L</"CONFIGURATION FILE"> for an example.

This only makes sense with the few options not directly controlled by/through I<spampd>.
As of I<Net::Server> v2.009 the list is:

  reverse_lookups, allow, deny, cidr_allow, cidr_deny, chroot, ipv, conf_file,
  serialize, lock_file, check_for_dead, max_dequeue, check_for_dequeue

If running in L</"Scalable Mode"> then these settings from I<Net::Server::PreFork> can also be very relevant to performance tuning:

  check_for_waiting, check_for_spawn, min_child_ttl

Keep in mind that the I<Net::Server> types inherit from each other: C<PreFork> inherits from C<PreForkSimple>
which inherits from C<Net::Server> itself. Which means all the options are also inherited.

See the L<Net::Server(3)|https://https://metacpan.org/pod/Net::Server#DEFAULT-ARGUMENTS-FOR-Net::Server>,
L<Net::Server::PreForkSimple(3)|https://metacpan.org/pod/Net::Server::PreForkSimple#COMMAND-LINE-ARGUMENTS>,
and L<Net::Server::PreFork(3)|https://metacpan.org/pod/Net::Server::PreFork#COMMAND-LINE-ARGUMENTS>
documentation for details.


=head2 Deprecated Options

The following options are no longer used but still accepted for backwards
compatibility with prevoius I<spampd> versions:

=over 5

=item  B<--dead-letters>

=item  B<--heloname>

=item  B<--stop-at-threshold>

=item  B<--add-sc-header>

=item  B<--hostname>

=item B<--auto-whitelist> or B<-aw> C<deprecated with SpamAssassin v3+>

This option is no longer relevant with SA version 3.0 and above, which
controls auto whitelist use via config file settings. Do not use it unless
you must use an older SA version. An error will be generated if attempting
to use this option with SA 3.0 or above.

For SA version < 3.0, turns on the SpamAssassin global whitelist feature.
See the SA docs. Note that per-user whitelists are not available.

B<NOTE>: B<DBBasedAddrList> is used as the storage mechanism. If you wish to use
a different mechanism (such as SQLBasedAddrList), the I<spampd> code will
need to be modified in 2 instances (search the source for DBBasedAddrList).

=back


=head1 CONFIGURATION FILE

Since v2.60 I<spampd> allows for the use of a configuration file to load server parameters.
One or more files can be specified on the command line (see C<--config> option for more details on syntax).
The format of a configuration file is simple key/value pairs. Comments (starting with # or ;)
and blank lines are ignored. The option names are exactly as they appear above in the L</"OPTIONS"> section.
They can be listed with or w/out the "-"/"--" prefixes.
Key/value separator can be one or more of space, tab, or "=" (equal) sign.

Multiple configuration files can be loaded, with the latter ones being able to override options
loaded earlier. Any options specified on the command line will take precedence over options from
file(s). Configuration file(s) are reloaded during a HUP-induced restart (see L</"SIGNALS">),
making it possible to adjust settings dynamically on a running server.

You may also provide "B<passthrough>" options directly to I<Net::Server> by putting them after a "--" on a
line by itself (this is just like using the lonesome "--" on a command line; see L</"Other Net::Server Options">).

Note that one cannot use the C<--config> option to load a file from within
another file. B<A config file can only be specified on the command line.>

Use the C<< spampd --show defaults > spampd.config >> command to generate a sample
configuration file showing all default values. The example below demonstrates various
valid syntax for the file.

  # Sample configuration file for SpamPD.

  # Double dashes
  --user    spampd

  # Single dash and = separator with spaces
  -pid = /var/run/spampd/spampd.pid

  # No dashes required, equals separator no spaces
  homedir=/var/cache/spampd

  # No dashes, space separator
  host  127.0.0.1

  # Disabled option (after comment character)
  #port  10025

  # Boolean values can be set/unset a number of ways:
  tagall      1
  local-only  0
  set-envelope-from
  no-log-rules-hit

  # Passthrough arguments for Net::Server[::PreFork[Simple]] could go here.
  # Be sure to also uncomment the "--" if using any.
  # --
  # cidr_allow      127.0.0.1/32


=head1 SIGNALS

=over 5

=item HUP  C<updated in v2.60>

Sending HUP signal to the master process will restart all the children gracefully (meaning the currently
running requests will shut down once the request is complete).

C<Since v2.60>:

SpamAssassin configuration IS reloaded on HUP. Any children currently in the middle of a transaction will
finish with the previous SA config and then exit. A new set of children, using the new config, is spawned
immediately upon HUP and will serve any new requests.

In a similar manner, I<spampd> will also reload its own settings from any configuration file(s)
specified on the original command line with C<--config> option (see L</"OPTIONS"> and L</"CONFIGURATION FILE">).

C<Since v2.52>: Children were restarted but SpamAssassin configuration was not reloaded.

C<Prior to v2.52>: HUP would try to restart the server with all default settings (usually failing).

=item TTIN, TTOU

Sending TTIN signal to the master process will dynamically increase
the number of children by one, and TTOU signal will decrease it by one.

=item INT, TERM

Sending INT or TERM signal to the master process will kill all the
children immediately and shut down the daemon.

=item QUIT

Sending QUIT signal to the master process will perform a graceful shutdown,
waiting for all children to finish processing any current transactions and
then shutting down the parent process.

=back


=head1 EXAMPLES

=over 5

=item Running between firewall/gateway and internal mail server:

I<spampd> listens on port 10025 on the same host as the internal mail server.

  spampd --host=192.168.1.10

Same as above but I<spampd> runs on port 10025 of the same host as
the firewall/gateway and passes messages on to the internal mail server
on another host.

  spampd --relayhost=192.168.1.10

=item Using Postfix advanced content filtering example
and disable SA network checks:

  spampd --port=10025 --relayhost=127.0.0.1:10026 --local-only

=item Using UNIX sockets instead if INET ports:

I<spampd> listens on the UNIX socket C</var/run/spampd.socket> with
persmissions 700 instead of a TCP port:

  spampd --socket /var/run/spampd.socket --socket-perms 700

I<spampd> will relay mail to C</var/run/dovecot/lmtp> instead of a TCP port:

  spampd --relaysocket /var/run/dovecot/lmtp

Remember that the user I<spampd> runs as needs to have read AND write
permissions on the relaysocket!

=back


=head1 CREDITS

I<spampd> is written and maintained by Maxim Paperno <MPaperno@WorldDesign.com>.
The open source code repository is located at L<https://github.com/mpaperno/spampd/>.
See L<http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm> for historical info.

I<spampd> v2 uses two Perl modules (I<MSDW::SMTP::Client> and I<MSDW::SMTP::Server>)
by Bennett Todd and Copyright (C) 2001 Morgan Stanley Dean Witter.
These are distributed under the GNU GPL (see module code for more details).
Both modules have been slightly modified from the originals and are included in
this file under new names (I<SpamPD::Client> and I<SpamPD::Server>, respectively).

Also thanks to Bennett Todd for the example I<smtpproxy> script which helped create
this version of I<spampd>.  See L<http://bent.latency.net/smtpprox/> (seems to be down)
or L<https://github.com/jnorell/smtpprox>.

I<spampd> v1 was based on code by Dave Carrigan named I<assassind>. Trace
amounts of his code or documentation may still remain. Thanks to him for the
original inspiration and code. L<https://openshut.net/>.

Also thanks to I<spamd> (included with SpamAssassin) and
I<amavisd-new> (L<http://www.ijs.si/software/amavisd/>) for some tricks.

Various people have contributed patches, bug reports, and ideas, all of whom
I would like to thank.  I have tried to include credits in code comments and
in the change log, as appropriate.

=head2 Code Contributors (in order of appearance):

 Kurt Andersen
 Roland Koeckel
 Urban Petry
 Sven Mueller

See also: L<https://github.com/mpaperno/spampd/graphs/contributors/>


=head1 COPYRIGHT, LICENSE, AND DISCLAIMER

I<spampd> is Copyright (c) Maxim Paperno;  All Rights Reserved.

Portions are Copyright (c) 2001 Morgan Stanley Dean Witter as mentioned above
in the Credits section.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.


You should have received a copy of the GNU General Public License
along with this program.  If not, see L<https://www.gnu.org/licenses/>.


=head1 BUGS

Use GitHub issue tracking: L<https://github.com/mpaperno/spampd/issues>


=head1 SEE ALSO

L<spamassassin(1)>

L<Mail::SpamAssassin(3)|https://spamassassin.apache.org/doc/Mail_SpamAssassin.html>

L<Net::Server(3)|https://metacpan.org/pod/Net::Server>

L<SpamAssassin Site|http://www.spamassassin.org/>

L<SpamPD Code Repository|https://github.com/mpaperno/spampd>

L<SpamPD product page|http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm>

L<Integrating SpamAssassin into Postfix using spampd|https://wiki.apache.org/spamassassin/IntegratePostfixViaSpampd>


=begin html

<!-- HTML formatter customizations -->

<style>
  /* change color of internal links */
  a[href^="#"] {
    color: green;
    text-decoration: none;
  }
  /* In the styles below, the first selector is for Pod::HTML (pod2html), other(s) for Pod::Simple::HTML (perldoc -o html) */
  /* remove ugly underlines and color on headings with backlinks */
  a[href*="podtop"],
  a.u {
    color: unset !important;
    text-decoration: none;
  }
  /* set up to display "back to top" links on headings with backlinks */
  a[href*="podtop"] h1,
  a.u {
    position: relative;
    display: block;
  }
  /* place "back to top" links in pseudo ::after elements (except the first n heading(s) */
  a[href*="podtop"]:not(:nth-of-type(-n+3)) h1::after,
  h1:not(:nth-of-type(-n+3)) a.u::after,
  h2 a.u::after {
    content: "[back to top]";
    font-size: small;
    text-decoration: underline;
    color: green;
    display: inline-block;
    position: absolute;
    bottom: 0px;
    right: 20px;
  }
</style>
<script>
  // Transform each level 1 heading and index entry to Title Case on document load.
  window.onload = function() {
    var prepsRx = RegExp("^(?:the|and?|or|of|by|in)$", "i");
    var titleCase = function(str) {
      return str.toLowerCase().split(' ').map(function(word, idx) {
        if (idx && prepsRx.test(word)) return word;
        return word.replace(word[0], word[0].toUpperCase());
      }).join(' ');
    };
    var list = document.querySelectorAll("a[href*=podtop] h1, ul#index > li > a, h1 a.u, body > h1[id], li.indexItem1 > a");
    for (let item of list)
      item.innerText = titleCase(item.innerText);
  }
</script>

=end html

=cut
