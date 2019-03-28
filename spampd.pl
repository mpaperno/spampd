#!/usr/bin/perl -T

######################
# SpamPD - spam proxy daemon
#
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
# spampd is Copyright (c) 2002-2006, 2009-2010, 2013, 2018-2019 Maxim Paperno; All Rights Reserved.
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
# acknowlege each command or request. Since acknowlegement or failure
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
# acknowlegement must be made. If chat returns true, then its return
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
# the only protocol-specific knowlege it has is the structure of SMTP
# multiline responses. All specifics lie in the hands of the calling
# program; this makes it appropriate for a semi-transparent SMTP
# proxy, passing commands between a talker and a listener.
#
# =cut

use strict;
use warnings;

# =item new([interface => $interface, port => $port] | [unix_socket => $unix_socket] [, timeout = 300]);
#
# The interface and port, OR a unix socket to talk to must be specified. If
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
use version;
use Getopt::Long qw(GetOptions);
use Time::HiRes qw(time);
use Mail::SpamAssassin ();

our $VERSION = '2.60';

# Global flag, if true prevents automatic execution of script.
our $LoadAsModule;

BEGIN {
  require Net::Server; Net::Server->VERSION(0.89);
  require Net::Server::PreForkSimple;
  our @ISA = qw(Net::Server::PreForkSimple);

  # use included modules
  import SpamPD::Server;
  import SpamPD::Client;
}

use constant {
  # Logging type constants: low byte for destination(s), high byte for logger type.
  LOG_NONE => 0, LOG_SYSLOG => 0x01, LOG_FILE => 0x02, LOG_STDERR => 0x04,
  LOGGER_DEFAULT => 0, LOGGER_SA => 0x0100, LOGGER_L4P => 0x0200,
  # Map Net::Server logging levels to SpamAssassin::Logger level names.
  SA_LOG_LEVELS => {0 => 'error', 1 => 'warn', 2 => 'notice', 3 => 'info', 4 => 'dbg'},
};

##################   RUN   ######################

unless ($LoadAsModule) {
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
      max_servers       => 5,                     # number of child processes (servers) to spawn at start
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
      logtype           => LOG_SYSLOG,            # logging destination and logger type (--logfile option)
      instance          => 0,                     # child instance count
      sa_version        => version->parse(Mail::SpamAssassin->VERSION)  # may be used while processing messages
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
    }
  }, $class;
}

##################   INIT   ######################

sub init {
  my $self = shift;
  my ($spd_p, $sa_p) = ($self->{spampd}, $self->{assassin});
  my $is_reloading = !!$ENV{'BOUND_SOCKETS'};

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

  # SA v3.1.0 changed debug logging to be more granular and introduced Logger module which we can use.
  my $use_logger = eval {
    require Mail::SpamAssassin::Logger;
    LOGGER_SA;
  } or LOGGER_DEFAULT;

  # We actually call Getopt::Long::GetOptions three (!) times. First time is to check for presence of config file option(s).
  # If we get any, then we parse the file(s) into @ARGV, in front of any existing @ARGV options (so command-line overrides).
  $self->handle_cfg_file_opts();

  # Run GetOptions a 2nd time to check for help/usage/version/debug requests, but don't bother if we're HUPping. We may not return from here.
  $self->handle_help_opts() if !$is_reloading;

  # Handle "--show defaults" debugging request here (while we still know them).
  if ($spd_p->{show_dbg} && grep(/^(defaults?|all)$/i, @{$spd_p->{show_dbg}})) {
    # make sure we don't "show defaults" again
    @{$spd_p->{show_dbg}} = grep {$_ !~ /^defaults?$/i} @{$spd_p->{show_dbg}};
    # show defaults and exit here if that's all the user wanted to see
    print_options({$self->options_map()}, 'default', (@{$spd_p->{show_dbg}} ? -1 : 0));
  }

  # save final ARGV for debug (handle_main_opts() will clear @ARGV)
  my @startup_args = @ARGV;

  # Now (finally) process all the actual options passed on @ARGV (including anything from config files).
  # Options on the actual command line will override anything loaded from the file(s).
  $self->handle_main_opts($use_logger, $is_reloading);

  # If debug output requested, do it now, before logging is set up, and exit.
  show_debug($spd_p->{show_dbg}, {$self->options_map()}, \@startup_args, \%$self) && exit(0) if $spd_p->{show_dbg};

  # Configure logging.
  $self->setup_logging();

  $self->dbg(__PACKAGE__." v$VERSION ". ($is_reloading ? "reloading": "starting") ." with: @startup_args \n");

  # Redirect all warnings to logger
  $SIG{__WARN__} = sub { $self->log(1, $_[0]); };

  # Create and set up SpamAssassin object. This replaces our SpamPD->{assassin} property with the actual object instance.
  $sa_p = Mail::SpamAssassin->new($sa_p);

  $self->{spampd}->{sa_awl} and eval {
    require Mail::SpamAssassin::DBBasedAddrList;
    # create a factory for the persistent address list
    $sa_p->set_persistent_address_list_factory(Mail::SpamAssassin::DBBasedAddrList->new());
  };

  $sa_p->compile_now(!!$sa_p->{userprefs_filename});

  return $self;
}

sub handle_cfg_file_opts {
  my $self = shift;
  my @config_files;
  # Configure Getopt::Long to pass through any unknown options.
  Getopt::Long::Configure(qw(ignore_case no_permute no_auto_abbrev no_require_order pass_through));
  # Check for config file option(s) only.
  GetOptions('conf|config|cfg|conf-file|config-file|cfg-file=s' => \@config_files);
  # Handle config files. Note that options on the actual command line will override anything loaded from the file(s).
  if (@config_files) {
    # files could be passed as a list separated by ":"
    trimmed(@config_files = split(/:/, join(':', @config_files)));
    $self->log(2, "Loading config from file(s): @config_files \n");
    read_args_from_file(\@config_files, \@ARGV);
  }
}

sub handle_help_opts {
  my $self = shift;
  my $spd_p = $self->{spampd};
  # Configure Getopt::Long to pass through any unknown options.
  Getopt::Long::Configure(qw(ignore_case no_permute no_auto_abbrev no_require_order pass_through));
  # Check for help/version/show option(s) only. These all cause an exit(0), except --show which is processed later.
  GetOptions(
    'show=s@'         => \$spd_p->{show_dbg},
    'help|h|?:s'      => sub { usage(0, 1, $_[1]); },
    'hh|??:s'         => sub { usage(0, 2, $_[1]); },
    'hhh|???:s'       => sub { usage(0, 3, $_[1]); },
    'hhhh|????|man:s' => sub { usage(0, 4, $_[1]); },
    'version'         => \&version,
  );
  # "--show" could be a CSV list
  trimmed(@{$spd_p->{show_dbg}} = split(/,/, join(',', @{$spd_p->{show_dbg}}))) if defined($spd_p->{show_dbg});
}

# Main command-line options mapping; this is for Getopt::Long::GetOptions and also to generate config dumps.
sub options_map {
  my ($self) = @_;
  my ($srv_p, $spd_p, $sa_p) = ($self->{server}, $self->{spampd}, $self->{assassin});
  $spd_p->{logspec} = logtype2file($spd_p->{logtype}, $srv_p->{log_file}, ':'); # set a valid default for print_options()

  # To support setting boolean options with "--opt", "--opt=1|0", as well as the "no-" prefix,
  #   we make them accept an optional integer and add the "no" variants manually. Because Getopt::Long doesn't support that :(
  return (
    # Net::Server
    'host=s'                   => \$srv_p->{host},
    'port=i'                   => \$srv_p->{port},
    'children|c=i'             => \$srv_p->{max_servers},
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
    # SA
    'debug|d:s'                => \$sa_p->{debug},
    'saconfig=s'               => \$sa_p->{userprefs_filename},
    'homedir=s'                => \$sa_p->{userstate_dir},
    'local-only|l:1'           => \$sa_p->{local_tests_only},
    'no-local-only|no-l'       => sub { $sa_p->{local_tests_only} = 0; },
    # others
    'dead-letters=s'           => \&deprecated_opt,
    'heloname=s'               => \&deprecated_opt,
    'stop-at-threshold'        => \&deprecated_opt,
    'add-sc-header|ash'        => \&deprecated_opt,
    'hostname=s'               => \&deprecated_opt,
  );
}

sub handle_main_opts {
  my ($self, $use_logger, $is_reloading) = @_;
  my ($srv_p, $spd_p, $sa_p) = ($self->{server}, $self->{spampd}, $self->{assassin});

  # Reconfigure GoL for stricter parsing and check for all other options on ARGV, including anything parsed from config file(s).
  Getopt::Long::Configure(qw(ignore_case no_permute no_bundling auto_abbrev require_order no_pass_through));
  GetOptions($self->options_map()) or ($is_reloading ? $self->fatal("Could not parse command line!\n") : usage(1));

  # Validation

  if ($srv_p->{max_servers} < 1)
    { die "Option --children must be greater than zero!\n"; }

  if ($self->{spampd}->{sa_awl} && $spd_p->{sa_version} >= 3)
    { die "Option --auto-whitelist is deprecated with SpamAssassin v3.0+. Use SA configuration file instead.\n"; }

  # validate syslog socket option
  if ($spd_p->{logtype} & LOG_SYSLOG) {
    # in theory this check could be made more adaptive based on OS or something...
    my $allowed_syslog_socks = 'native|eventlog|tcp|udp|inet|unix|stream|pipe|console';
    if ($srv_p->{syslog_logsock} && $srv_p->{syslog_logsock} !~ /^($allowed_syslog_socks)$/) {
      die "--logsock parameter not recognized, must be one of ($allowed_syslog_socks).\n";
    }
    elsif (!$srv_p->{syslog_logsock} && $use_logger != LOGGER_SA) {
      # log socket default for HP-UX and SunOS (thanks to Kurt Andersen for the 'uname -s' fix)
      # note that SA::Logger has own fallback for cases where the default syslog selection fails.
      eval {
        my $osname = `uname -s`;
        $srv_p->{syslog_logsock} = "inet" if ($osname =~ 'HP-UX' || $osname =~ 'SunOS');
      };
    }
  }

  # Validate that required modules for relay server exist (better now than later).
  if ($spd_p->{relaysocket}) {
    eval { require IO::Socket::UNIX; }
    or die "Error loading IO::Socket::UNIX module, required for --relaysocket option.\n\t$@ \n";
  }
  else {
    eval { require IO::Socket::IP; }
    or die "Error loading IO::IP::UNIX module, required for --relayhost option.\n\t$@ \n";
  }

  # These paths are already untainted but do a more careful check JIC.
  for ($spd_p->{socket}, $spd_p->{relaysocket}, $srv_p->{pid_file}, $sa_p->{userprefs_filename})
    { $_ = untaint_path($_); }

  # /Validation

  # set up logging specs based on options ($logspec is only an array if --logfile option(s) existed)
  if (ref($spd_p->{logspec}) eq 'ARRAY') {
    # Handle ":" record separator and trim values.
    trimmed(@{$spd_p->{logspec}} = split(/:/, join(':', @{$spd_p->{logspec}})));
    $spd_p->{logtype} = LOG_NONE;  # reset
    for (@{$spd_p->{logspec}}) {
      if ($_ eq 'syslog') {
        $spd_p->{logtype} |= LOG_SYSLOG;
      }
      elsif ($_ eq 'stderr') {
        $spd_p->{logtype} |= LOG_STDERR;
      }
      elsif ($_ = untaint_path($_)) {
        $spd_p->{logtype} |= LOG_FILE;
        $srv_p->{log_file} = $_;
      }
    }
  }
  # be sure to add the logger type
  $spd_p->{logtype} |= $use_logger;

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

  # Configure debugging
  if ($sa_p->{debug} ne '0') {
    $srv_p->{log_level} = 4;  # set Net::Server log level to debug
    # SA since v3.1.0 can do granular debug logging based "channels" which can be passed to us via --debug option parameters.
    # --debug can also be specified w/out any parameters, in which case we enable the "all" channel.
    # In case of old SA version, just set the debug flag to true.
    if ($use_logger == LOGGER_SA) {
      my ($ident, $debug) = ($srv_p->{syslog_ident}, \$sa_p->{debug});
      ${$debug} = 'all' if (!${$debug} || ${$debug} eq '1');
      ${$debug} .= ','.$ident if (${$debug} !~ /(?:all|(?:\A|,)$ident)/i);
    }
    else {
      $sa_p->{debug} = 1;
    }
  }

  # Set misc. options based on other options.
  $srv_p->{setsid}= 0 if !$srv_p->{background};
  $sa_p->{home_dir_for_helpers} = $sa_p->{userstate_dir};
  $sa_p->{username} = $srv_p->{user};

}

sub setup_logging {
  my $self = shift;
  my ($srv_p, $spd_p, $sa_p) = ($self->{server}, $self->{spampd}, $self->{assassin});

  if ($spd_p->{logtype} & LOGGER_SA) {
    # Stderr logger method is active by default, remove it unless we're using it.
    unless ($spd_p->{logtype} & LOG_STDERR) {
      Mail::SpamAssassin::Logger::remove('stderr');
    }
    # Add syslog method?
    if ($spd_p->{logtype} & LOG_SYSLOG) {
      Mail::SpamAssassin::Logger::add(
        method => 'syslog',
        socket => $srv_p->{syslog_logsock},
        facility => $srv_p->{syslog_facility},
        ident => $srv_p->{syslog_ident}
      );
    }
    # Add file method?
    if ($spd_p->{logtype} & LOG_FILE) {
      Mail::SpamAssassin::Logger::add(method => 'file', filename => $srv_p->{log_file});
      push(@{$srv_p->{chown_files}}, $srv_p->{log_file});  # make sure we own the file
    }
    # Add SA logging facilities
    Mail::SpamAssassin::Logger::add_facilities($sa_p->{debug});
    $sa_p->{debug} = undef;   # clear this otherwise SA will re-add the facilities in new()
    $srv_p->{log_file} = undef;  # disable Net::Server logging (use our write_to_log_hook() instead)
  }
  # using Net::Server default logging
  else {
    if ($spd_p->{logtype} & LOG_SYSLOG) {
      $srv_p->{log_file} = 'Sys::Syslog';
    }
    elsif ($spd_p->{logtype} & LOG_STDERR) {
      $srv_p->{log_file} = undef;  # tells Net::Server to log to stderr
    }
  }
}


##################   SERVER METHODS   ######################

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
    $self->log(2, "skipped large message (" . $size / 1024 . "KB)");
    return 1;
  }

  my (@msglines, $msgid, $sender, $recips, $tmp, $mail, $msg_resp);
  my $inhdr      = 1;
  my $envfrom    = 0;
  my $envto      = 0;
  my $addedenvto = 0;

  $recips = "@{$self->{smtp_server}->{to}}";
  if ("$self->{smtp_server}->{from}" =~ /(\<.*?\>)/) { $sender = $1; }
  $recips ||= "(unknown)";
  $sender ||= "(unknown)";

  ## read message into array of lines to feed to SA

  # loop over message file content
  $fh->seek(0, 0) or die "Can't rewind message file: $!";
  while (<$fh>) {
    $envto   = 1 if (/^(?:X-)?Envelope-To: /);
    $envfrom = 1 if (/^(?:X-)?Envelope-From: /);
    if (/^\r?\n$/ && $inhdr) {
      $inhdr = 0;  # outside of msg header after first blank line
      if (($prop->{envelopeheaders} || $prop->{setenvelopefrom}) && !$envfrom) {
        unshift(@msglines, "X-Envelope-From: $sender\r\n");
        $self->dbg("Added X-Envelope-From") ;
      }
      if ($prop->{envelopeheaders} && !$envto) {
        unshift(@msglines, "X-Envelope-To: $recips\r\n");
        $addedenvto = 1;
        $self->dbg("Added X-Envelope-To");
      }
    }
    push(@msglines, $_);

    # find the Message-ID for logging (code is mostly from spamd)
    if ($inhdr && /^Message-Id:\s+(.*?)\s*$/i) {
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

  $msgid ||= "(unknown)";

  $self->log(2, "processing message $msgid for " . $recips);

  eval {

    local $SIG{ALRM} = sub { die "Timed out!\n" };

    # save previous timer and start new
    my $previous_alarm = alarm($prop->{satimeout});

    # Audit the message
    if ($prop->{sa_version} >= 3) {
      $mail = $assassin->parse(\@msglines, 0);
      undef @msglines;  #clear some memory-- this screws up SA < v3
    }
    elsif ($prop->{sa_version} >= 2.70) {
      $mail = Mail::SpamAssassin::MsgParser->parse(\@msglines);
    }
    else {
      $mail = Mail::SpamAssassin::NoMailAudit->new(data => \@msglines);
    }

    # Check spamminess (returns Mail::SpamAssassin:PerMsgStatus object)
    my $status = $assassin->check($mail);

    $self->dbg("Returned from checking by SpamAssassin");

    #  Rewrite mail if high spam factor or options --tagall
    if ($status->is_spam || $prop->{tagall}) {

      $self->dbg("Rewriting mail using SpamAssassin");

      # use Mail::SpamAssassin:PerMsgStatus object to rewrite message
      if ($prop->{sa_version} >= 3) {
        $msg_resp = $status->rewrite_mail;
      }
      else {
        # SA versions prior to 3 need to get the response in a different manner
        $status->rewrite_mail;
        $msg_resp = join '', $mail->header, "\r\n", @{$mail->body};
      }

      # Build the new message to relay.
      # Pause the timeout alarm while we do this (no point in timing
      # out here and leaving a half-written file).
      my @resplines   = split(/\r?\n/, $msg_resp);
      my $arraycont   = @resplines;
      my $pause_alarm = alarm(0);
      my $skipline    = 0;
      $inhdr = 1;
      $fh->seek(0, 0) or die "Can't rewind message file: $!";
      $fh->truncate(0) or die "Can't truncate message file: $!";

      for (0 .. ($arraycont - 1)) {
        $inhdr = 0 if ($resplines[$_] =~ m/^\r?\n$/);

        # if we are still in the header, skip over any
        # "X-Envelope-To: " line if we have previously added it.
        if ($inhdr && $addedenvto && $resplines[$_] =~ m/^X-Envelope-To: .*$/) {
          $skipline = 1;
          $self->dbg("Removing X-Envelope-To");
        }

        if (!$skipline) {
          $fh->print($resplines[$_] . "\r\n")
            or die "Can't print to message file: $!";
        }
        else {
          $skipline = 0;
        }
      }
      #restart the alarm
      alarm($pause_alarm);
    }  # end rewrite mail

    # Log what we did
    my $was_it_spam = 'clean message';
    if ($status->is_spam) { $was_it_spam = 'identified spam'; }
    my $msg_score     = sprintf("%.2f", $status->get_hits);
    my $msg_threshold = sprintf("%.2f", $status->get_required_hits);
    my $proc_time     = sprintf("%.2f", time - $start);

    $self->log(2, "$was_it_spam $msgid ($msg_score/$msg_threshold) from $sender for " .
                    "$recips in " . $proc_time . "s, $size bytes.");

    # thanks to Kurt Andersen for this idea
    $self->log(2, "rules hit for $msgid: " . $status->get_names_of_tests_hit) if ($prop->{rh});

    $status->finish();
    $mail->finish();

    # set the timeout alarm back to wherever it was at
    alarm($previous_alarm);

  };  # end eval block

  if ($@ ne '') {
    $self->log(1, "WARNING!! SpamAssassin error on message $msgid: $@");
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
          or $self->log(1, "WARNING!! Couldn't close smtp_server->{data} temp file: $!");

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
        if ($smtp_server->{state} =~ /^rset/i) { $rcpt_ok = 0; }
        if ($smtp_server->{state} =~ /^mail/i) { $rcpt_ok = 0; }
        if ($smtp_server->{state} =~ /^rcpt/i and $destresp =~ /^25/) { $rcpt_ok++; }
        if ($smtp_server->{state} eq '.') {
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
    $self->log(0, "WARNING!! Error in process_request eval block: $@");
    $self->{server}->{done} = 1;  # exit this child gracefully
  }

  $prop->{instance}++;
}

# Net::Server hook
# After binding listening sockets
sub post_bind_hook {
  my $prop = $_[0]->{spampd};
  if (defined($prop->{socket}) and defined($prop->{socket_mode})) {
    chmod(oct($prop->{socket_mode}), $prop->{socket})
      or die $_[0]->fatal("Couldn't chmod '$prop->{socket}' [$!]\n");
  }
}

# Net::Server hook: new child starting
sub child_init_hook {
  # set process name to help clarify via process listing which is child/parent
  $0 = 'spampd child';
}

# Net::Server hook
# about to exit child process
sub child_finish_hook {
  $_[0]->dbg("Exiting child process after handling " . $_[0]->{spampd}->{instance} . " requests");
}

# Net::Server hook
# Only called when we're using SA Logger and bypassing Net::Server logging entirely.
sub write_to_log_hook {
  my ($self, $level, $msg) = @_;
  if (!($self->{spampd}->{logtype} & LOG_SYSLOG) && $self->{server}->{syslog_ident})
    { $msg = join(': ', $self->{server}->{syslog_ident}, $msg); }
  if ($self->{spampd}->{logtype} & LOGGER_SA)
    { Mail::SpamAssassin::Logger::log_message(SA_LOG_LEVELS->{$level}, $msg); }
  else
    { $self->SUPER::write_to_log_hook($level, $msg); }
}

sub dbg {
  shift()->log(4, @_);
}


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
  my (@args, @ptargs);
  my $dest = \@args;
  $sep = '=' if !defined($sep);
  $prfx = '--' if !defined($prfx);
  open(my $fh, '<', $file) or die "Couldn't open config file '$file' [$!]";
  while (defined(my $line = <$fh>)) {
    next if ($line !~ m/^\s* ((?:--?)?[\w\@-]+) (?:[=:\t ]+ (\S+) \s*)?$/xo);
    ($dest = \@ptargs) && next if $1 eq '--';
    my $k = $1;
    $k = join('', $prfx, $k) if $prfx && substr($k, 0, 1) ne '-';
    $k = join($sep, $k, $2) if $sep && $2;
    push (@{$dest}, $k);
    push (@{$dest}, $2) if !$sep && $2;
  }
  close $fh;
  return (\@args, \@ptargs);
}

# Converts a bitfield of logging type, plus optional file name, to an array/list
# of values which would be suitable for the commandline --logfile (-o) option.
sub logtype2file {
  my ($type, $file, $sep) = @_;
  my @ret;
  push(@ret, 'syslog') if ($type & LOG_SYSLOG);
  push(@ret, 'stderr') if ($type & LOG_STDERR);
  push(@ret, $file)    if ($type & LOG_FILE) && $file;
  return wantarray ? @ret : join($sep || ', ', @ret);
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
  die "refusing to untaint suspicious path: '$path'\n";
}

# Trims a string or array of strings. Modifies whatever was passed in!
sub trimmed { s{^\s+|\s+$}{}g foreach @_; };

# =item print_options(\%options [, type = "default"] [, exit = -1])
# Prints out names and values from a hash of option {name => \$value} pairs, such as might
#   be passed to Getopt::Long::GetOptions(). Fairly limited, eg. it cannot handle hash values.
# Any value that is not a ref to a scalar or to an array ref is ignored. The first version of the
#   option name, before the first "|", is used as the option name. Any option spec is also excluded.
sub print_options {
  my $opts = shift;
  my $type = ($_[0] && $_[0] !~ /^\d+$/ ? shift : 'default');
  my $exit = @_ ? $_[0] : -1;
  print "\n";
  print "# Configuration options for ".__PACKAGE__." v".$VERSION." with ".$type." values.\n";
  print "# This format is suitable as a configuration file. Just remove\n".
        "# the '#' marks (comment characters) and change values as needed.\n\n" if $exit > -1;
  for my $k (sort keys %{$opts}) {
    my $v = %{$opts}{$k};
    next if ref($v) !~ /SCALAR|REF/;
    $k = $1 if $k =~ /([\w-]+).*/;
    $v = defined(${$v}) ? ${$v} : "(undefined)";
    $v = join(":", @{$v}) if ref($v) eq 'ARRAY';
    printf("# %-24s %s\n", $k, $v);
  }
  print "\n";
  exit $exit if $exit > -1;
}

# =item show_debug($what, [ \%options, \@startup_args, %$self | \$thing_to_dump [,\$another_thing[,...]] ])
# Debug helper, print some values and exit. $what can be an array or single string or CSV list.
# $what values: [ all | [conf(ig), argv, start(args), self] ] | obj(ect)
#   "all" means everything except "object".
#   "obj" means just dump the rest of the argument(s); ignores rest of $what, basically Data::Dumper->Dump([@_])
# Always returns true, even if there is an error, so can be used eg.: show_debug(...) && exit(0);
sub show_debug {
  eval {
    my ($what, $opts, $clargs, $self) = (shift);
    my ($ok, @dumps, @dnames) = (0);
    trimmed(@$what = split(/,/, join(',', @$what)));
    if (grep(/^obj(ect)?$/i, @$what)) {
      push(@dumps, @_);
    }
    else {
      ($opts, $clargs, $self) = @_;
      if (grep(/^(conf(ig)?|all)$/i, @$what) && $opts)
        { print_options($opts, 'current', -1); $ok = 1; }
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
        $Data::Dumper::Quotekeys = 0; $Data::Dumper::Bless = '';
        $Data::Dumper::Sortkeys = $Data::Dumper::Sparseseen = 1;
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
  print __PACKAGE__." version $VERSION\n";
  print "  using Net::Server $Net::Server::VERSION\n";
  print "  using SpamAssassin " . Mail::SpamAssassin::Version() . "\n";
  print "  using Perl " . join(".", map(0+($_||0), ($] =~ /(\d)\.(\d{3})(\d{3})?/))) . "\n\n";
  exit 0;
}

# =item usage([exit_value=2, [help_level=1, [help_format=man]]])
sub usage {
  my ($exitval, $hlevel, $helpfmt) = @_;
  $exitval = 2 if !defined($exitval);
  $hlevel ||= 1;
  $helpfmt ||= 'man';
  my ($width, $indent, $quotes) = (78, 2, "‘’");
  my (@sections, $msg, $outfile, $pdoc_opts);

  eval {
    no warnings 'once';  # silence useless "$Pod::Usage::Formatter used only once: possible typo" warning
    $Pod::Usage::Formatter = 'Pod::Text::Termcap' if $helpfmt !~ /^txt$/i;
    require Pod::Usage;
  } or die "Could not load Pod::Usage!\n\t$@";

  # check if html version is requested (currently only works with full docs due to Pod::Usage behavior of -verbose < 2)
  if ($hlevel == 4) {
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
      $pdoc_opts = "-o man -w quotes:$quotes -w section:8 -w release:$VERSION ".
                   "-w center:".__PACKAGE__." -w name:".lc(__PACKAGE__);
    }
    elsif ($helpfmt =~ /^txt$/i) {
      $pdoc_opts = "-o text -T -w width:$width -w indent:$indent -w quotes:$quotes";
    }
  }
  else {
    push(@sections, "USAGE")    if $hlevel == 1 || $hlevel == 3;
    push(@sections, "SYNOPSIS") if $hlevel == 2;
    push(@sections, "OPTIONS")  if $hlevel == 3;
    $msg = "\n".__PACKAGE__." version $VERSION\n";
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
  exit $exitval if !$outfile;

  # if we get here, handle html output: first try to show it in a browser.
  my $disp_ok = eval {
    require HTML::Display;
    print "Using HTML::Display to display HTML.\n";
    HTML::Display::display(file => $outfile->filename());
  };
  # if HTML::Display is not installed, just try Debian or OSX style, or bail out.
  if (!$disp_ok) {
    my ($deb, $mac) = (-x "/usr/bin/x-www-browser"), ($^O =~ qr/darwin/i);
    if (my $cmdline = ($deb ? "x-www-browser " : ($mac ? "open " : undef))) {
      $cmdline .= $outfile->filename()." > /dev/null 2>&1" if $cmdline;
      if ($disp_ok = (system($cmdline) == 0))
        { print "Waiting to delete temp file...\n"; sleep 3; }
    }
  }
  if ($disp_ok) {
    $outfile->unlink_on_destroy(1);
    print "Removing temporary perldoc file ".$outfile->filename()."\n";
  }
  else {
    print "Unable to start a browser, open the generated HTML file manually.\n";
    print "Consider installing the HTML::Display Perl module.\n" if !defined($HTML::Display::VERSION);
  }
  exit $exitval;
}

sub deprecated_opt {
  warn "Note: option '". shift() ."' is deprecated and will be ignored.\n";
}

1;

__END__

##################   POD   ######################

=encoding UTF-8

=head1 NAME

SpamPD - Spam Proxy Daemon

=head1 VERSION

Documentation for SpamPD version 2.60.

=head1 SYNOPSIS

B<spampd> I<[ options ]>

Options:

  --config <filename>       Load options from file(s).

  --host <host>[:<port>]    Hostname/IP and optional port to listen on.
  --port <n>                Port to listen on (alternate syntax to above).
  --socket <socketpath>     UNIX socket to listen on.
  --socket-perms <mode>     The octal mode to set on the UNIX socket.
  --relayhost <hst>[:<prt>] Host and optional port to relay mail to.
  --relayport <n>           Port to relay to (alternate syntax to above).
  --relaysocket <sockpath>  UNIX socket to relay to.

  --children or -c <n>      Number of concurrent scanner processes to run.
  --maxrequests or -r <n>   Maximum requests that each child can process.
  --childtimeout <n>        Time out children after this many seconds.
  --satimeout <n>           Time out SpamAssassin after this many seconds.

  --pid   or -p <filename>  Store the daemon's process ID in this file.
  --user  or -u <user>      Specifies the user that the daemon runs as.
  --group or -g <group>     Specifies the group that the daemon runs as.

  --[no]detach              Detach from the console daemonize (default).
  --[no]setsid              Completely detach from stderr with setsid().

  --maxsize n               Maximum size of mail to scan (in KB).
  --dose                    (D)ie (o)n (s)pamAssassin (e)rrors.
  --tagall                  Tag all messages with SA headers, not just spam.
  --set-envelope-headers    Set X-Envelope-From and X-Envelope-To headers.
  --set-envelope-from       Set X-Envelope-From header only.

  --local-only or -L        Turn off all SA network-based tests.
  --homedir path            Use the specified directory as SA home.
  --saconfig <filename>     Use the file for SA "user_prefs" configuration.

  --logfile or -o <dest>    Destination for logs (syslog|stderr|<filename>).
  --logsock or -ls <sock>   Allows specifying the syslog socket type.
  --logident or -li <name>  Specify syslog identity name.
  --logfacility or -lf <nm> Specify syslog facility (log name).
  --log-rules-hit or -rh    Log the names of each matched SA test per mail.
  --debug or -d [<areas>]   Controls extra debug logging.

  --help | -h | -?   [txt]  Show basic command-line usage.
          -hh | -??  [txt]  Show short option descriptions (this text).
         -hhh | -??? [txt]  Show usage summary and full option descriptions.
  --man [html|txt]          Show full documentation as a man page or HTML/txt.
  --show defaults|<thing>   Print default option values (or <thing>) and exit.
  --version                 Print version information and exit.

Deprecated since SpamAssassin v3:

  --auto-whitelist or -aw   Use the SA global auto-whitelist feature.

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

=head1 REQUIRES

Perl modules:

=over 5

=item B<Mail::SpamAssassin>

=item B<Net::Server::PreForkSimple> (>= v0.89)

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
installation.  You may want to specify the --children option if you have an
especially beefy or weak server box because I<spampd> is a memory-hungry
program.  Check the L<"Options"> for details on this and all other parameters.

Note that B<I<spampd> replaces I<spamd>> from the I<SpamAssassin> distribution
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

If upgrading from a version prior to 2.2, please note that the --add-sc-header
option is no longer supported.  Use SA's built-in header manipulation features
instead (as of SA v2.6).

Upgrading from version 1 simply involves replacing the F<spampd> program file
with the latest one.  Note that the I<dead-letters> folder is no longer being
used and the --dead-letters option is no longer needed (though no errors are
thrown if it's present).  Check the L</OPTIONS> list below for a full list of new
and deprecated options.  Also be sure to check out the change log.

=head1 USAGE

  spampd [
    [ --config | --cfg | --config-file | --cfg-file [<filename>] ][...]

    [ --host <host>[:<port>]      | --socket <path> --socket-perms <mode> ]
    [ --relayhost <host>[:<port>] | --relaysocket <path>                  ]

    [--children      | -c <n>] [--saconfig <filename>] [--user  | -u <user> ]
    [--maxrequests   | -r <n>] [--satimeout <n>      ] [--group | -g <group>]
    [--childtimeout       <n>] [--dose               ] [--pid   | -p <file> ]
    [--tagall        | -a    ] [--maxsize   <n>      ] [--detach            ]
    [--log-rules-hit | -rh   ] [--local-only | -L    ] [--setsid            ]
    [ [--set-envelope-headers | -seh] | [--set-envelope-from | -sef] ]

    [ --logfile | -o (syslog|stderr|<filename>) ][...]
    [ --logsock | -ls <socketpath>    ]  [ --logident    | -li <name> ]
    [ --debug   | -d [<area,...>|1|0] ]  [ --logfacility | -lf <name> ]
    [ --show ( all | (defaults, config, argv, start, self) ) ][...]
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
arguments in the L</USAGE> section.

=over 5

=item B<--config> or B<--cfg> or B<--config-file> or B<--cfg-file> I<<filename>> C<(new in v2.60)>

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

Specifies what port I<spampd> listens on. By default, it listens on
port 10025. This is an alternate to using the above --host=ip:port notation.
Note that a I<port> specified in the C<--host> option will override this one.


=item B<--socket> I<<socketpath>>

Specifies what UNIX socket I<spampd> listens on. If this is specified,
--host and --port are ignored.


=item B<--socket-perms> I<<mode>>

The file mode for the created UNIX socket (see --socket) in octal
format, e.g. 700 to specify acces only for the user I<spampd> is run as.


=item B<--relayhost> I<< (<ip>|<hostname>)[:<port>] >>

Specifies the hostname/IP to which I<spampd> will relay all
messages. Defaults to 127.0.0.1 (localhost). If the port is not provided, that
defaults to 25.

As of v2.60 this option can also handle IPv6 addresses in the form of
C<--relayhost n:n:n> or, with port, C<--relayhost [n:n:n]:port> (the square brackets
are optional in both forms but recommended in the latter case).

Note that the I<port> specified this way implicitly overrides the C<--relayport> option.


=item B<--relayport> I<<n>>

Specifies what port I<spampd> will relay to. Default is 25. This is an
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

Number of child servers to start and maintain (where n > 0). Each child will
process up to --maxrequests (below) before exiting and being replaced by
another child.  Keep this number low on systems w/out a lot of memory.
Default is 5 (which seems OK on a 512MB lightly loaded system).  Note that
there is always a parent process running, so if you specify 5 children you
will actually have 6 I<spampd> processes running.

You may want to set your origination mail server to limit the
number of concurrent connections to I<spampd> to match this setting (for
Postfix this is the C<xxxx_destination_concurrency_limit> setting where
'xxxx' is the transport being used, usually 'smtp', and the default is 100).


=item B<--maxrequests> or B<-mr> or B<-r> I<<n>>

I<spampd> works by forking child servers to handle each message. The
B<maxrequests> parameter specifies how many requests will be handled
before the child exits. Since a child never gives back memory, a large
message can cause it to become quite bloated; the only way to reclaim
the memory is for the child to exit. The default is 20.


=item B<--childtimeout> I<<n>>

This is the number of seconds to allow each child server before it times out
a transaction. In an S/LMTP transaction the timer is reset for every command.
This timeout includes time it would take to send the message data, so it should
not be too short.  Note that it's more likely the origination or destination
mail servers will timeout first, which is fine.  This is just a "sane" failsafe.
Default is 360 seconds (6 minutes).


=item B<--satimeout> I<<n>>

This is the number of seconds to allow for processing a message with
SpamAssassin (including feeding it the message, analyzing it, and adding
the headers/report if necessary).
This should be less than your origination and destination servers' timeout
settings for the DATA command. For Postfix the default is 300 seconds in both
cases (smtp_data_done_timeout and smtpd_timeout). In the event of timeout
while processing the message, the problem is logged and the message is passed
on anyway (w/out spam tagging, obviously).  To fail the message with a temp
450 error, see the --dose (die-on-sa-errors) option, below.
Default is 285 seconds.


=item B<--pid> or B<-p> I<<filename>>

Specifies a filename where I<spampd> will write its process ID so
that it is easy to kill it later. The directory that will contain this
file must be writable by the I<spampd> user. The default is
F</var/run/spampd.pid>.


=item B<--logfile> or B<-o> I<< (syslog|stderr|<filename>) >> C<(new in v2.60)>

Logging method to use. May be one or more of:

=over 5

=item *

C<syslog>: Use the system's syslogd (via Sys::Syslog). B<default>

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


=item B<--logsock> or B<-ls> I<<type>> C<(new in v2.20)>  C<(updated in v2.60)>

Syslog socket to use if C<--logfile> is set to I<syslog>.

C<Since v2.60:>

The I<type> can be any of the socket types or logging mechanisms as accepted by
the subroutine Sys::Syslog::setlogsock(). Depending on the version of Sys::Syslog and
the underlying operating system, one of the following values (or their subset) can
be used:

    native, tcp, udp, inet, unix, stream, pipe, console, eventlog (Win32 only)

The default behavior since I<spampd> v2.60 is to let Sys::Syslog pick the default
syslog socket. This is the recommended usage for Sys::Syslog (since v0.15).

    The default is to try native, tcp, udp, unix, pipe, stream, console. Under systems with the
    Win32 API, eventlog will be added as the first mechanism to try if Win32::EventLog is available.

C<Prior to v2.60:>

The default was C<unix>. To preserve backwards-compatibility, the default on HP-UX and SunOS
(Solaris) systems is C<inet>.

For more information please consult the L<Sys::Syslog|https://metacpan.org/pod/Sys::Syslog> documentation.


=item B<--logident> or B<-li> I<<name>> C<(new in v2.60)>

Syslog identity name to use. This may also be used in log files written directly (w/out syslog). Default is C<spampd>.


=item B<--logfacility> or B<--lf> I<<name>> C<(new in v2.60)>

Syslog facility name to use. This is typically the name of the system-wide log file to be written to. Default is C<mail>.


=item B<--[no]detach> I<[0|1]> C<(new in v2.20)>

By default I<spampd> will detach from the console and fork into the
background ("daemonize"). Use C<--nodetach> to override this.
This can be useful for running under control of some daemon
management tools or testing from a command line.


=item B<--[no]setsid> I<[0|1]> C<(new in v2.51)>

If C<--setsid> is specified then I<spampd> will fork after the bind method to release
itself from the command line and then run the POSIX::setsid() command to truly
daemonize. Only used if C<--nodetach> isn't specified.


=item B<--maxsize> I<<n>>

The maximum message size to send to SpamAssassin, in KBytes. By default messages
over 64KB are not scanned at all, and an appropriate message is logged
indicating this.  The size includes headers and attachments (if any).


=item B<--dose> I<[0|1]>

Acronym for (d)ie (o)n (s)pamAssassin (e)rrors.  By default if I<spampd>
encounters a problem with processing the message through Spam Assassin (timeout
or other error), it will still pass the mail on to the destination server.  If
you specify this option however, the mail is instead rejected with a temporary
error (code 450, which means the origination server should keep retrying to send
it).  See the related --satimeout option, above.


=item B<--tagall> or B<-a> I<[0|1]>

Tells I<spampd> to have SpamAssassin add headers to all scanned mail,
not just spam.  By default I<spampd> will only rewrite messages which
exceed the spam threshold score (as defined in the SA settings).  Note that
for this option to work as of SA-2.50, the I<always_add_report> and/or
I<always_add_headers> settings in your SpamAssassin F<local.cf> need to be
set to 1/true.


=item B<--log-rules-hit> or B<--rh> I<[0|1]>

Logs the names of each SpamAssassin rule which matched the message being
processed.  This list is returned by SA.


=item B<--set-envelope-headers> or B<--seh> I<[0|1]> C<(new in v2.30)>

Turns on addition of X-Envelope-To and X-Envelope-From headers to the mail
being scanned before it is passed to SpamAssassin. The idea is to help SA
process any blacklist/whitelist to/from directives on the actual
sender/recipients instead of the possibly bogus envelope headers. This
potentially exposes the list of all recipients of that mail (even BCC'd ones).
Therefore usage of this option is discouraged.

I<NOTE>: Even though I<spampd> tries to prevent this leakage by removing the
X-Envelope-To header after scanning, SpamAssassin itself might add headers
that report recipient(s) listed in X-Envelope-To.


=item B<--set-envelope-from> or B<--sef> I<[0|1]> C<(new in v2.30)>

Same as above option but only enables the addition of X-Envelope-From header.
For those that don't feel comfortable with the possible information exposure
of X-Envelope-To.  The above option overrides this one.


=item B<--local-only> or B<-L> I<[0|1]>

Turn off all SA network-based tests (DNS, Razor, etc).


=item B<--homedir> I<<directory>> C<(new in v2.40)>

Use the specified directory as home directory for the spamassassin process.
Things like the auto-whitelist and other plugin (razor/pyzor) files get
written to here.
Default is /var/spool/spamassassin/spampd.  A good place for this is in the same
place your bayes_path SA config setting points to (if any).  Make sure this
directory is accessible to the user that spampd is running as (default: mail).
Thanks to Alexander Wirt for this fix.


=item B<--saconfig> I<<filename>>

Use the specified file for SpamAssassin configuration options in addition to the
default local.cf file.  Any options specified here will override the same
option from local.cf.  Default is to not use any additional configuration file.


=item B<--debug> or B<-d> I<< [<area,...>|1|0] >> C<(updated in v2.60)>

Turns on SpamAssassin debug messages which print to the system mail log
(same log as spampd will log to).  Also turns on more verbose logging of
what spampd is doing (new in v2).  Also increases log level of Net::Server
to 4 (debug), adding yet more info (but not too much) (new in v2.2).

C<New in v2.60:>

Setting the value to 1 (one) is the same as using no parameter (eg. simply I<-d>).
The value of 0 (zero) disables debug logging (this is the default).

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


=item B<--show> I<<thing>>[,I<<thing>>[,...]] C<(new in v2.60)>

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

C<argv>: Shows anything remaining on command line (@ARGV) after processing all known arguments
(this will be passed onto Net::Server).

=item *

C<self>: Dumps the whole SpamPD object, including all settings. Trés geek.

=item *

C<all>: Prints all of the above.

=back

Multiple C<thing>s may be specified by using the I<--show> option multiple times, or
separating the items with a comma: C<--show config,start,argv>.


=item B<--version> C<(new in v2.52)>

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
For example there are access control options, an option to run chrooted, and a few more (see below).
Such options can be passed through to I<Net::Server> by specifying them at the end
of the I<spampd> command line (or in a configuration file) following two dashes
C< -- > by themselves (this is a failry typicaly convention for passing options onto
another program). As an example, it may look something like this:

  spampd --host 10.0.0.1 -port 10025 -- --cidr_allow 10.0.0.0/24

The C<--cidr_allow> after the C< -- > is passed onto I<Net::Server>. If the C< -- > were
not there, you would get an error from I<spampd> about an unknown option.

To specify I<Net::Server> options in a configuration file, place them after two
dashes (C<-->) on a line by themselves. See L</"CONFIGURATION FILE"> for an example.

This only makes sense with the few options not directly controlled by/through I<spampd>.
As of I<Net::Server> and I<Net::Server::PreForkSimple> v2.009 the list is:

  reverse_lookups, allow, deny, cidr_allow, cidr_deny, chroot, ipv, conf_file,
  serialize, lock_file, check_for_dead, max_dequeue, check_for_dequeue

See the L<Net::Server(3)|https://metacpan.org/pod/distribution/Net-Server/lib/Net/Server.pod#DEFAULT-ARGUMENTS-FOR-Net::Server>
and L<Net::Server::PreForkSimple(3)|https://metacpan.org/pod/Net::Server::PreForkSimple#COMMAND-LINE-ARGUMENTS>
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

=item B<--auto-whitelist> or B<--aw> C<(deprecated with SpamAssassin v3+)>

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

I<spampd> allows for the use of a configuration file to read in server parameters.
The format of this conf file is simple key value pairs. Comments (starting with # or ;)
and blank lines are ignored. The option names are exactly as they appear above.
They can be listed with or w/out the "-"/"--" prefixes.
Key/value separator can be one or more of space, tab, or "=" (equal) sign.

Multiple configuration files can be loaded, with the latter ones being able to
override options loaded earlier. Any options specified on the command line will
take precedence over options from file(s). You may also provide "passthrough"
options directly to Net::Server by putting them after a "--" on a line by itself
(this is just like using the lonesome "--" on a command line; see L</"Other Net::Server Options">).

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

  # Passthrough arguments for Net::Server[::PreForkSimple] could go here.
  # Be sure to also uncomment the "--" if using any.
  # --
  # cidr_allow      127.0.0.1/32

This feature was added in C<(v2.60)>.


=head1 SIGNALS

=over 5

=item HUP

Sending HUP signal to the master process will restart all the children
gracefully (meaning the currently running requests will shut down once
the request is complete).

C<(new in v2.60)>: SpamAssassin configuration IS reloaded on HUP. Any children
currently in the middle of a transaction will finish with the previous SA config
and then exit. A new set of children, using the new config, is spawned upon HUP
and will serve any new requests.

=item TTIN, TTOU

Sending TTIN signal to the master process will dynamically increase
the number of children by one, and TTOU signal will decrease it by one.

=item INT, TERM

Sending INT or TERM signal to the master process will kill all the
children immediately and shut down the daemon.

=item QUIT

Sending QUIT signal to the master process will perform a graceful shutdown,
waiting for all children to finish processing any current transactions and
then shutting down the daemon.

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
See L<http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm> for latest info.

I<spampd> v2 uses two Perl modules by Bennett Todd and Copyright (C) 2001 Morgan
Stanley Dean Witter. These are distributed under the GNU GPL (see
module code for more details). Both modules have been slightly modified
from the originals and are included in this file under new names.

Also thanks to Bennett Todd for the example smtpproxy script which helped create
this version of I<spampd>.  See http://bent.latency.net/smtpprox/ .

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

I<spampd> is Copyright (c) 2002-2006, 2009-2010, 2013, 2018-2019 Maxim Paperno;
All Rights Reserved.

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

=head1 TO DO

Figure out how to use Net::Server::PreFork because it has cool potential for
load management.  I tried but either I'm missing something or PreFork is
somewhat broken in how it works.  If anyone has experience here, please let
me know. (It looks like some things have been fixed in Net::Server::PreFork since this
note was originally written, so it may be worth trying again.)

=head1 SEE ALSO

L<spamassassin(1)>

L<Mail::SpamAssassin(3)|https://spamassassin.apache.org/doc/Mail_SpamAssassin.html>

L<Net::Server(3)|https://metacpan.org/pod/distribution/Net-Server/lib/Net/Server.pod>

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
    var list = document.querySelectorAll("a[href*=podtop] h1, ul#index > li > a, h1 a.u, li.indexItem1 > a");
    for (let item of list)
      item.innerText = titleCase(item.innerText);
  }
</script>

=end html

=cut

=begin comment

This documents a feature which may be implemented later.

=item B<--maxchildren=n> or B<--mc=n>

Maximum number of children to spawn if needed (where n >= --children).  When
I<spampd> starts it will spawn a number of child servers as specified by
--children. If all those servers become busy, a new child is spawned up to the
number specified in --maxchildren. Default is to have --maxchildren equal to
--children so extra child processes aren't started. Also see the --children
option, above.  You may want to set your origination mail server to limit the
number of concurrent connections to I<spampd> to match this setting (for
Postfix this is the C<xxxx_destination_concurrency_limit> setting where
'xxxx' is the transport being used, usually 'smtp', and the default is 100).

Note that extra servers after the initial --children will only spawn on very
busy systems.  This is because the check to see if a new server is needed (ie.
all current ones are busy) is only done around once per minute (this is
controlled by the Net::Server::PreFork module, in case you want to
hack at it :).  It can still be useful as an "overflow valve," and is
especially nice since the extra child servers will die off once they're not
needed.

=end comment
