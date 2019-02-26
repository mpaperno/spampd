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
# spampd is Copyright (c) 2002-2006, 2009, 2010, 2013, 2018 by World Design Group and Maxim Paperno
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
use IO::File;

# =item new(socket => $socket);
#
# Changed by MP: This now emulates Net::SMTP::Server::Client for use with 
#   Net::Server which passes an already open socket.
# The #socket listen on must be specified. If this call
# succeeds, it returns a server structure. If it fails it dies, so
# if you want anything other than an exit with an explanatory error
# message, wrap the constructor call in an eval block and pull the
# error out of $@ as usual. This is also the case for all other
# methods; they succeed or they die.
#
# =cut

sub new {
  my ($this, $socket) = @_;

  my $class = ref($this) || $this;
  my $self = {};
  $self->{sock} = $socket;

  bless($self, $class);

  die "$0: socket bind failure: $!\n" unless defined $self->{sock};
  $self->{state} = 'started';
  $self->{proto} = 'unknown';
  $self->{helo} = 'unknown.host';
  return $self;
}

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
      $self->{data}->print($_) or die "$0: write error saving data\n";
    }
    return 0;
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
  if (defined $self->{debug}) {
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
use warnings;
use IO::Socket::IP;
use IO::Socket::UNIX;

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
  if (defined $self->{unix_socket}) {
    $self->{sock} = IO::Socket::UNIX->new(
      Peer    => $self->{unix_socket},
      Timeout => $self->{timeout},
      Type    => SOCK_STREAM,
    );
  }
  else {
    $self->{sock} = IO::Socket::IP->new(
      PeerAddr => $self->{interface},
      PeerPort => $self->{port},
      Timeout  => $self->{timeout},
      Proto    => 'tcp',
      Type     => SOCK_STREAM,
    );
  }
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
  $self->{sock}->autoflush(0);  # use fewer writes (thx to Sam Horrocks for the tip)
  while (<$fh>) {
    s/^\./../;
    $self->{sock}->print($_) or die "$0: write error: $!\n";
  }
  $self->{sock}->autoflush(1);  # restore unbuffered socket operation
  $self->{sock}->print(".\r\n") or die "$0: write error: $!\n";
}

1;


################################################################################
package SpamPD;

use strict;
use warnings;
use Net::Server::PreForkSimple;
use IO::File;
use Getopt::Long;
use Mail::SpamAssassin;

BEGIN {
  # Load Time::HiRes if it's available
  eval { require Time::HiRes };
  Time::HiRes->import(qw(time)) unless $@;

  # use included modules
  import SpamPD::Server;
  import SpamPD::Client;
}


use vars qw(@ISA $VERSION);
our @ISA     = qw(Net::Server::PreForkSimple);
our $VERSION = '2.53';

sub process_message {
  my ($self, $fh) = @_;

  # output lists with a , delimeter by default
  local ($") = ",";

  # start a timer
  my $start = time;
  # use the assassin object created during startup
  my $assassin   = $self->{spampd}->{assassin};
  my $sa_version = Mail::SpamAssassin::Version();
  # $sa_version can have a non-numeric value if version_tag is
  # set in local.cf. Only take first numeric value
  $sa_version =~ s/([0-9]*\.[0-9]*).*/$1/;

  # this gets info about the message temp file
  my $size = ($fh->stat)[7] or die "Can't stat mail file: $!";

  # Only process message under --maxsize KB
  if ($size >= ($self->{spampd}->{maxsize} * 1024)) {
    $self->mylog(2, "skipped large message (" . $size / 1024 . "KB)");
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
      if (($self->{spampd}->{envelopeheaders} || $self->{spampd}->{setenvelopefrom}) && !$envfrom) {
        unshift(@msglines, "X-Envelope-From: $sender\r\n");
        $self->dbg("Added X-Envelope-From") ;
      }
      if ($self->{spampd}->{envelopeheaders} && !$envto) {
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

  $self->mylog(2, "processing message $msgid for " . $recips);

  eval {

    local $SIG{ALRM} = sub { die "Timed out!\n" };

    # save previous timer and start new
    my $previous_alarm = alarm($self->{spampd}->{satimeout});

    # Audit the message
    if ($sa_version >= 3) {
      $mail = $assassin->parse(\@msglines, 0);
      undef @msglines;  #clear some memory-- this screws up SA < v3
    }
    elsif ($sa_version >= 2.70) {
      $mail = Mail::SpamAssassin::MsgParser->parse(\@msglines);
    }
    else {
      $mail = Mail::SpamAssassin::NoMailAudit->new(data => \@msglines);
    }

    # Check spamminess (returns Mail::SpamAssassin:PerMsgStatus object)
    my $status = $assassin->check($mail);

    $self->dbg("Returned from checking by SpamAssassin");

    #  Rewrite mail if high spam factor or options --tagall
    if ($status->is_spam || $self->{spampd}->{tagall}) {

      $self->dbg("Rewriting mail using SpamAssassin");

      # use Mail::SpamAssassin:PerMsgStatus object to rewrite message
      if ($sa_version >= 3) {
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

    $self->mylog(2, "$was_it_spam $msgid ($msg_score/$msg_threshold) from $sender for " .
                    "$recips in " . $proc_time . "s, $size bytes.");

    # thanks to Kurt Andersen for this idea
    $self->mylog(2, "rules hit for $msgid: " . $status->get_names_of_tests_hit) if ($self->{spampd}->{rh});

    $status->finish();
    $mail->finish();

    # set the timeout alarm back to wherever it was at
    alarm($previous_alarm);

  };  # end eval block

  if ($@ ne '') {
    $self->mylog(1, "WARNING!! SpamAssassin error on message $msgid: $@");
    return 0;
  }

  return 1;
}

sub process_request {
  my $self = shift;

  eval {

    local $SIG{ALRM} = sub { die "Child server process timed out!\n" };
    my $timeout = $self->{spampd}->{childtimeout};
    my $rcpt_ok = 0;

    # start a timeout alarm
    alarm($timeout);

    # start an smtp server
    my $smtp_server = SpamPD::Server->new($self->{server}->{client});
    die "Failed to create listening Server: $!" unless (defined $smtp_server);

    $self->{smtp_server} = $smtp_server;

    $self->dbg("Initiated Server");

    # start an smtp "client" (really a sending server)
    my $client = SpamPD::Client->new(
      interface   => $self->{spampd}->{relayhost},
      port        => $self->{spampd}->{relayport},
      unix_socket => $self->{spampd}->{unix_relaysocket}
    );
    die "Failed to create sending Client: $!" unless (defined $client);

    $self->dbg("Initiated Client");

    # pass on initial client response
    # $client->hear can handle multiline responses so no need to loop
    $smtp_server->ok($client->hear)
      or die "Error in initial server->ok(client->hear): $!";

    $self->dbg("smtp_server state: '" . $smtp_server->{state} . "'");

    # while loop over incoming data from the server
    while (my $what = $smtp_server->chat) {

      $self->dbg("smtp_server state: '" . $smtp_server->{state} . "'");

      # until end of DATA is sent, just pass the commands on transparently
      if ($what ne '.') {
        $client->say($what)
          or die "Failure in client->say(what): $!";
      }
      # but once the data is sent now we want to process it
      else {
        # spam checking routine - message might be rewritten here
        my $pmrescode = $self->process_message($smtp_server->{data});

        # pass on the messsage if exit code <> 0 or die-on-sa-errors flag is off
        if ($pmrescode or !$self->{spampd}->{dose}) {
          # need to give the client a rewound file
          $smtp_server->{data}->seek(0, 0)
            or die "Can't rewind mail file: $!";
          # now send the data on through the client
          $client->yammer($smtp_server->{data})
            or die "Failure in client->yammer(smtp_server->{data}): $!";
        }
        else {
          $smtp_server->ok("450 Temporary failure processing message, please try again later");
          last;
        }

        #close the temp file
        $smtp_server->{data}->close
          or $self->mylog(1, "WARNING!! Couldn't close smtp_server->{data} temp file: $!");

        $self->dbg("Finished sending DATA");
      }

      # pass on whatever the relayhost said in response
      # $client->hear can handle multiline responses so no need to loop
      my $destresp = $client->hear;
      $smtp_server->ok($destresp)
        or die "Error in server->ok(client->hear): $!";

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
            $smtp_server->ok($destresp)
              or die "Error in server->ok(client->hear): $!";
            $self->dbg("Destination response: '" . $destresp . "'");
          }
        }
      }

      # restart the timeout alarm
      alarm($timeout);

    }  # server ends connection

    # close connections
    $client->{sock}->close
      or die "Couldn't close client->{sock}: $!";
    $smtp_server->{sock}->close
      or die "Couldn't close smtp_server->{sock}: $!";

    $self->dbg("Closed connections");

  };  # end eval block

  alarm(0);  # stop the timer
  # check for error in eval block
  if ($@ ne '') {
    chomp($@);
    my $msg = "WARNING!! Error in process_request eval block: $@";
    $self->mylog(0, $msg);
    die($msg . "\n");
  }

  $self->{spampd}->{instance}++;
}

# Net::Server hook
# After binding listening sockets
sub post_bind_hook {
  my $self   = shift;
  my $server = $self->{server};
  if (defined $server->{unix_socket} and defined $server->{unix_socket_perms}) {
    my $mode = oct($server->{unix_socket_perms});
    chmod $mode, $server->{unix_socket} or die $@;
  }
}

# Net::Server hook
# about to exit child process
sub child_finish_hook {
  my $self = shift;
  $self->dbg("Exiting child process after handling " . $self->{spampd}->{instance} . " requests");
}

# older Net::Server versions (<= 0.87) die when logging a % character to Sys::Syslog
sub mylog($$$) {
  my ($self, $level, $msg) = @_;
  $msg =~ s/\%/%%/g;
  $self->log($level, $msg);
}

sub dbg($$) {
  my ($self, $msg) = @_;
  $self->mylog(2, $msg) if $self->{spampd}->{debug};
}

# Override Net::Server's HUP handling - just gracefully restart all the children.
sub sig_hup {
  my $self = shift;
  $self->hup_children;
}


##################   SETUP   ######################

my $host            = '127.0.0.1';                       # listen on ip
my $port            = 10025;                             # listen on port
my $socket          = undef;                             # listen on socket
my $socket_perms    = undef;                             # listening socket permissions (octal)
my $relayhost       = '127.0.0.1';                       # relay to ip
my $relayport       = 25;                                # relay to port
my $relaysocket     = undef;                             # relay to socket
my $children        = 5;                                 # number of child processes (servers) to spawn at start
my $maxrequests     = 20;                                # max requests handled by child b4 dying
my $childtimeout    = 6 * 60;                            # child process per-command timeout in seconds
my $satimeout       = 285;                               # SpamAssassin timeout in seconds (15s less than Postfix
                                                         #   default for smtp_data_done_timeout)
my $pidfile         = '/var/run/spampd.pid';             # write pid to file
my $user            = 'mail';                            # user to run as
my $group           = 'mail';                            # group to run as
my $tagall          = 0;                                 # mark-up all msgs with SA, not just spam
my $maxsize         = 64;                                # max. msg size to scan with SA, in KB.
my $rh              = 0;                                 # log which rules were hit
my $debug           = 0;                                 # debug flag
my $dose            = 0;                                 # die-on-sa-errors flag
my $logsock         = 'unix';                            # default log socket (some systems like 'inet')
my $nsloglevel      = 2;                                 # default log level for Net::Server (in the range 0-4)
my $background      = 1;                                 # specifies whether to 'daemonize' and fork into background;
                                                         #   apparently useful under Win32/cygwin to disable this via --nodetach;
my $setsid          = 0;                                 # specifies whether to use POSIX::setsid() command to truly daemonize.
my $envelopeheaders = 0;                                 # Set X-Envelope-To and X-Envelope-From headers in the mail before
                                                         #   passing it to spamassassin. Set to 1 to enable this.
my $setenvelopefrom = 0;                                 # Set X-Envelope-From header only
my $sa_config       = '';                                # use this config file for SA settings (blank uses default local.cf)
my $sa_home_dir     = '/var/spool/spamassassin/spampd';  # home directory for SA files (auto-whitelist, plugin helpers)
my $sa_local_only   = 0;                                 # disable SA network tests
my $sa_awl          = 0;                                 # enable SA auto-whitelist (deprecated as of SA 3.0)

# log socket default for HP-UX and SunOS (thanks to Kurt Andersen for the 'uname -s' fix)
eval {
  my $osname = `uname -s`;
  $logsock = "inet" if ($osname =~ 'HP-UX' || $osname =~ 'SunOS');
};

GetOptions(
  'host=s'                   => \$host,
  'port=i'                   => \$port,
  'socket=s'                 => \$socket,
  'socket-perms=s'           => \$socket_perms,
  'relayhost=s'              => \$relayhost,
  'relayport=i'              => \$relayport,
  'relaysocket=s'            => \$relaysocket,
  'children|c=i'             => \$children,
  'maxrequests|mr=i'         => \$maxrequests,
  'childtimeout=i'           => \$childtimeout,
  'satimeout=i'              => \$satimeout,
  'pid|p=s'                  => \$pidfile,
  'user|u=s'                 => \$user,
  'group|g=s'                => \$group,
  'maxsize=i'                => \$maxsize,
  'tagall|a'                 => \$tagall,
  'log-rules-hit|rh'         => \$rh,
  'debug|d'                  => \$debug,
  'dose'                     => \$dose,
  'logsock=s'                => \$logsock,
  'detach!'                  => \$background,
  'setsid'                   => \$setsid,
  'set-envelope-headers|seh' => \$envelopeheaders,
  'set-envelope-from|sef'    => \$setenvelopefrom,
  'saconfig=s'               => \$sa_config,
  'homedir=s'                => \$sa_home_dir,
  'local-only|l'             => \$sa_local_only,
  'auto-whitelist|aw'        => \$sa_awl,
  'help|h|?'                 => sub { usage(0) },
  'version'                  => \&version,
  'dead-letters=s'           => \&deprecated_opt,
  'heloname=s'               => \&deprecated_opt,
  'stop-at-threshold'        => \&deprecated_opt,
  'add-sc-header|ash'        => \&deprecated_opt,
  'hostname=s'               => \&deprecated_opt,
) or usage(1);

if ($logsock !~ /^(unix|inet)$/) {
  print "--logsock parameter needs to be either unix or inet\n\n";
  exit 1; 
}

if ($children < 1) { 
  print "Option --children must be greater than zero!\n";
  exit 1;
}

# Untaint some options provided by admin command line.
$host         = $1 if $host =~ /^(.*)$/;
$port         = $1 if $port =~ /^(.*)$/;
$socket       = $1 if defined($socket) && $socket =~ /^(.*)$/;
$socket_perms = $1 if defined($socket_perms) && $socket_perms =~ /^(.*)$/;
$relayhost    = $1 if $relayhost =~ /^(.*)$/;
$relayport    = $1 if $relayport =~ /^(.*)$/;
$relaysocket  = $1 if defined($relaysocket) && $relaysocket =~ /^(.*)$/;
$pidfile      = $1 if $pidfile =~ /^(.*)$/;
$logsock      = $1 if $logsock =~ /^(.*)$/;
#

$nsloglevel = 4 if $debug;
$setsid     = 0 if !$background;

my @tmp = split(/:/, $relayhost);
$relayhost = $tmp[0];
$relayport = $tmp[1] if $tmp[1];

@tmp = split(/:/, $host);
$host = $tmp[0];
$port = $tmp[1] if $tmp[1];

my $sa_options = {
  'dont_copy_prefs'      => 1,
  'debug'                => $debug,
  'local_tests_only'     => $sa_local_only,
  'home_dir_for_helpers' => $sa_home_dir,
  'userstate_dir'        => $sa_home_dir,
  'username'             => $user
};

my $use_user_prefs = 0;

if ($sa_config ne '') {
  $sa_options->{'userprefs_filename'} = $sa_config;
  $use_user_prefs = 1;
}

#cleanup environment before starting SA (thanks to Alexander Wirt)
$ENV{'PATH'} = '/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin';
delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV', 'HOME'};

my $assassin = Mail::SpamAssassin->new($sa_options);

$sa_awl and eval {
  require Mail::SpamAssassin::DBBasedAddrList;

  # create a factory for the persistent address list
  my $addrlistfactory = Mail::SpamAssassin::DBBasedAddrList->new();
  $assassin->set_persistent_address_list_factory($addrlistfactory);
};

$assassin->compile_now($use_user_prefs);

# Net::Server wants UNIX sockets passed via port too. This part
# decides what we want to pass.
my @ports;
if (defined $socket) {
  @ports = ($socket . '|unix');
}
else {
  @ports = ($port);
}

my $server = bless {
  server => {
    host              => $host,
    port              => \@ports,
    unix_socket       => $socket,
    unix_socket_perms => $socket_perms,
    log_file          => 'Sys::Syslog',
    log_level         => $nsloglevel,
    syslog_logsock    => $logsock,
    syslog_ident      => 'spampd',
    syslog_facility   => 'mail',
    background        => $background,
    setsid            => $setsid,
    pid_file          => $pidfile,
    user              => $user,
    group             => $group,
    max_servers       => $children,
    max_requests      => $maxrequests,
  },
  spampd => {
    relayhost        => $relayhost,
    relayport        => $relayport,
    unix_relaysocket => $relaysocket,
    tagall           => $tagall,
    maxsize          => $maxsize,
    assassin         => $assassin,
    childtimeout     => $childtimeout,
    satimeout        => $satimeout,
    rh               => $rh,
    debug            => $debug,
    dose             => $dose,
    instance         => 0,
    envelopeheaders  => $envelopeheaders,
    setenvelopefrom  => $setenvelopefrom,
  },
}, 'SpamPD';

# Redirect all warnings to Server::log
$SIG{__WARN__} = sub { $server->log(2, $_[0]); };

# call Net::Server to start up the daemon inside
$server->run;

exit 1;  # shouldn't get here

sub version {
  print "SpamPD version $VERSION\n";
  print "  using Net::Server $Net::Server::VERSION\n";
  print "  using SpamAssassin " . Mail::SpamAssassin::Version() . "\n";
  print "  using Perl " . join(".", map(0+($_||0), ($] =~ /(\d)\.(\d{3})(\d{3})?/))) . "\n\n";
  exit 0;
}

sub usage {
  print <<EOF ;
usage: $0 [ options ]

Options:
  --host=host[:port]       Hostname/IP and optional port to listen on. 
                             Default is 127.0.0.1 port 10025
  --port=n                 Port to listen on (alternate syntax to above).
  --socket=socketpath      UNIX socket to listen on. Alternative to
                             --host and --port.
  --socket-perms=perms     The file mode to set on the created UNIX
                             socket in octal format.
  --relayhost=host[:port]  Host to relay mail to. 
                             Default is 127.0.0.1 port 25.
  --relayport=n            Port to relay to (alternate syntax to above).
  --relaysocket            UNIX socket to relay to. Alternative to
                             --relayhost and --relayport.
  --children=n or -c n     Number of child processes (servers) to start and
                             keep running. Default is 5 (plus 1 parent proc).
  --maxrequests=n          Maximum requests that each child can process before
    or --mr n                exiting. Default is 20.
  --childtimeout=n         Time out children after this many seconds during
                             transactions (each S/LMTP command including the
                             time it takes to send the data). 
                             Default is 360 seconds (6min).
  --satimeout=n            Time out SpamAssassin after this many seconds.
                             Default is 285 seconds.

  --pid=filename           Store the daemon's process ID in this file. 
    or -p filename           Default is /var/run/spampd.pid
  --user=username          Specifies the user that the daemon runs as.
    or -u username           Default is mail.
  --group=groupname        Specifies the group that the daemon runs as.
    or -g groupname          Default is mail.

  --nodetach               Don't detach from the console and fork into
                             background. Useful for some daemon control
                             tools or when running as a win32 service
                             under cygwin.
  --setsid                 Fork after the bind method to release itself
                             from the command line and then run the
                             POSIX::setsid() command to truly daemonize.
                             Only used if --nodetach isn't specified.
  --logsock=(inet|unix)    Allows specifying the syslog socket type. Default is 
                             'unix' except on HPUX and SunOS which use 'inet'.

  --maxsize=n              Maximum size of mail to scan (in KB).
                             Default is 64KB.
  --dose                   (d)ie (o)n (s)pamAssassin (e)rrors. If this is
                             specified and SA times out or throws an error,
                             the mail will be rejected with a 450 temporary
                             error message. Default is to pass through email
                             even in the event of an SA problem.
  --tagall                 Tag all messages with SA headers, not just spam.
  --log-rules-hit          Log the name of each SA test which matched the
    or --rh                  current message.

  --set-envelope-headers   Set X-Envelope-From and X-Envelope-To headers before
    or --seh                 passing the mail to SpamAssassin. This is 
                             disabled by default because it potentially leaks
                             information. NOTE: Please read the manpage before
                             enabling this!
  --set-envelope-from      Same as above but only sets X-Envelope-From, for
    or --sef                 those that don't feel comfortable with the
                             potential information leak.

  --auto-whitelist         Use the SA global auto-whitelist feature 
    or --aw                  (SA versions => 3.0 now control this via local.cf).
  --local-only or -L       Turn off all SA network-based tests (RBL/Razor/etc).
  --homedir=path           Use the specified directory as home directory for 
                             the SpamAssassin process. 
                             Default is /var/spool/spamassassin/spampd
  --saconfig=filename      Use the specified file for loading SA configuration
                             options after the default local.cf file.

  --debug or -d            Turn on extra debugging details (sent to log file).
  --version                Print version information and exit.
  --help or -h or -?       Show this help text.

Deprecated Options (still accepted for backwards compatibility):
  --heloname=hostname      No longer used in spampd v.2
  --dead-letters=path      No longer used in spampd v.2
  --stop-at-threshold      No longer implemented in SpamAssassin
EOF

  exit shift;
}

sub deprecated_opt {
  my $opt_name = shift;
  print "Note: option '$opt_name' is deprecated and will be ignored.\n";
}

__END__

# Some commented-out documentation.  POD doesn't have a way to comment 
# out sections!?  This documents a feature which may be implemented later.
#
# =item B<--maxchildren=n> or B<--mc=n>
#
# Maximum number of children to spawn if needed (where n >= --children).  When 
# I<spampd> starts it will spawn a number of child servers as specified by 
# --children. If all those servers become busy, a new child is spawned up to the
# number specified in --maxchildren. Default is to have --maxchildren equal to
# --children so extra child processes aren't started. Also see the --children 
# option, above.  You may want to set your origination mail server to limit the 
# number of concurrent connections to I<spampd> to match this setting (for 
# Postfix this is the C<xxxx_destination_concurrency_limit> setting where 
# 'xxxx' is the transport being used, usually 'smtp', and the default is 100).
#
# Note that extra servers after the initial --children will only spawn on very
# busy systems.  This is because the check to see if a new server is needed (ie.
# all current ones are busy) is only done around once per minute (this is 
# controlled by the Net::Server::PreFork module, in case you want to 
# hack at it :).  It can still be useful as an "overflow valve," and is 
# especially nice since the extra child servers will die off once they're not
# needed.

=pod

=head1 NAME

SpamPD - Spam Proxy Daemon (version 2.5x)

=head1 Synopsis

B<spampd>
[B<--host=host[:port]>]
[B<--relayhost=hostname[:port]>]
[B<--socket>]
[B<--socket-perms>]
[B<--relaysocket>]
[B<--user|u=username>]
[B<--group|g=groupname>]
[B<--children|c=n>]
[B<--maxrequests=n>]
[B<--childtimeout=n>]
[B<--satimeout=n>]
[B<--pid|p=filename>]
[B<--nodetach>]
[B<--setsid>]
[B<--logsock=inet|unix>]
[B<--maxsize=n>]
[B<--dose>]
[B<--tagall|a>]
[B<--log-rules-hit|rh>]
[B<--set-envelope-headers|seh>]
[B<--set-envelope-from|sef>]
[B<--auto-whitelist|aw>]
[B<--local-only|L>]
[B<--saconfig=filename>]
[B<--debug|d>]

B<spampd> B<--help>

=head1 Description

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

=head1 Requires

Perl modules:

=over 5

=item B<Mail::SpamAssassin>

=item B<Net::Server::PreForkSimple>

=item B<IO::File>

=item B<IO::Socket::IP>

=item B<IO::Socket::UNIX>

=item B<Time::HiRes> (not actually required but recommended)

=back

=head1 Operation

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


B<Running between firewall/gateway and internal mail server>

=over 3

The firewall/gateway MTA would be configured to forward all of its mail 
to the port that I<spampd> listens on, and I<spampd> would relay its 
messages to port 25 of your internal server. I<spampd> could either 
run on its own host (and listen on any port) or it could run on either 
mail server (and listen on any port except port 25).

 Internet -> [ MX gateway (@inter.net.host:25) -> 
	spampd (@localhost:2025) ] ->
	Internal mail (@private.host.ip:25)

=back

B<Using Postfix advanced content filtering>

=over 3

Please see the F<FILTER_README> that came with the Postfix distribution.  You
need to have a version of Postfix which supports this (ideally v.2 and up).

 Internet -> [ Postfix (@inter.net.host:25) -> 
	spampd (@localhost:10025) -> 
	Postfix (@localhost:10026) ] -> final delivery

=back

Note that these examples only show incoming mail delivery.  Since it is 
usually unnecessary to scan mail coming from your network (right?),
it may be desirable to set up a separate outbound route which bypasses
I<spampd>.

=head1 Upgrading

If upgrading from a version prior to 2.2, please note that the --add-sc-header
option is no longer supported.  Use SAs built-in header manipulation features
instead (as of SA v2.6).

Upgrading from version 1 simply involves replacing the F<spampd> program file
with the latest one.  Note that the I<dead-letters> folder is no longer being
used and the --dead-letters option is no longer needed (though no errors are
thrown if it's present).  Check the L<"Options"> list below for a full list of new
and deprecated options.  Also be sure to check out the change log.

=head1 Installation

I<spampd> can be run directly from the command prompt if desired.  This is
useful for testing purposes, but for long term use you probably want to put
it somewhere like /usr/bin or /usr/local/bin and execute it at system startup.
For example on Red Hat-style Linux system one can use a script in 
/etc/rc.d/init.d to start I<spampd> (a sample script is available on the 
I<spampd> Web page @ http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm).

The options all have reasonable defaults, especially for a Postfix-centric
installation.  You may want to specify the --children option if you have an
especially beefy or weak server box because I<spampd> is a memory-hungry 
program.  Check the L<"Options"> for details on this and all other parameters.

Note that I<spampd> B<replaces> I<spamd> from the I<SpamAssassin> distribution
in function. You do not need to run I<spamd> in order for I<spampd> to work.
This has apparently been the source of some confusion, so now you know.

=head2 Postfix-specific Notes

Here is a typical setup for Postfix "advanced" content filtering as described
in the F<FILTER_README> that came with the Postfix distribution (which you 
really need to read):

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

F<FILTER_README> from the Postfix distro has more details and examples of
various setups, including how to skip the content filter for outbound mail.

Another tip for Postfix when considering what timeout values to use for
--childtimout and --satimeout options is the following command:

C<# postconf | grep timeout>

This will return a list of useful timeout settings and their values.  For 
explanations see the relevant C<man> page (smtp, smtpd, lmtp).  By default
I<spampd> is set up for the default Postfix timeout values.

=head1 Options

=over 5

=item B<--host=(ip|hostname)[:port]>

Specifies what hostname/IP and port I<spampd> listens on. By default, it listens
on 127.0.0.1 (localhost) on port 10025. 

B<Important!> You should NOT enable I<spampd> to listen on a
public interface (IP address) unless you know exactly what you're doing!

=item B<--port=n>

Specifies what port I<spampd> listens on. By default, it listens on
port 10025. This is an alternate to using the above --host=ip:port notation.

=item B<--socket=socketpath>

Specifies what UNIX socket I<spampd> listens on. If this is specified,
--host and --port are ignored.

=item B<--socket-perms=mode>

The file mode fo the created UNIX socket (see --socket) in octal
format, e.g. 700 to specify acces only for the user spampd is run as.

=item B<--relayhost=(ip|hostname)[:port]>

Specifies the hostname/IP to which I<spampd> will relay all
messages. Defaults to 127.0.0.1 (localhost). If the port is not provided, that
defaults to 25.

=item B<--relayport=n>

Specifies what port I<spampd> will relay to. Default is 25. This is an 
alternate to using the above --relayhost=ip:port notation.

=item B<--relaysocket=socketpath>

Specifies what UNIX socket spampd will relay to. If this is specified
--relayhost and --relayport will be ignored.

=item B<--user=username> or B<-u=username>

=item B<--group=groupname> or  B<-g=groupname>

Specifies the user and/or group that the proxy will run as. Default is
I<mail>/I<mail>.

=item B<--children=n> or B<-c=n>

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

=item B<--maxrequests=n>

I<spampd> works by forking child servers to handle each message. The
B<maxrequests> parameter specifies how many requests will be handled
before the child exits. Since a child never gives back memory, a large
message can cause it to become quite bloated; the only way to reclaim
the memory is for the child to exit. The default is 20.

=item B<--childtimeout=n>

This is the number of seconds to allow each child server before it times out
a transaction. In an S/LMTP transaction the timer is reset for every command. 
This timeout includes time it would take to send the message data, so it should 
not be too short.  Note that it's more likely the origination or destination
mail servers will timeout first, which is fine.  This is just a "sane" failsafe.
Default is 360 seconds (6 minutes).

=item B<--satimeout=n>

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

=item B<--pid=filename> or B<-p=filename>

Specifies a filename where I<spampd> will write its process ID so
that it is easy to kill it later. The directory that will contain this
file must be writable by the I<spampd> user. The default is
F</var/run/spampd.pid>.

=item B<--logsock=(unix|inet)> C<(new in v2.20)>

Syslog socket to use.  May be either "unix" of "inet".  Default is "unix"
except on HP-UX and SunOS (Solaris) systems which seem to prefer "inet".

=item B<--nodetach> C<(new in v2.20)>

If this option is given spampd won't detach from the console and fork into the
background. This can be useful for running under control of some daemon
management tools or when configured as a win32 service under cygrunsrv's
control.

=item B<--setsid> C<(new in v2.51)>

If this option is given spampd will fork after the bind method to release
itself from the command line and then run the POSIX::setsid() command to truly
daemonize. Only used if --nodetach isn't specified.

=item B<--maxsize=n>

The maximum message size to send to SpamAssassin, in KBytes. By default messages
over 64KB are not scanned at all, and an appropriate message is logged
indicating this.  The size includes headers and attachments (if any).

=item B<--dose>

Acronym for (d)ie (o)n (s)pamAssassin (e)rrors.  By default if I<spampd>
encounters a problem with processing the message through Spam Assassin (timeout 
or other error), it will still pass the mail on to the destination server.  If 
you specify this option however, the mail is instead rejected with a temporary 
error (code 450, which means the origination server should keep retrying to send 
it).  See the related --satimeout option, above.

=item B<--tagall> or B<-a>

Tells I<spampd> to have SpamAssassin add headers to all scanned mail,
not just spam.  By default I<spampd> will only rewrite messages which 
exceed the spam threshold score (as defined in the SA settings).  Note that
for this option to work as of SA-2.50, the I<always_add_report> and/or 
I<always_add_headers> settings in your SpamAssassin F<local.cf> need to be 
set to 1/true.

=item B<--log-rules-hit> or B<--rh>

Logs the names of each SpamAssassin rule which matched the message being 
processed.  This list is returned by SA.

=item B<--set-envelope-headers> or B<--seh> C<(new in v2.30)>

Turns on addition of X-Envelope-To and X-Envelope-From headers to the mail
being scanned before it is passed to SpamAssassin. The idea is to help SA 
process any blacklist/whitelist to/from directives on the actual 
sender/recipients instead of the possibly bogus envelope headers. This 
potentially exposes the list of all recipients of that mail (even BCC'ed ones). 
Therefore usage of this option is discouraged. 

I<NOTE>: Even though spampd tries to prevent this leakage by removing the
X-Envelope-To header after scanning, SpamAssassin itself might add headers
itself which report one or more of the recipients which had been listed in
this header.

=item B<--set-envelope-from> or B<--sef> C<(new in v2.30)>

Same as above option but only enables the addition of X-Envelope-From header.
For those that don't feel comfortable with the possible information exposure
of X-Envelope-To.  The above option overrides this one.

=item B<--auto-whitelist> or B<--aw> C<(deprecated with SpamAssassin v3+)>

This option is no longer relevant with SA version 3.0 and above, which
controls auto whitelist use via config file settings. This option is likely to
be removed in the future.  Do not use it unless you must use an older SA
version.

For SA version < 3.0, turns on the SpamAssassin global whitelist feature.  
See the SA docs. Note that per-user whitelists are not available.

B<NOTE>: B<DBBasedAddrList> is used as the storage mechanism. If you wish to use
a different mechanism (such as SQLBasedAddrList), the I<spampd> code will 
need to be modified in 2 instances (search the source for DBBasedAddrList).

=item B<--local-only> or B<-L>

Turn off all SA network-based tests (DNS, Razor, etc).

=item B<--homedir=directory>

Use the specified directory as home directory for the spamassassin process. 
Things like the auto-whitelist and other plugin (razor/pyzor) files get
written to here.
Defaul is /var/spool/spamassassin/spampd.  A good place for this is in the same
place your bayes_path SA config setting points to (if any).  Make sure this
directory is accessible to the user that spampd is running as (default: mail).
New in v2.40. Thanks to Alexander Wirt for this fix.

=item B<--saconfig=filename>

Use the specified file for SpamAssassin configuration options in addition to the
default local.cf file.  Any options specified here will override the same
option from local.cf.  Default is to not use any additional configuration file.

=item B<--debug> or B<-d>

Turns on SpamAssassin debug messages which print to the system mail log
(same log as spampd will log to).  Also turns on more verbose logging of 
what spampd is doing (new in v2).  Also increases log level of Net::Server
to 4 (debug), adding yet more info (but not too much) (new in v2.2).

=item B<--version>

Prints version information about SpamPD, Net::Server, SpamAssassin, and Perl.

=item B<--help> or B<-h> or B<-?>

Prints usage information.

=back

=head2 Deprecated Options

The following options are no longer used but still accepted for backwards
compatibility with prevoius I<spampd> versions:

=over 5

=item  B<--dead-letters>

=item  B<--heloname>

=item  B<--stop-at-threshold>

=item  B<--add-sc-header>

=item  B<--hostname>

=back

=head1 Signals

=over 5

=item HUP

Sending HUP signal to the master process will restart all the children
gracefully (meaning the currently running requests will shut down once
the request is complete).  SpamAssassin configuration is NOT reloaded.

=item TTIN, TTOU

Sending TTIN signal to the master process will dynamically increase
the number of children by one, and TTOU signal will decrease it by one.

=item INT, TERM

Sending INT or TERM signal to the master process will kill all the
children immediately and shut down the daemon.

=back

=head1 Examples

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

Spampd listens on the UNIX socket /var/run/spampd.socket with
persmissions 700 instead of a TCP port:

  spampd --socket /var/run/spampd.socket --socket-perms 700

Spampd will relay mail to /var/run/dovecot/lmtp instead of a TCP port:

  spampd --relaysocket /var/run/dovecot/lmtp

Remember that the user spampd runs as needs to have read AND write
permissions on the relaysocket!

=back

=head1 Credits

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

=head1 Copyright, License, and Disclaimer

I<spampd> is Copyright (c) 2002-2006, 2009, 2010, 2013, 2018 
by World Design Group, Inc. and Maxim Paperno.

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


=head1 Bugs

Use GitHub issue tracking: L<https://github.com/mpaperno/spampd/issues>

=head1 To Do

Figure out how to use Net::Server::PreFork because it has cool potential for
load management.  I tried but either I'm missing something or PreFork is
somewhat broken in how it works.  If anyone has experience here, please let 
me know.

Add configurable option for rejecting mail outright based on spam score.
It would be nice to make this program safe enough to sit in front of a mail 
server such as Postfix and be able to reject mail before it enters our systems.
The only real problem is that Postfix will see localhost as the connecting
client, so that disables any client-based checks Postfix can do and creates a 
possible relay hole if localhost is trusted.

=head1 See Also

perl(1), Mail::SpamAssassin(3pm), L<http://www.spamassassin.org/>, 
L<http://www.WorldDesign.com/index.cfm/rd/mta/spampd.htm>
