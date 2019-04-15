#! /usr/bin/perl

# $Id: assassind,v 1.1 2002/04/28 19:08:22 dave Exp $
# $Source: /var/cvs/src/assassind/assassind,v $
# Copyright (c) 2002 Dave Carrigan

package Assassind;

use strict;
use Net::Server::PreFork;
use Net::SMTP::Server::Client;
use IO::File;
use Getopt::Long;
use Data::Dumper;
use Mail::SpamAssassin;
use Mail::SpamAssassin::NoMailAudit;
#use Mail::Audit;
use Net::SMTP;
use Error qw(:try);

our @ISA = qw(Net::Server::PreFork);
our $VERSION = '1.0.1';

sub dead_letter {
  my($self, $client, $message) = @_;

  my $filename = join("/", $self->{assassind}->{dead_letters},
		      sprintf("assassind.%d.%d.%f.dead", time(), $$, rand));

  my $dead = IO::File->new;
  unless ($dead->open(">$filename")) {
    $self->log(0, "Can't open dead letter file $filename: $!");
    return;
  }
  chmod 0600, $filename;

  try {
    if (defined $message) {
      $dead->print($message, "\n") or
	throw Error -text => "Can't print to dead letter: $!";
    }
    foreach (@{$client->{TO}}) {
      $dead->print("TO $_\n") or
	throw Error -text => "Can't print to dead letter: $!";
    }
    $dead->print("FROM ", $client->{FROM}, "\n") or
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
    
    # Skip processing message over 256K (need to make this an option)
    if ( length($message) < ($self->{assassind}->{maxsize} * 1024) ) {
    
		my @msglines = split (/\r?\n/, $message);
		my $arraycont = @msglines; for(0..$arraycont) { $msglines[$_] .= "\r\n"; }
		# Audit the message
	    my $mail = Mail::SpamAssassin::NoMailAudit->new (
	                            data => \@msglines,
	                            add_From_line => 0
	                     );

	    my $assassin = $self->{assassind}->{assassin};
	    # Check spamminess and rewrite mail if high spam factor or option -a (tag All)
	    my $status = $assassin->check($mail);
		if ( $status->is_spam || $self->{assassind}->{tagall} ) { 
			$status->rewrite_mail; 
		}

	    # Build the message to send back
	    $msg_resp = join '',$mail->header,"\n",@{$mail->body};
    
		# Log what we did, FWIW
	    my $was_it_spam;
	    if($status->is_spam) { $was_it_spam = 'identified spam'; } else { $was_it_spam = 'clean message'; }
	    my $msg_score = int($status->get_hits);
	    my $msg_threshold = int($status->get_required_hits);
	    #$current_user ||= '(unknown)';
		$self->log(2, "$was_it_spam ($msg_score/$msg_threshold) in ". sprintf("%3d", time - $start) ." seconds.");

	    $status->finish();
    
    } else {
    
    	$msg_resp = $message;
		$self->log(2, "Scanning skipped due to size (". length($message) .")");

    }

#  my $message = [split(/\r?\n/, $client->{MSG})];
#  my $auditor = Mail::Audit->new(data => $message);
#  my $assassin = $self->{assassind}->{assassin};
#  my $status = $assassin->check($auditor);

#  my $score = $status->get_hits;
#  my $spam_color = 'red';
#  foreach my $color (qw(green blue yellow orange)) {
#    if ($score <= $self->{assassind}->{$color}) {
#      $spam_color = $color;
#      last;
#    }
#  }

#  $auditor->put_header('X-Spam-Color', $spam_color);
#  my $is_spam =$status->is_spam? 'Yes' : 'No';
#  $auditor->put_header('X-Spam-Status',
#		       sprintf("%s, hits=%.2f required=%.2f tests=%s",
#			       $is_spam,
#			       $status->get_hits,
#			       $status->get_required_hits,
#			       $status->get_names_of_tests_hit));

#  if ($spam_color ne 'green') {
#    foreach (split(/\n/, $status->get_report)) {
#      $auditor->put_header('X-Spam-Report', $_);
#    }
#  }

#  $status->finish;

  my $smtp = Net::SMTP->new($self->{assassind}->{relayhost}, Hello => $self->{assassind}->{heloname});
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
#    $smtp->data;
    throw Error -text => sprintf("Relay failed; server said %s %s",
				 $smtp->code, $smtp->message) unless $smtp->ok;

#    $smtp->datasend($auditor->header);
#    $smtp->datasend("\n");
#    foreach (@{$auditor->body}) {
#      $smtp->datasend($_ . "\r\n");
#    }
#    $smtp->dataend;
#    throw Error -text => sprintf("Relay failed; server said %s %s",
#				 $smtp->code, $smtp->message) unless $smtp->ok;

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
    $self->log(4, "Received message");
    $SIG{TERM} = sub {
      $self->dead_letter($client, "Process interrupted by SIGTERM");
    };
    $self->relay_message($client);
    $SIG{TERM} = sub { exit 0; };
  } else {
    $self->log(1, "An error occurred while receiving message");
  }
  $self->{assassind}->{instance} = 1 unless defined $self->{assassind}->{instance};
  exit 0 if $self->{assassind}->{instance} > $self->{assassind}->{maxrequests}++;
}

my $relayhost = 'localhost';
my $host = 'localhost';
my $port = 2025;
my $maxrequests = 20;
my $dead_letters = '/var/tmp';
my $pidfile = '/var/run/assassind.pid';
my $user = 'mail';
my $group = 'mail';
my $tagall = 0;
my $maxsize = 256;
my $heloname = 'spamfilter.localdomain';
# my $auto_whitelist = 0;
# my $stop_at_threshold = 0;

my %options = (port => \$port,
	       host => \$host,
	       relayhost => \$relayhost,
	       'dead-letters' => \$dead_letters,
	       pid => \$pidfile,
	       user => \$user,
	       group => \$group,
	       maxrequests => \$maxrequests,
	       tagall => \$tagall,
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
			   'tagall=i',
			   'maxsize=i',
			   'heloname=s',
			   'auto-whitelist',
			   'stop-at-threshold',
			   'debug',
			   'help');
usage(0) if $options{help};

my $assassin = Mail::SpamAssassin->new({
						'dont_copy_prefs' => 1,
						'stop_at_threshold' => $options{'stop_at_threshold'} || 0,
  						'debug' => $options{'debug'} || 0 });
						
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
		    assassind => {maxrequests => $maxrequests,
				  relayhost => $relayhost,
				  dead_letters => $dead_letters,
				  tagall => $tagall,
				  maxsize => $maxsize,
				  assassin => $assassin,
				  heloname => $heloname,
				 },
		   }, 'Assassind';
$server->run;

sub usage {
  print <<EOF ;
usage: $0 [ --port=port ]

Options:
  --port=n                 Port to listen on. Defaults to 2025.
  --host=host              Hostname/IP to listen on. Default is localhost.
  --relayhost=host[:port]  Host to relay mail to. Defaults to localhost.
  --maxrequests=n          Maximum requests that each child can process before exiting.
                           Defaults to 20.
  --pid=filename           Store the daemon's process ID in this file.
  --user=username          Specifies the user that the daemon runs as. Default is mail.
  --group=groupname        Specifies the group that the daemon runs as. Default is mail.
  --dead-letters=path      Path to store letters that couldn't be relayed.
                           Defaults to /tmp.
  --tagall=n               Tag all messages not just spam (specify 1/0). Defaults to 0.
  --maxsize=n              Maximum size of mail to scan (in KB). Defaults to 256.
  --heloname=hostname      Hostname to use in HELO command when sending mail. 
                           Defaults to 'spamfilter.localdomain'.
  
  --auto-whitelist         Use the global SA auto-whitelist feature.
  --stop-at-threshold      Use SA feature to stop scanning once threshold is reached.
  --debug                  Turn on SA debugging.
						   
  --help                   This message
EOF
  exit shift;
}

=pod

=head1 NAME

assassind - Spam filtering SMTP proxy that uses SpamAssassin

=head1 SYNOPSIS

B<assassind>
[B<--port=n>]
[B<--host=host>]
[B<--relayhost=hostname[:port]>]
[B<--user=username>]
[B<--group=groupname>]
[B<--maxrequests=n>]
[B<--dead-letters=/path>]
[B<--pid=filename>]
[B<--tagall=n>]
[B<--maxsize=n>]
[B<--auto-whitelist>]
[B<--stop-at-threshold>]
[B<--debug>]
[B<--heloname=hostname>]

B<assassind> B<--help>

=head1 DESCRIPTION

I<assassind> is a relaying SMTP proxy that filters spam using
SpamAssassin. The proxy is designed to be robust in the face of
exceptional errors, and will (hopefully) never lose a message.

I<assassind> is meant to be used as a system-wide message processor, so
the proxy does not make any changes to existing message contents or
headers; instead choosing just to add three headers of its own, which
end users can use to make decisions about filtering (or not filtering)
their spam.

The most important header that I<assassind> adds is the B<X-Spam-Color>
header. This header will have one of five values: I<green>, I<blue>,
I<yellow>, I<orange> and I<red>. Green messages are very unlikely to be
spam, while red messages are almost guaranteed to be spam. You can use
this header as the basis for your own message filtering rules, using any
common message filtering system (procmail, sieve, etc.).

I<assassind> also adds a B<X-Spam-Status> filter. This header is the
same as the header generated by the standard SpamAssassin message
processor, and contains the message's SpamAssassin score and other
information.

Finally, I<assassind> adds one or more B<X-Spam-Report> headers, which
contain a plain-text report of the rules that SpamAssassin used to
assign the message its score.

I<assassind> logs all aspects of its operation to syslog(8), using the
mail syslog facility.

=head1 OPERATION

I<assassind> is meant to operate as a mail relay that sits between the
Internet and your internal mail system. The three most common
configurations include

=over 5

=item Running between firewall and internal mail server

The firewall would be configured to forward all of its mail to the port
that I<assassind> listens on, and I<assassind> would relay its messages
to port 25 of your internal server. I<assassind> could either run on its
own host (and listen on any port) or it could run on the mail server
(and listen on any port except port 25). This is I<assassind> default
mode of operation.

=item Running on the firewall with an internal mail server

I<assassind> would accept messages on port 25 and forward them to the
mail server that is also listening on port 25. Note that I<assassind>
does not do anything other than check for spam, so it is not suitable as
an anti-relay system. If your current mail system is configured
correctly for anti-relaying, it should continue to work correctly in
this configuration, but you may want to verify this using one of the
standard open-relay blackhole testing systems.

=item Running on the mail server, which is not behind a firewall

In this configuration I<assassind> would listen on port 25, while your
mail server would be configured to listen on some other port.

=back

OPTIONS

=over 5

=item B<--port=n>

Specifies what port I<assassind> listens on. By default, it listens on
port 2025.

=item B<--relayhost=hostname[:port]>

Specifies the hostname where I<assassind> will relay all
messages. Defaults to I<localhost>. If the port is not provided, that
defaults to 25.

=item B<--user=username>
=item B<--group=groupname>

Specifies the user and group that the proxy will run as. Default is
I<mail>/I<mail>.

=item B<--maxrequests=n>

I<assassind> works by forking child servers to handle each message. The
B<maxrequests> parameter specifies how many requests will be handled
before the child exits. Since a child never gives back memory, a large
message can cause it to become quite bloated; the only way to reclaim
the memory is for the child to exit. The default is 20.

=item B<--dead-letters=/path>

Specifies the directory where I<assassind> will store any message that
it fails to deliver. The default is F</var/tmp>. You should periodically
examine this directory to see if there are any messages that couldn't be
delivered.

B<Important!> This path should not be on the same partition as your mail
server's message spool, because if your mail server rejects a message
because of a full disk, I<assassind> will not be able to save the
message, and it will be lost.

=item B<--pid=filename>

Specifies a filename where I<assassind> will write its process ID so
that it is easy to kill it later. The directory that will contain this
file must be writable by the I<assassind> user. The default is
F</var/run/assassind/assassind.pid>.

=item B<--green=n>
=item B<--blue=n>
=item B<--yellow=n>
=item B<--orange=n>

Specifies the spam score thresholds for each color. The defaults are 5,
6, 10 and 20. Anything over 20 will have a color of red.

=back

=head1 EXAMPLES

=over 5

=item Running between firewall and internal mail server

This is I<assassind>'s default configuration, where it listens on port
2025 on the same host as the mail server.

  assassind

=item Running on the firewall with an internal mail server

  assassind --port=25 --relayhost=internal.serv.er

=item Running on the mail server, which is not behind a firewall

This scenario assumes that the real mail server is running on port 2025
of the same host.

  assassind --port=25 --relayhost=localhost:2025

=back

=head1 AUTHOR

Dave Carrigan, <dave@rudedog.org>

This program is Copyright © 2002, Dave Carrigan. All rights
reserved. This program is free software; you can redistribute it and/or
modify it under the same terms as Perl.

This program is distributed "as is", without warranty of any kind,
either expressed or implied, including, but not limited to, the implied
warranties of merchantability and fitness for a particular purpose.  The
entire risk as to the quality and performance of the program is with
you. Should the program prove defective, you assume the cost of all
necessary servicing, repair or correction.


=head1 SEE ALSO

perl(1), Spam::Assassin(3), http://www.rudedog.org/assassind/

=head1 BUGS

Due to the nature of Perl's SMTP::Server module, a SMTP message is
stored completely in memory. However, as soon as the module receives its
entire message data from the SMTP client, it returns a 250, signifying
to the client that the message has been delivered. However, this means
that there is a period of time where the message is vulnerable to being
lost if the I<assassind> process is killed before it has relayed or
saved the message. Caveat Emptor!
