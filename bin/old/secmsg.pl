#!/usr/bin/perl

#
# secmsg — client for a lightweight encrypted message relay,
#          based on a layered cryptographic stack.
#
# Copyright (c) 2026, C R Jervis.
# Released under the BSD License. See LICENSE file for details. 
#
# The client handles encryption, message formatting, and display.
# All message payloads are encrypted before transmission.
#
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use IO::Socket::IP;
use IO::Select;
use Term::ReadLine;

use FindBin;
use lib "$FindBin::Bin/../lib";
use SecMsg qw(encode_frame decode_frame PROTO_VERSION new_msg_id);

my $server = '127.0.0.1:7337';
my $user   = $ENV{USER} // 'anon';

GetOptions(
    's|server=s' => \$server,
    'u|user=s'   => \$user,
) or die "Usage: $0 [-s host:port] [-u user]\n";

my ($host, $port) = split(/:/, $server, 2);
die "Bad -s host:port\n" unless $host && $port && $port =~ /^\d+$/;

my $sock = IO::Socket::IP->new(
    PeerHost => $host,
    PeerPort => $port,
    Proto    => 'tcp',
) or die "connect $server: $!\n";

$sock->autoflush(1);

# Send HELLO and AUTH as plaintext control frames for now.
print $sock encode_frame('H', "secmsg-client;proto=" . PROTO_VERSION);
print $sock encode_frame('A', $user);

my $sel = IO::Select->new($sock);

my $term = Term::ReadLine->new('secmsg');
print "Connected to $server as $user\n";
print "Commands: /msg <user> <text>, /quit\n\n";

while (1) {
    # Non-blocking check for inbound frames.
    if (my @ready = $sel->can_read(0)) {
        for my $fh (@ready) {
            my $line = <$fh>;
            if (!defined $line) {
                print "\n[disconnected]\n";
                exit 0;
            }
            my ($type, $ver, $bytes) = eval { decode_frame($line) };
            if ($@) {
                print "[protocol error] $@\n";
                next;
            }

            if ($type eq 'E') {
                print "[server error] $bytes\n";
            } elsif ($type eq 'M') {
                # For scaffold: server sends "from\0to\0body"
                my ($from, $to, $body) = split(/\0/, $bytes, 3);
                $from //= '?';
                $to   //= '?';
                $body //= '';
                print "<$from> $body\n";
            } elsif ($type eq 'A') {
                print "[auth] $bytes\n";
            } else {
                # ignore or print
                # print "[recv $type] $bytes\n";
            }
        }
    }

    my $line = $term->readline('secmsg> ');
    last unless defined $line;
    $line =~ s/\r?\n$//;

    next if $line =~ /^\s*$/;

    if ($line =~ m{^/quit\b}i) {
        last;
    }

    if ($line =~ m{^/msg\s+(\S+)\s+(.+)$}i) {
        my ($to, $body) = ($1, $2);
        my $payload = join("\0", $user, $to, $body);
        print $sock encode_frame('M', $payload);
        next;
    }

    print "Unknown command. Use: /msg <user> <text> or /quit\n";
}

close $sock;
exit 0;
