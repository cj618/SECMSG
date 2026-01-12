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
use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256_hex);
use Time::HiRes qw(time);

# --- Compatibility / portability ------------------------------------------
sub _have_module {
    my ($m) = @_;
    eval "require $m; 1" or return 0;
    return 1;
}

sub _new_tcp_socket {
    my (%args) = @_;
    my ($host, $port) = @args{qw(host port)};
    die "missing host/port\n" unless defined $host && defined $port;

    if (_have_module('IO::Socket::IP')) {
        IO::Socket::IP->import();
        my $sock = IO::Socket::IP->new(
            PeerHost => $host,
            PeerPort => $port,
            Proto    => 'tcp',
        );
        return $sock if $sock;
        die "connect $host:$port (IO::Socket::IP): $!\n";
    } else {
        require IO::Socket::INET;
        my $sock = IO::Socket::INET->new(
            PeerAddr => $host,
            PeerPort => $port,
            Proto    => 'tcp',
        );
        return $sock if $sock;
        die "connect $host:$port (IO::Socket::INET): $!\n";
    }
}

my $TERM_RL;
sub _readline {
    my ($prompt) = @_;
    $prompt //= '';
    if (!defined $TERM_RL && _have_module('Term::ReadLine')) {
        Term::ReadLine->import();
        $TERM_RL = Term::ReadLine->new('secmsg');
    }
    if ($TERM_RL) {
        return $TERM_RL->readline($prompt);
    } else {
        print $prompt;
        return <STDIN>;
    }
}

# --- Framing (Base64 line frames) -----------------------------------------
use constant PROTO_VERSION => 1;

sub encode_frame {
    my ($type, $bytes, $version) = @_;
    $version //= PROTO_VERSION;
    die "encode_frame: type must be 1 char\n" unless defined($type) && length($type) == 1;
    $bytes //= '';
    my $b64 = encode_base64($bytes, ''); # no newlines
    return "$type $version $b64\n";
}

sub decode_frame {
    my ($line) = @_;
    die "decode_frame: no line\n" unless defined $line;
    chomp($line);
    my ($type, $version, $b64) = split(/ /, $line, 3);
    die "decode_frame: bad frame\n" unless defined($type) && defined($version) && defined($b64);
    die "decode_frame: bad type\n" unless length($type) == 1;
    die "decode_frame: bad version\n" unless $version =~ /^\d+$/;
    my $bytes = decode_base64($b64);
    return ($type, int($version), $bytes);
}

sub new_msg_id {
    my $seed = join(":", time(), $$, rand(), {});
    return sha256_hex($seed);
}

# --- Client ----------------------------------------------------------------
my $server = $ENV{SECMSG_SERVER} // '127.0.0.1:7337';
my $user   = $ENV{SECMSG_USER}   // ($ENV{USER} // 'anon');

GetOptions(
    's|server=s' => \$server,
    'u|user=s'   => \$user,
) or die "Usage: $0 [-s host:port] [-u user]\n";

my ($host, $port) = split(/:/, $server, 2);
die "Bad -s host:port\n" unless $host && $port && $port =~ /^\d+$/;

my $sock = _new_tcp_socket(host => $host, port => $port);
$sock->autoflush(1);

# Control frames are plaintext for now (scaffold).
print $sock encode_frame('H', "secmsg-client;proto=" . PROTO_VERSION);
print $sock encode_frame('A', $user);

my $sel = IO::Select->new($sock);

print "Connected to $server as $user\n";
print "Commands: /msg <user> <text>, /join <chan>, /leave <chan>, /quit\n\n";

while (1) {
    # Receive any pending frames (non-blocking).
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
            } elsif ($type eq 'A') {
                print "[auth] $bytes\n";
            } elsif ($type eq 'M') {
                # Scaffold payload: "from\0to\0body"
                my ($from, $to, $body) = split(/\0/, $bytes, 3);
                $from //= '?';
                $to   //= '?';
                $body //= '';
                print "<$from> $body\n";
            } else {
                # ignore
            }
        }
    }

    my $line = _readline('secmsg> ');
    last unless defined $line;
    $line =~ s/\r?\n$//;
    next if $line =~ /^\s*$/;

    if ($line =~ m{^/quit\b}i) {
        last;
    } elsif ($line =~ m{^/msg\s+(\S+)\s+(.+)$}i) {
        my ($to, $body) = ($1, $2);
        my $payload = join("\0", $user, $to, $body);
        print $sock encode_frame('M', $payload);
    } elsif ($line =~ m{^/join\s+(\S+)$}i) {
        print "[note] channels are not implemented in this scaffold yet.\n";
    } elsif ($line =~ m{^/leave\s+(\S+)$}i) {
        print "[note] channels are not implemented in this scaffold yet.\n";
    } else {
        print "Unknown command. Use: /msg <user> <text> or /quit\n";
    }
}

close $sock;
exit 0;
