#!/usr/bin/perl

#
# secmsgd — relay daemon for secmsg.
#
# Copyright (c) 2026, C R Jervis. 
# Released under the BSD License. See LICENSE file for details.
#
#
# The server is intentionally minimal and does not decrypt
# message payloads. It routes opaque frames between clients.
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);

# --- Compatibility / portability ------------------------------------------
sub _have_module {
    my ($m) = @_;
    eval "require $m; 1" or return 0;
    return 1;
}

sub _new_listen_socket {
    my (%args) = @_;
    my ($addr, $port, $backlog) = @args{qw(addr port backlog)};
    $backlog //= 20;

    if (_have_module('IO::Socket::IP')) {
        IO::Socket::IP->import();
        my $srv = IO::Socket::IP->new(
            LocalHost => $addr,
            LocalPort => $port,
            Proto     => 'tcp',
            Listen    => $backlog,
            ReuseAddr => 1,
        );
        return $srv if $srv;
        die "listen $addr:$port (IO::Socket::IP): $!\n";
    } else {
        require IO::Socket::INET;
        my $srv = IO::Socket::INET->new(
            LocalAddr => $addr,
            LocalPort => $port,
            Proto     => 'tcp',
            Listen    => $backlog,
            ReuseAddr => 1,
        );
        return $srv if $srv;
        die "listen $addr:$port (IO::Socket::INET): $!\n";
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

# --- Server / relay --------------------------------------------------------
my $listen = $ENV{SECMSG_LISTEN} // '0.0.0.0';
my $port   = $ENV{SECMSG_PORT}   // 7337;

GetOptions(
    'l|listen=s' => \$listen,
    'p|port=i'   => \$port,
) or die "Usage: $0 [-l addr] [-p port]\n";

my $srv = _new_listen_socket(addr => $listen, port => $port, backlog => 20);
$srv->autoflush(1);

my $sel = IO::Select->new($srv);

# State
my %fh_to_user;  # fileno -> username
my %user_to_fh;  # username -> filehandle

print "secmsgd listening on $listen:$port (proto " . PROTO_VERSION . ")\n";

sub _drop_client {
    my ($fh, $why) = @_;
    my $fn = fileno($fh);
    my $u  = $fh_to_user{$fn};
    delete $fh_to_user{$fn};
    if (defined $u && exists $user_to_fh{$u} && fileno($user_to_fh{$u}) == $fn) {
        delete $user_to_fh{$u};
    }
    $sel->remove($fh);
    close $fh;
    print "disconnect fn=$fn user=" . (defined $u ? $u : '-') . " reason=$why\n";
}

while (1) {
    for my $fh ($sel->can_read(0.5)) {
        if ($fh == $srv) {
            my $c = $srv->accept;
            $c->autoflush(1);
            $sel->add($c);
            print "connect fn=" . fileno($c) . "\n";
            next;
        }

        my $line = <$fh>;
        if (!defined $line) {
            _drop_client($fh, "eof");
            next;
        }

        my ($type, $ver, $bytes) = eval { decode_frame($line) };
        if ($@) {
            print $fh encode_frame('E', "bad frame");
            _drop_client($fh, "protocol");
            next;
        }

        if ($type eq 'H') {
            next;
        }

        if ($type eq 'A') {
            my $user = $bytes // '';
            $user =~ s/[^A-Za-z0-9_\-\.@]//g;
            $user = substr($user, 0, 48) if length($user) > 48;

            if (!$user) {
                print $fh encode_frame('E', "bad username");
                _drop_client($fh, "auth");
                next;
            }
            if (exists $user_to_fh{$user}) {
                print $fh encode_frame('E', "user already connected");
                _drop_client($fh, "auth");
                next;
            }

            my $fn = fileno($fh);
            $fh_to_user{$fn} = $user;
            $user_to_fh{$user} = $fh;

            print $fh encode_frame('A', "ok");
            print "auth fn=$fn user=$user\n";
            next;
        }

        if ($type eq 'M') {
            my $fn = fileno($fh);
            my $from = $fh_to_user{$fn};

            if (!defined $from) {
                print $fh encode_frame('E', "not authenticated");
                next;
            }

            # Scaffold payload: "from\0to\0body"
            my (undef, $to, $body) = split(/\0/, $bytes, 3);
            $to //= '';

            if (!$to || !exists $user_to_fh{$to}) {
                print $fh encode_frame('E', "unknown recipient");
                next;
            }

            my $out = join("\0", $from, $to, ($body // ''));
            my $dest = $user_to_fh{$to};
            print $dest encode_frame('M', $out);
            next;
        }

        # Future: J/L (channels), P (ping), rate limiting, etc.
    }
}

