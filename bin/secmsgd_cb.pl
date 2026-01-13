#!/usr/bin/perl
#
# secmsg — a lightweight encrypted message relay,
#          based on a layered cryptographic stack.
#
#
# Copyright (c) 2026 C R Jervis under the terms in the accompanying LICENSE file
#
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
Getopt::Long::Configure('no_ignore_case');

use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256);

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

sub sha256_hex { unpack("H*", sha256($_[0] // '')) }

sub _rand_id {
    my $seed = join(":", time(), $$, rand(), {});
    return substr(sha256_hex($seed), 0, 16);
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

# --- Server / relay (radio net) -------------------------------------------
my $listen = $ENV{SECMSG_LISTEN} // '0.0.0.0';
my $port   = $ENV{SECMSG_PORT}   // 7337;

GetOptions(
    'l|listen=s' => \$listen,
    'p|port=i'   => \$port,
) or die "Usage: $0 [-l addr] [-p port]\n";

my $srv = _new_listen_socket(addr => $listen, port => $port, backlog => 50);
$srv->autoflush(1);

my $sel = IO::Select->new($srv);

# Connection state
my %fh_to_id;     # fileno -> random id
my %fh_to_sock;   # fileno -> fh (for iteration)

print "secmsgd listening on $listen:$port (radio net mode; proto " . PROTO_VERSION . ")\n";

sub _drop_client {
    my ($fh, $why) = @_;
    my $fn = fileno($fh);
    my $id = $fh_to_id{$fn};

    delete $fh_to_id{$fn};
    delete $fh_to_sock{$fn};

    $sel->remove($fh);
    close $fh;

    print "disconnect fn=$fn id=" . (defined $id ? $id : '-') . " reason=$why\n";
}

sub _send_err {
    my ($fh, $msg) = @_;
    eval { print $fh encode_frame('E', $msg // 'error') };
}

while (1) {
    for my $fh ($sel->can_read(0.5)) {
        if ($fh == $srv) {
            my $c = $srv->accept;
            $c->autoflush(1);
            $sel->add($c);

            my $fn = fileno($c);
            my $id = _rand_id();
            $fh_to_id{$fn} = $id;
            $fh_to_sock{$fn} = $c;

            print "connect fn=$fn id=$id\n";
            next;
        }

        my $line = <$fh>;
        if (!defined $line) {
            _drop_client($fh, "eof");
            next;
        }

        my ($type, $ver, $bytes) = eval { decode_frame($line) };
        if ($@) {
            _send_err($fh, "bad frame");
            _drop_client($fh, "protocol");
            next;
        }

        next if $type eq 'H';

        if ($type ne 'M') {
            _send_err($fh, "unsupported type");
            next;
        }

        # Client payload: "" "\0" nonce_b64 "\0" tag_hex "\0" rot13_b64ct
        my (undef, $nonce_b64, $tag_hex, $rot13_b64ct) = split(/\0/, $bytes, 4);
        if (!defined $nonce_b64 || !defined $tag_hex || !defined $rot13_b64ct) {
            _send_err($fh, "bad message payload");
            next;
        }

        my $sender_id = $fh_to_id{ fileno($fh) } // 'unknown';
        my $out = join("\0", $sender_id, $nonce_b64, $tag_hex, $rot13_b64ct);

        my $sender_fn = fileno($fh);
        for my $fn (keys %fh_to_sock) {
            next if $fn == $sender_fn;
            my $dest = $fh_to_sock{$fn};
            next unless $dest;
            print $dest encode_frame('M', $out);
        }
    }
}
