#!/usr/bin/perl
#
# secmsg — a lightweight encrypted message relay,
#          based on a layered cryptographic stack.
#
#
# Copyright (c) 2026 C R Jervis under the terms in the accompanying LICENSE file
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
Getopt::Long::Configure('no_ignore_case'); # allow -k and -K to differ

use IO::Select;

use FindBin;
use lib "$FindBin::Bin/lib";

use SecMsg::Crypto qw(seal_message open_message);
use MIME::Base64 qw(decode_base64);

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

# --- Framing (Base64 line frames) -----------------------------------------
use MIME::Base64 qw(encode_base64 decode_base64);
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

# --- Counter party mapping -------------------------------------------------
my %peer_label;         # sender_id -> label number
my $next_label = 1;

sub counterparty_name {
    my ($sender_id) = @_;
    $sender_id //= 'unknown';
    if (!exists $peer_label{$sender_id}) {
        $peer_label{$sender_id} = $next_label;
        $next_label++;
        $next_label = 1 if $next_label > 5; # per spec: [1..5]
    }
    return "Counter Party " . $peer_label{$sender_id};
}

# --- Client ----------------------------------------------------------------
my $server  = $ENV{SECMSG_SERVER} // '127.0.0.1:7337';
my $key_str = $ENV{SECMSG_KEY};        # optional
my $keyfile = undef;
my $verbose = 0;

GetOptions(
    's|server=s' => \$server,
    'k|key=s'    => \$key_str,
    'K|keyfile=s'=> \$keyfile,
    'v|verbose'  => \$verbose,
) or die "Usage: $0 [-s host:port] (-k key | -K keyfile) [-v]\n";

if (!defined($key_str) && defined($keyfile)) {
    open my $kf, '<', $keyfile or die "open keyfile: $!\n";
    local $/;
    $key_str = <$kf>;
    close $kf;
    $key_str //= '';
    $key_str =~ s/\r?\n$//;
}

die "You must provide a shared key via -k or -K.\n"
    unless defined($key_str) && length($key_str);

my ($host, $port) = split(/:/, $server, 2);
die "Bad -s host:port\n" unless $host && $port && $port =~ /^\d+$/;

my $sock = _new_tcp_socket(host => $host, port => $port);
$sock->autoflush(1);

# Hello (informational)
print $sock encode_frame('H', "secmsg-client;mode=radio;proto=" . PROTO_VERSION);

my $sel = IO::Select->new();
$sel->add($sock);
$sel->add(\*STDIN);

sub _prompt { print "secmsg> "; }

print "Connected to $server (radio net mode)\n";
print "Enter text to transmit to the net. /quit to exit.\n";
print "Traffic you cannot decrypt is ignored by default; use -v to see BACKGROUND SIGNAL.\n\n";
_prompt();

while (1) {
    for my $fh ($sel->can_read(0.5)) {
        if ($fh == $sock) {
            my $line = <$sock>;
            if (!defined $line) {
                print "\n[disconnected]\n";
                exit 0;
            }
            my ($type, $ver, $bytes) = eval { decode_frame($line) };
            if ($@) {
                print "\n[protocol error] $@\n";
                _prompt();
                next;
            }

            if ($type eq 'E') {
                print "\n[server error] $bytes\n";
                _prompt();
                next;
            }

            next unless $type eq 'M';

            my ($sender_id, $nonce_b64, $tag_hex, $rot13_b64ct) = split(/\0/, $bytes, 4);
            next unless defined $sender_id && defined $nonce_b64 && defined $tag_hex && defined $rot13_b64ct;

            my ($ok, $pt) = open_message(
                key          => $key_str,
                nonce_b64     => $nonce_b64,
                tag_hex       => $tag_hex,
                rot13_b64ct   => $rot13_b64ct,
            );

            if ($ok) {
                my $name = counterparty_name($sender_id);
                $pt =~ s/\r?\n$//;
                print "\n<$name> $pt\n";
            } else {
                print "\nBACKGROUND SIGNAL\n" if $verbose;
            }

            _prompt();
            next;
        }

        # User input
        my $in = <STDIN>;
        if (!defined $in) {
            print "\n";
            exit 0;
        }
        $in =~ s/\r?\n$//;
        next if $in =~ /^\s*$/ && _prompt();

        if ($in =~ m{^/quit\b}i) {
            print "\n";
            exit 0;
        }

        my ($nonce_b64, $tag_hex, $rot13_b64ct) = seal_message(
            key       => $key_str,
            plaintext => $in,
        );

        my $payload = join("\0",
            "", # sender_id slot is filled by server; client leaves blank
            $nonce_b64,
            $tag_hex,
            $rot13_b64ct,
        );

        print $sock encode_frame('M', $payload);
        _prompt();
    }
}
