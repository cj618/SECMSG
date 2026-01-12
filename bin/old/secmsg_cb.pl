#!/usr/bin/perl
#
# secmsg — a lightweight encrypted message relay,
#          based on a layered cryptographic stack.
#
#
# Copyright (c) 2026 C R Jervis
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

use strict;
use warnings;

use Getopt::Long qw(GetOptions);
Getopt::Long::Configure('no_ignore_case');
use IO::Select;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256 hmac_sha256);

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

sub _rand_bytes {
    my ($n) = @_;
    $n //= 16;
    my $buf = '';
    if (open my $fh, '<', '/dev/urandom') {
        read($fh, $buf, $n);
        close $fh;
        return $buf if length($buf) == $n;
    }
    # Fallback: not cryptographically strong, but keeps the POC portable.
    for (1..$n) { $buf .= chr(int(rand(256))); }
    return $buf;
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

# --- "Layered cryptographic stack" (POC) ----------------------------------
# NOTE: This is intentionally lightweight and self-contained (no XS deps).
# It provides confidentiality + tamper detection (HMAC), but it is not meant
# to be presented as modern, reviewed cryptography.
#
# Envelope format (bytes in frame payload):
#   sender_id "\0" nonce_b64 "\0" tag_hex "\0" ct_b64
#
# tag = HMAC-SHA256(key, nonce || ciphertext)   (hex-encoded)
# keystream = SHA256(key || nonce || counter) repeated, XOR with plaintext
#
sub _xor_stream {
    my ($key, $nonce, $data) = @_;
    my $out = '';
    my $i = 0;
    my $off = 0;
    while ($off < length($data)) {
        my $block = sha256($key . $nonce . pack("N", $i));
        my $take = length($data) - $off;
        $take = 32 if $take > 32;
        my $chunk = substr($data, $off, $take);
        my $mask  = substr($block, 0, $take);
        $out .= ($chunk ^ $mask);
        $off += $take;
        $i++;
    }
    return $out;
}

sub seal_message {
    my (%args) = @_;
    my $key = $args{key} // die "seal_message: missing key\n";
    my $pt  = $args{plaintext} // '';
    my $nonce = _rand_bytes(12);
    my $ct = _xor_stream($key, $nonce, $pt);
    my $tag = hmac_sha256($nonce . $ct, $key);  # bytes
    my $tag_hex = unpack("H*", $tag);
    return ($nonce, $tag_hex, $ct);
}

sub open_message {
    my (%args) = @_;
    my $key   = $args{key}   // die "open_message: missing key\n";
    my $nonce = $args{nonce} // die "open_message: missing nonce\n";
    my $tag_hex = $args{tag_hex} // die "open_message: missing tag_hex\n";
    my $ct    = $args{ciphertext} // '';

    my $want = unpack("H*", hmac_sha256($nonce . $ct, $key));
    return (0, undef) if lc($want) ne lc($tag_hex);

    my $pt = _xor_stream($key, $nonce, $ct);
    return (1, $pt);
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
print "Commands:\n";
print "  <text>        transmit encrypted text to the net\n";
print "  /quit         exit\n";
print "Flags:\n";
print "  -v            show BACKGROUND SIGNAL for traffic you can't decrypt\n\n";
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

            my ($sender_id, $nonce_b64, $tag_hex, $ct_b64) = split(/\0/, $bytes, 4);
            next unless defined $sender_id && defined $nonce_b64 && defined $tag_hex && defined $ct_b64;

            my $nonce = eval { decode_base64($nonce_b64) };
            my $ct    = eval { decode_base64($ct_b64) };
            if ($@ || !defined($nonce) || !defined($ct)) {
                if ($verbose) {
                    print "\nBACKGROUND SIGNAL\n";
                    _prompt();
                }
                next;
            }

            my ($ok, $pt) = open_message(
                key        => $key_str,
                nonce      => $nonce,
                tag_hex    => $tag_hex,
                ciphertext => $ct,
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

        my ($nonce, $tag_hex, $ct) = seal_message(
            key       => $key_str,
            plaintext => $in,
        );

        my $payload = join("\0",
            "", # sender_id slot is filled by server; client leaves blank
            encode_base64($nonce, ''),
            $tag_hex,
            encode_base64($ct, ''),
        );

        print $sock encode_frame('M', $payload);
        _prompt();
    }
}
