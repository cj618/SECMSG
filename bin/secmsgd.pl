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
use IO::Socket::IP;
use IO::Select;

use FindBin;
use lib "$FindBin::Bin/../lib";
use SecMsg qw(encode_frame decode_frame PROTO_VERSION);

my $listen = '0.0.0.0';
my $port   = 7337;

GetOptions(
    'l|listen=s' => \$listen,
    'p|port=i'   => \$port,
) or die "Usage: $0 [-l addr] [-p port]\n";

my $srv = IO::Socket::IP->new(
    LocalHost => $listen,
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 20,
    ReuseAddr => 1,
) or die "listen $listen:$port: $!\n";

$srv->autoflush(1);

my $sel = IO::Select->new($srv);

# State
my %fh_to_user;     # fileno -> username
my %user_to_fh;     # username -> filehandle

print "secmsgd listening on $listen:$port (proto " . PROTO_VERSION . ")\n";

sub drop_client {
    my ($fh, $why) = @_;
    my $fn = fileno($fh);
    my $u  = $fh_to_user{$fn};
    delete $fh_to_user{$fn};
    if (defined $u && $user_to_fh{$u} && fileno($user_to_fh{$u}) == $fn) {
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
            drop_client($fh, "eof");
            next;
        }

        my ($type, $ver, $bytes) = eval { decode_frame($line) };
        if ($@) {
            print $fh encode_frame('E', "bad frame");
            drop_client($fh, "protocol");
            next;
        }

        if ($type eq 'H') {
            # hello is informational
            next;
        }

        if ($type eq 'A') {
            my $user = $bytes;
            $user =~ s/[^A-Za-z0-9_\-\.@]//g;
            $user = substr($user, 0, 48) if length($user) > 48;

            if (!$user) {
                print $fh encode_frame('E', "bad username");
                drop_client($fh, "auth");
                next;
            }
            if (exists $user_to_fh{$user}) {
                print $fh encode_frame('E', "user already connected");
                drop_client($fh, "auth");
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

        # ignore other types for now
    }
}
