\
package SecMsg;

use strict;
use warnings;
use Exporter 'import';

use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256_hex);
use Carp qw(croak);

our $VERSION = '0.0';

# Export a small, stable surface area for now.
our @EXPORT_OK = qw(
    PROTO_VERSION
    encode_frame decode_frame
    new_msg_id
);

use constant PROTO_VERSION => 1;

# Base64 line frames:
#   <TYPE> SP <VERSION> SP <BASE64(BYTES)>\n
sub encode_frame {
    my ($type, $bytes, $version) = @_;
    $version //= PROTO_VERSION;

    croak "encode_frame: type must be 1 char" unless defined($type) && length($type) == 1;
    $bytes //= '';

    my $b64 = encode_base64($bytes, ''); # no newlines
    return "$type $version $b64\n";
}

sub decode_frame {
    my ($line) = @_;
    croak "decode_frame: no line" unless defined $line;

    chomp($line);
    my ($type, $version, $b64) = split(/ /, $line, 3);

    croak "decode_frame: bad frame (missing fields)" unless defined($type) && defined($version) && defined($b64);
    croak "decode_frame: bad type" unless length($type) == 1;
    croak "decode_frame: bad version" unless $version =~ /^\d+$/;

    my $bytes = eval { decode_base64($b64) };
    croak "decode_frame: base64 decode failed" if $@;

    return ($type, int($version), $bytes);
}

# POC message id: cheap deterministic-ish random via time + pid + rand, hashed.
sub new_msg_id {
    my $seed = join(":", time(), $$, rand(), {});
    return sha256_hex($seed);
}

1;
