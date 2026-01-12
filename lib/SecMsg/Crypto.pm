
# Stack v0.01

package SecMsg::Crypto;

use strict;
use warnings;
use Exporter 'import';

use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(sha256 hmac_sha256);

our @EXPORT_OK = qw(seal_message open_message);

# ---------------------------------------------------------------------------
# "Layered cryptographic stack" (central project feature)
#
#   plaintext
#     -> Blowfish-CBC (IV from nonce)
#     -> Skipjack-CBC (IV derived from nonce)
#     -> Base64
#     -> ROT13
#
# We additionally attach an HMAC-SHA256 tag so receivers can decide whether a
# frame is valid for their shared secret (otherwise: BACKGROUND SIGNAL).
#
# Envelope fields (carried in the relay 'M' payload):
#   nonce_b64 "\0" tag_hex "\0" rot13_b64ct
#
# ---------------------------------------------------------------------------

sub _rot13 {
    my ($s) = @_;
    $s //= '';
    $s =~ tr/A-Za-z/N-ZA-Mn-za-m/;
    return $s;
}

sub _kdf {
    my ($label, $key) = @_;
    $label //= '';
    $key   //= '';
    return sha256("secmsg:$label\0" . $key);  # 32 bytes
}

sub _require_blowfish {
    # We keep Skipjack implemented here (pure Perl), but Blowfish is taken from
    # the widely available Crypt::CBC + Crypt::Blowfish.
    eval { require Crypt::CBC; 1 } or die "Missing dependency Crypt::CBC. Install it (cpan/cpanm) to use the layered stack.\n";
    eval { require Crypt::Blowfish; 1 } or die "Missing dependency Crypt::Blowfish. Install it (cpan/cpanm) to use the layered stack.\n";
}

# ------------------------- Skipjack (pure Perl) ----------------------------
# Reference: NSA Skipjack specification (block cipher, 64-bit block, 80-bit key)
# Implemented here for portability and POC use.
my @F = (
    0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9,
    0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28,
    0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53,
    0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2,
    0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8,
    0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90,
    0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76,
    0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d,
    0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18,
    0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4,
    0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40,
    0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5,
    0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2,
    0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8,
    0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac,
    0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46,
);

sub _u16 { $_[0] & 0xFFFF }
sub _rol16 { my ($x,$n)=@_; _u16((($x<<$n) | ($x>>(16-$n)))) }
sub _ror16 { my ($x,$n)=@_; _u16((($x>>$n) | ($x<<(16-$n)))) }

sub _G {
    my ($w, $k, $r) = @_; # w is u16, k is 10 bytes, r is round (1..32)
    my $g1 = ($w >> 8) & 0xFF;
    my $g2 = $w & 0xFF;
    my $k1 = ord(substr($k, ((4*($r-1)+0) % 10), 1));
    my $k2 = ord(substr($k, ((4*($r-1)+1) % 10), 1));
    my $k3 = ord(substr($k, ((4*($r-1)+2) % 10), 1));
    my $k4 = ord(substr($k, ((4*($r-1)+3) % 10), 1));

    my $g3 = $F[$g2 ^ $k1] ^ $g1;
    my $g4 = $F[$g3 ^ $k2] ^ $g2;
    my $g5 = $F[$g4 ^ $k3] ^ $g3;
    my $g6 = $F[$g5 ^ $k4] ^ $g4;

    return (($g5 << 8) | $g6) & 0xFFFF;
}

sub _Ginv {
    my ($w, $k, $r) = @_;
    my $g5 = ($w >> 8) & 0xFF;
    my $g6 = $w & 0xFF;

    my $k1 = ord(substr($k, ((4*($r-1)+0) % 10), 1));
    my $k2 = ord(substr($k, ((4*($r-1)+1) % 10), 1));
    my $k3 = ord(substr($k, ((4*($r-1)+2) % 10), 1));
    my $k4 = ord(substr($k, ((4*($r-1)+3) % 10), 1));

    # Reverse the G steps:
    my $g4 = $F[$g5 ^ $k4] ^ $g6;
    my $g3 = $F[$g4 ^ $k3] ^ $g5;
    my $g2 = $F[$g3 ^ $k2] ^ $g4;
    my $g1 = $F[$g2 ^ $k1] ^ $g3;

    return (($g1 << 8) | $g2) & 0xFFFF;
}

sub _skipjack_encrypt_block {
    my ($block8, $key10) = @_;
    my ($w1,$w2,$w3,$w4) = unpack("n4", $block8);

    for my $r (1..32) {
        if (($r >= 1 && $r <= 8) || ($r >= 17 && $r <= 24)) { # Rule A
            my $g = _G($w1, $key10, $r);
            my $tmp = $w4;
            $w4 = $w3;
            $w3 = $w2;
            $w2 = _u16($g ^ $r ^ $w4); # uses old w4? in spec it's old w4 before shift: that's $tmp
            $w2 = _u16($g ^ $r ^ $tmp);
            $w1 = $g;
        } else { # Rule B
            my $g = _G($w1, $key10, $r);
            my $tmp = $w4;
            $w4 = $w3;
            $w3 = _u16($w1 ^ $w2 ^ $r);
            $w2 = $g;
            $w1 = $tmp;
        }
    }
    return pack("n4", $w1,$w2,$w3,$w4);
}

sub _skipjack_decrypt_block {
    my ($block8, $key10) = @_;
    my ($w1,$w2,$w3,$w4) = unpack("n4", $block8);

    for (my $r = 32; $r >= 1; $r--) {
        if (($r >= 1 && $r <= 8) || ($r >= 17 && $r <= 24)) { # inverse of Rule A
            my $g = $w1;
            my $w1_prev = _Ginv($g, $key10, $r);
            my $w4_prev = _u16($w2 ^ $r ^ $g);
            my $w3_prev = $w4;
            my $w2_prev = $w3;
            my $w4_new  = $w4_prev;
            ($w1,$w2,$w3,$w4) = ($w1_prev,$w2_prev,$w3_prev,$w4_new);
        } else { # inverse of Rule B
            my $w4_prev = $w1;
            my $g = $w2;
            my $w1_prev = _u16($w3 ^ $w4_prev ^ $r);
            my $w2_prev = _Ginv($g, $key10, $r);
            my $w3_prev = $w4;
            my $w4_new  = $w4_prev;
            ($w1,$w2,$w3,$w4) = ($w1_prev,$w2_prev,$w3_prev,$w4_new);
        }
    }
    return pack("n4", $w1,$w2,$w3,$w4);
}

sub _cbc_encrypt_skipjack {
    my ($pt, $key10, $iv8) = @_;
    die "skipjack cbc: iv must be 8 bytes\n" unless defined($iv8) && length($iv8) == 8;
    die "skipjack cbc: key must be 10 bytes\n" unless defined($key10) && length($key10) == 10;
    die "skipjack cbc: pt len must be multiple of 8\n" unless (length($pt) % 8) == 0;

    my $prev = $iv8;
    my $out = '';
    for (my $i=0; $i<length($pt); $i+=8) {
        my $blk = substr($pt, $i, 8) ^ $prev;
        my $ct  = _skipjack_encrypt_block($blk, $key10);
        $out .= $ct;
        $prev = $ct;
    }
    return $out;
}

sub _cbc_decrypt_skipjack {
    my ($ct, $key10, $iv8) = @_;
    die "skipjack cbc: iv must be 8 bytes\n" unless defined($iv8) && length($iv8) == 8;
    die "skipjack cbc: key must be 10 bytes\n" unless defined($key10) && length($key10) == 10;
    die "skipjack cbc: ct len must be multiple of 8\n" unless (length($ct) % 8) == 0;

    my $prev = $iv8;
    my $out = '';
    for (my $i=0; $i<length($ct); $i+=8) {
        my $blk = substr($ct, $i, 8);
        my $pt  = _skipjack_decrypt_block($blk, $key10) ^ $prev;
        $out .= $pt;
        $prev = $blk;
    }
    return $out;
}

# ----------------------- Public API: seal/open -----------------------------
sub seal_message {
    my (%args) = @_;
    my $key = $args{key} // die "seal_message: missing key\n";
    my $pt  = $args{plaintext} // '';

    # Derive materials
    my $k_bf   = substr(_kdf("blowfish", $key), 0, 16);  # 128-bit key
    my $k_sj   = substr(_kdf("skipjack", $key), 0, 10);  # 80-bit key
    my $k_mac  = _kdf("hmac", $key);                     # 256-bit

    # Nonce/IVs
    my $nonce = substr(_kdf("nonce", $key . "\0" . rand() . "\0" . time()), 0, 16);
    my $iv_bf = substr($nonce, 0, 8);
    my $iv_sj = substr(sha256($nonce), 0, 8);

    _require_blowfish();

    my $bf = Crypt::CBC->new(
        -cipher      => 'Blowfish',
        -key         => $k_bf,
        -iv          => $iv_bf,
        -header      => 'none',
        -literal_key => 1,
        -padding     => 'standard',
    );

    my $stage1 = $bf->encrypt($pt);                 # Blowfish-CBC
    # Ensure stage1 multiple of 8 for Skipjack CBC (Crypt::CBC padding should do this)
    die "unexpected stage1 len\n" unless (length($stage1) % 8) == 0;

    my $stage2 = _cbc_encrypt_skipjack($stage1, $k_sj, $iv_sj);  # Skipjack-CBC

    my $b64ct = encode_base64($stage2, '');
    my $rot   = _rot13($b64ct);

    my $tag = hmac_sha256($nonce . $stage2, $k_mac);
    my $tag_hex = unpack("H*", $tag);

    return (encode_base64($nonce, ''), $tag_hex, $rot);
}

sub open_message {
    my (%args) = @_;
    my $key        = $args{key}        // die "open_message: missing key\n";
    my $nonce_b64  = $args{nonce_b64}  // return (0, undef);
    my $tag_hex    = $args{tag_hex}    // return (0, undef);
    my $rot        = $args{rot13_b64ct}// return (0, undef);

    my $nonce = eval { decode_base64($nonce_b64) };
    return (0, undef) if $@ || !defined($nonce) || length($nonce) != 16;

    my $k_bf   = substr(_kdf("blowfish", $key), 0, 16);
    my $k_sj   = substr(_kdf("skipjack", $key), 0, 10);
    my $k_mac  = _kdf("hmac", $key);

    my $iv_bf = substr($nonce, 0, 8);
    my $iv_sj = substr(sha256($nonce), 0, 8);

    my $b64ct = _rot13($rot);  # invert ROT13 (same function)
    my $ct = eval { decode_base64($b64ct) };
    return (0, undef) if $@ || !defined($ct) || (length($ct) % 8) != 0;

    my $want = unpack("H*", hmac_sha256($nonce . $ct, $k_mac));
    return (0, undef) if lc($want) ne lc($tag_hex);

    _require_blowfish();

    my $stage1 = _cbc_decrypt_skipjack($ct, $k_sj, $iv_sj);

    my $bf = Crypt::CBC->new(
        -cipher      => 'Blowfish',
        -key         => $k_bf,
        -iv          => $iv_bf,
        -header      => 'none',
        -literal_key => 1,
        -padding     => 'standard',
    );

    my $pt = eval { $bf->decrypt($stage1) };
    return (0, undef) if $@;

    return (1, $pt);
}

1;
