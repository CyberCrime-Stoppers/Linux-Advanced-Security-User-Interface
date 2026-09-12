package LASUI::Audit;
use strict; use warnings; use JSON::PP qw(encode_json);

sub new { return bless {}, shift }

sub scan_setuid {
    my @found;
    open my $fh, '-|', 'find', '/usr', '-perm', '-4000', '-type', 'f'
        or die "find failed: $!";
    while (<$fh>) {
        chomp;
        push @found, { path => $_, mode => (stat($_))[2] & 07777 };
    }
    return map { encode_json({ check => 'setuid', %{$_} }) } @found;
}

sub scan_world_writable {
    # find /etc /var -type f -perm -o+w, minus whitelists...
    return;
}

1;
