package Class::Sniff::App;

use strict;
use warnings;

use Class::Sniff;
use Getopt::Long;
use File::Find::Rule;
use File::Spec;

sub new {
    my ( $class, @args ) = @_;
    local @ARGV = @args;
    my $self = bless {
        dir       => undef,
        ignore    => undef,
        namespace => qr/./,
        universal => 0,
        output    => undef,
        verbose   => undef,
    } => $class;
    GetOptions(
        "dir=s"       => \$self->{dir},
        "ignore=s"    => \$self->{ignore},
        "namespace=s" => \$self->{namespace},
        "universal"   => \$self->{universal},
        "output=s"    => \$self->{output},
        "verbose"     => \$self->{verbose},
    );
    $self->_initialize;
    return $self;
}

sub _dir       { $_[0]->{dir} }
sub _ignore    { $_[0]->{ignore} }
sub _namespace { $_[0]->{namespace} }
sub _universal { $_[0]->{universal} }
sub _output    { $_[0]->{output} }
sub _verbose   { $_[0]->{verbose} }

sub _initialize {
    my $self = shift;

    $self->{namespace} = qr/$self->{namespace}/
      unless 'Regexp' eq ref $self->{namespace};
    $self->{ignore} = qr/$self->{ignore}/ if $self->{ignore};
    $self->_load_classes;
}

sub run {
}

sub _load_classes {
    my ($self) = @_;
    my $dir = $self->_dir;

    unless (-d $dir) {
        die "Cannot find ($dir) to sniff";
    }
    my @classes = map { $self->_load_class($_) }
        File::Find::Rule->file->name('*.pm')->in($dir);
    $self->{classes} = \@classes;
}

sub _load_class {
    my ( $self, $file ) = @_;
    $self->_say("Attempting to load ($file)");
    my $dir = $self->_dir;
    $file =~ s{\.pm$}{};             # remove .pm extension
    $file =~ s{\\}{/}g;              # to make win32 happy
    $dir  =~ s{\\}{/}g;              # to make win32 happy
    $file =~ s/^$dir//;
    my $_package = join '::' => grep $_ => File::Spec->splitdir( $file );

    # untaint that puppy!
    my ( $package ) = $_package =~ /^([[:word:]]+(?:::[[:word:]]+)*)$/;

    eval "use $package"; ## no critic
    warn $@ if $@;
    unless ($@) {
        $self->_say("$package loaded successfully");
    }
    return $package;
}

sub _say {
    my ( $self, $message ) = @_;
    return unless $self->_verbose;
    print "$message\n";
}

1;
