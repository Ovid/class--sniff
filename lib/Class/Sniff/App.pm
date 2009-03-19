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
        output    => undef,
        verbose   => undef,
    } => $class;
    GetOptions(
        "ignore=s"    => \$self->{ignore},
        "namespace=s" => \$self->{namespace},
        "verbose"     => \$self->{verbose},
        "png"         => sub { $self->{output} = '_as_png' },
        "gif"         => sub { $self->{output} = '_as_gif' },
    );
    $self->{output} ||= '_as_txt';

    unless ( @ARGV && 1 == @ARGV ) {
        die "You must supply a directory to load for Class::Sniff::App";
    }

    $self->{dir}       = shift @ARGV;
    $self->_initialize;
    return $self;
}

sub _dir       { $_[0]->{dir} }
sub _ignore    { $_[0]->{ignore} }
sub _graph     { $_[0]->{graph} }
sub _namespace { $_[0]->{namespace} }
sub _output    { $_[0]->{output} }
sub _verbose   { $_[0]->{verbose} }

sub _initialize {
    my $self = shift;

    $self->{namespace} = qr/$self->{namespace}/
      unless 'Regexp' eq ref $self->{namespace};
    $self->{ignore} = qr/$self->{ignore}/ if $self->{ignore};
}

sub run {
    my $self = shift;
    $self->_load_classes;
    my $graph = Class::Sniff->graph_from_namespace(
        {
            namespace => $self->_namespace,
            ignore    => $self->_ignore,
            universal => 1,
            clean     => 1,
        }
    );
    $self->{graph} = $graph;
    my $output = $self->_output;
    print $self->$output;
}

sub _as_txt { shift->_graph->as_ascii }

sub _as_png {
    my $self     = shift;
    my $graphviz = $self->_graph->as_graphviz();
    open my $DOT, '|dot -Tpng' or die("Cannot open pipe to dot: $!");
    print $DOT $graphviz;
}

sub _as_gif {
    my $self     = shift;
    my $graphviz = $self->_graph->as_graphviz();
    open my $DOT, '|dot -Tgif' or die("Cannot open pipe to dot: $!");
    print $DOT $graphviz;
}

sub _load_classes {
    my ($self) = @_;
    my $dir = $self->_dir;

    unless ( -d $dir ) {
        die "Cannot find ($dir) to sniff";
    }
    my @classes =
      map { $self->_load_class($_) }
      File::Find::Rule->file->name('*.pm')->in($dir);
    $self->{classes} = \@classes;
}

sub _load_class {
    my ( $self, $file ) = @_;
    $self->_say("Attempting to load ($file)");
    my $dir = $self->_dir;
    $file =~ s{\.pm$}{};    # remove .pm extension
    $file =~ s{\\}{/}g;     # to make win32 happy
    $dir  =~ s{\\}{/}g;     # to make win32 happy
    $file =~ s/^$dir//;
    my $_package = join '::' => grep $_ => File::Spec->splitdir($file);

    # untaint that puppy!
    my ($package) = $_package =~ /^([[:word:]]+(?:::[[:word:]]+)*)$/;

    eval "use $package";    ## no critic
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
