package Class::Sniff;

use warnings;
use strict;

use Carp 'croak';
use Tree;
use Graph::Easy;
use List::MoreUtils 'uniq';
use Devel::Symdump;

=head1 NAME

Class::Sniff - Look for class composition code smells

 my $sniff = Class::Sniff->new({class => 'My::Class'});
 print $sniff->to_string;
 my @unreachable = $sniff->unreachable;
 foreach my $method (@unreachable) {
    print "$method\n";
 }

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

    use Class::Sniff;

    my $sniff = Class::Sniff->new('Some::Class');

=cut

sub new {
    my ( $class, $arg_for ) = @_;
    my $target_class = $arg_for->{class}
        or croak "'class' argument not supplied to 'new'";
    if ( exists $arg_for->{ignore} && 'Regexp' ne ref $arg_for->{ignore} ) {
        croak "'ignore' requires a regex";
    }
    my $self = bless {
        classes      => {},
        class_order  => {},
        methods      => {},
        paths        => [[$target_class]],
        list_classes => [$target_class],
        graph        => undef,
        target       => $target_class,
        tree         => undef,
        ignore       => $arg_for->{ignore},
    } => $class;
    $self->_initialize;
    return $self;
}

sub _initialize {
    my $self = shift;
    my $target_class = $self->target;
    $self->_add_class($target_class);
    $self->{classes}{$target_class}{count} = 1;
    $self->{tree} = Tree->new($target_class);
    $self->_build_tree($self->tree);

    my $graph = Graph::Easy->new;
    for my $node ($self->tree->traverse) {
        my $class = $node->value;
        next if $class eq $target_class;
        $graph->add_edge_once($node->parent->value, $class);
    }
    $graph->set_attribute('graph', 'flow', 'up');
    $self->{graph} = $graph;
    $self->_finalize;
}

sub _finalize {
    my $self = shift;
    my @classes = $self->classes;
    my $index = 0;
    my %classes = map { $_ => $index++ } @classes;

    # sort in inheritance order
    while ( my ($method, $classes) = each %{ $self->{methods} } ) {
        @$classes = sort { $classes{$a} <=> $classes{$b} } @$classes;
    }
    $self->{class_order} = \%classes;
}

sub _add_class {
    my ( $self, $class ) = @_;
    return if exists $self->{classes}{$class};

    # Do I really want to throw this away?
    my $symdump = Devel::Symdump->new($class);
    my @methods = map { s/^$class\:://; $_ } $symdump->functions;

    for my $method (@methods) {
        $self->{methods}{$method} ||= [];
        push @{ $self->{methods}{$method} } => $class;
    }

    $self->{classes}{$class} = {
        parents  => [],
        children => [],
        methods  => \@methods,
        count    => 0,
    };
    return $self;
}

sub overridden {
    my $self = shift;
    my %methods;
    while ( my ($method, $classes) = each %{ $self->{methods} } ) {
        $methods{$method} = $classes if @$classes > 1;
    }
    return \%methods;
}

sub unreachable {
    my $self       = shift;
    my $overridden = $self->overridden;
    my @paths      = $self->paths;
    my %unreachable;

    while ( my ( $method, $classes ) = each %$overridden ) {
        my @unreachable;

        CLASS:
        for my $class (@$classes) {
            my $method_found = 0;
            for my $path (@paths) {
                if ($method_found) {
                    push @unreachable => $class;
                    next CLASS;
                }
                for my $curr_class (@$path) {
                    if ($curr_class eq $class) {
                        next CLASS;
                    }
                    if (not $method_found && $curr_class->can($method) ) {
                        $method_found = 1;
                    }
                }
            }
        }
        if (@unreachable) {
            $unreachable{$method} = \@unreachable;
        }
    }
    my @unreachable;
    while ( my ($method, $classes) = each %unreachable ) {
        foreach my $class (@$classes) {
            push @unreachable => "$class\::$method";
        }
    }
    return @unreachable;
}

sub _add_relationships {
    my ( $self, $class, @parents ) = @_;
    $self->_add_class($_) foreach $class, @parents;

    # what if this is called more than once?
    $self->{classes}{$class}{parents} = \@parents;
    $self->_add_child($_, $class) foreach @parents;
    return $self;
}

sub _add_child {
    my ( $self, $class, $child ) = @_;

    my $children = $self->{classes}{$class}{children};
    unless ( grep { $child eq $_ } @$children ) {
        push @$children => $child;
    }
}
sub to_string   { $_[0]->graph->as_ascii }
sub tree        { $_[0]->{tree} }
sub graph       { $_[0]->{graph} }
sub target      { $_[0]->{target} }
sub num_classes { $_[0]->{num_classes} }
sub classes     { @{ $_[0]->{list_classes} } }
sub ignore      { $_[0]->{ignore} }
sub paths       { 
    my $self = shift;
    return @{ $self->{paths} } unless @_;
    $self->{paths} = [@_];
    return $self;
}

sub parents {
    my ( $self, $target ) = @_;
    $target ||= $self->target;
    unless ( exists $self->{classes}{$target} ) {
        croak "No such class '$target' found in hierarchy";
    }
    return @{ $self->{classes}{$target}{parents} };
}

sub children {
    my ( $self, $target ) = @_;
    $target ||= $self->target;
    unless ( exists $self->{classes}{$target} ) {
        croak "No such class '$target' found in hierarchy";
    }
    return @{ $self->{classes}{$target}{children} };
}

sub methods {
    my ( $self, $target ) = @_;
    $target ||= $self->target;
    unless ( exists $self->{classes}{$target} ) {
        croak "No such class '$target' found in hierarchy";
    }
    return @{ $self->{classes}{$target}{methods} };
}

sub _get_parents {
    my ( $self, $class ) = @_;
    no strict 'refs';
    my @parents = uniq @{"$class\::ISA"};
    if ( my $ignore = $self->ignore ) {
        @parents = grep { !/$ignore/ } @parents;
    }
    return @parents;
}

sub _build_tree {
    my ($self,@nodes) = @_;

    for my $node (@nodes) {
        my $class = $node->value;

        my @parents = $self->_get_parents($class) or return;

        $self->_build_paths( $class, @parents );
        $self->_add_relationships( $class, @parents );

        # This algorithm will follow classes in Perl's default inheritance
        # order
        foreach my $parent (@parents) {
            push @{ $self->{list_classes} } => $parent
                unless grep { $_ eq $parent } @{ $self->{list_classes} };
            $self->{classes}{$parent}{count}++;
            my $tree = Tree->new($parent);
            $node->add_child($tree);
            $self->_build_tree($tree);
        }
    }
}

# This method builds 'paths'.  These are the paths the inheritance hierarchy
# will take through the code to find a method.  This is based on Perl's
# default search order, not C3.
sub _build_paths {
    my ( $self, $class, @parents ) = @_;

    my @paths = $self->paths;
    for my $i ( 0 .. $#paths ) {
        my $path = $paths[$i];
        if ( $path->[-1] eq $class ) {
            my @new_paths;
            for my $parent_class (@parents) {
                push @new_paths => [@$path, $parent_class];
            }
            splice @paths, $i, 1, @new_paths;
            $self->paths(@paths);
        }
    }
}

=head1 AUTHOR

Curtis "Ovid" Poe, C<< <ovid at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-class-sniff at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Class-Sniff>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Class::Sniff

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Class-Sniff>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Class-Sniff>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Class-Sniff>

=item * Search CPAN

L<http://search.cpan.org/dist/Class-Sniff/>

=back

=head1 ACKNOWLEDGEMENTS


=head1 COPYRIGHT & LICENSE

Copyright 2009 Curtis "Ovid" Poe, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of Class::Sniff
