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

=head1 VERSION

Version 0.03

=cut

our $VERSION = '0.03';

=head1 SYNOPSIS

 use Class::Sniff;
 my $sniff = Class::Sniff->new({class => 'Some::class'});

 my $num_methods = $sniff->methods;
 my $num_classes = $sniff->classes;
 my @methods     = $sniff->methods;
 my @classes     = $sniff->classes;

 my $graph    = $sniff->graph;   # Graph::Easy
 my $graphviz = $graph->as_graphviz();
 open my $DOT, '|dot -Tpng -o graph.png' or die("Cannot open pipe to dot: $!");
 print $DOT $graphviz;

 print $sniff->to_string;
 my @unreachable = $sniff->unreachable;
 foreach my $method (@unreachable) {
     print "$method\n";
 }

=head1 DESCRIPTION

B<ALPHA> code.  You've been warned.

This module attempts to help programmers find 'code smells' in the
object-oriented code.  If it reports something, it does not mean that your
code is wrong.  It just means that you might want to look at your code a
little bit more closely to see if you have any problems.

At the present time, we assume Perl's default left-most, depth-first search
order.  We may alter this in the future (and there's a work-around with the
C<paths> method.  More on this later).

=head1 CLASS METHODS

=head2 C<new>

 my $sniff = Class::Sniff->new({
    class  => 'My::Class',
    ignore => qr/^DBIx::Class/,
 });

The constructor accepts a hashref with the following parameters:

=over 4

=item * C<class>

Mandatory.

The name of the class to sniff.  If the class is not loaded into memory, the
constructor will still work, but nothing will get reported.  You must ensure
that your class is already loaded!

=item * C<ignore>

Optional.

This should be a regex telling C<Class::Sniff> what to ignore in class names.
This is useful if you're inheriting from a large framework and don't want to
report on it.  Be careful with this, though.  If you have a complicated
inheritance hierarchy and you try to ignore something other than the root, you
will likely get bad information returned.

=item * universal

Optional.

If present and true, will attempt to include the C<UNIVERSAL> base class.  If
a class hierarchy is pruned with C<ignore>, C<UNIVERSAL> may not show up.

=back

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
        universal    => $arg_for->{universal},
    } => $class;
    $self->_initialize;
    return $self;
}

sub _initialize {
    my $self = shift;
    my $target_class = $self->target_class;
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

=head1 INSTANCE METHODS

=head2 C<overridden>

 my $overridden = $sniff->overridden;

This method returns a hash of arrays.  Each key is a method in the hierarchy
which has been overridden and the arrays are lists of all classes the method
is defined in (not just which one's it's overridden in).  The order of the
classes is in Perl's default inheritance search order.

=head3 Code Smell

Overridden methods are not necessarily a code smell, but you should check them
to find out if you've overridden something you didn't expect to override.
Accidental overriding of a method can be very hard to debug.

=cut

sub overridden {
    my $self = shift;
    my %methods;
    while ( my ($method, $classes) = each %{ $self->{methods} } ) {
        $methods{$method} = $classes if @$classes > 1;
    }
    return \%methods;
}

=head2 C<unreachable>

 my @unreachable = $sniff->unreachable;
 for my $method (@unreachable) {
     print "Cannot reach '$method'\n";
 }

Returns a list of fully qualified method names (e.g.,
'My::Customer::_short_change') which are unreachable by Perl's normal search
inheritance search order.  It does this by searching the "paths" returned by
the C<paths> method.

=head3 Code Smell

Pretty straight-forward here.  If a method is unreachable, it's likely to be
dead code.  However, you might have a reason for this and maybe you're calling
it directly.

=cut

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

=head2 C<paths>

 my @paths = $sniff->paths;

 for my $i (0 .. $#paths) {
     my $path = join ' -> ' => @{ $paths[$i] };
     printf "Path #%d is ($path)\n" => $i + 1;
 }

Returns a list of array references.  Each array reference is a list of
classnames representing the path Perl will take to search for a method.  For
example, if we have an abstract C<Animal> class and we use diamond inheritance
to create an C<Animal::Platypus> class, we might have the following hierarchy:

               Animal
              /      \
    Animal::Duck   Animal::SpareParts
              \      /
          Animal::Platypus

With Perl's normal left-most, depth-first search order, C<paths> will return:

 (
     ['Animal::Platypus', 'Animal::Duck',       'Animal'],
     ['Animal::Platypus', 'Animal::SpareParts', 'Animal'],
 )

If you are using a different MRO (Method Resolution Order) and you know your
search order is different, you can pass in a list of "correct" paths,
structured as above:

 # Look ma, one hand (er, path)!
 $sniff->paths( 
     ['Animal::Platypus', 'Animal::Duck', 'Animal::SpareParts', 'Animal'],
 );

At the present time, we do I<no> validation of what's passed in.  It's just an
experimental (and untested) hack.

=head3 Code Smell

Multiple inheritance paths are tricky to get right, make it easy to have
'unreachable' methods and have a greater cognitive load on the programmer.
For example, if C<Animal::Duck> and C<Animal::SpareParts> both define the same
method, C<Animal::SpareParts>' method is likely unreachable.  But what if
makes a required state change?  You now have broken code.

See L<http://use.perl.org/~Ovid/journal/38373> for a more in-depth
explanation.

=cut

sub paths       { 
    my $self = shift;
    return @{ $self->{paths} } unless @_;
    $self->{paths} = [@_];
    return $self;
}

=head2 C<multiple_inheritance>

 my $num_classes = $sniff->multiple_inheritance;
 my @classes     = $sniff->multiple_inheritance;

Returns a list of all classes which inherit from more than one class.

=head3 Code Smell

See the C<Code Smell> section for C<paths>

=cut

sub multiple_inheritance {
    my $self = shift;
    return grep { $self->parents($_) > 1 } $self->classes;
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

=head2 C<to_string>

 print $sniff->to_string;

For debugging, lets you print a string representation of your class hierarchy.
Internally this is created by C<Graph::Easy> and I can't figure out how to
force it to respect the order in which classes are ordered.  Thus, the
'left/right' ordering may be incorrect.

=cut

sub to_string    { $_[0]->graph->as_ascii }

=head2 C<tree>

 my $tree = $sniff->tree;

Returns a L<Tree> representation of the inheritance hierarchy.

=cut

sub tree         { $_[0]->{tree} }

=head2 C<graph>

 my $graph = $sniff->graph;

Returns a C<Graph::Easy> representation of the inheritance hierarchy.  This is
exceptionally useful if you have C<GraphViz> installed.

 my $graph    = $sniff->graph;   # Graph::Easy
 my $graphviz = $graph->as_graphviz();
 open my $DOT, '|dot -Tpng -o graph.png' or die("Cannot open pipe to dot: $!");
 print $DOT $graphviz;

Visual representations of complex hierarchies are worth their weight in gold.
See L<http://pics.livejournal.com/publius_ovidius/pic/00015p9z>.

Because I cannot figure force it to respect the 'left/right' ordering of
classes, you may need to manually edit the C<$graphviz> data to get this
right.

=cut

sub graph        { $_[0]->{graph} }

=head2 C<target_class>

 my $class = $sniff->target_class;

This is the class you originally asked to sniff.

=cut

sub target_class { $_[0]->{target} }

=head2 C<ignore>

 my $ignore = $sniff->ignore;

This is the regex provided (if any) to the constructor's C<ignore> parameter.

=cut

sub ignore       { $_[0]->{ignore} }

=head2 C<universal>

 my $universal = $sniff->universal;

This is the value provided (if any) to the 'universal' parameter in the
constructor.  If it's a true value, 'UNIVERSAL' will be added to the
hierarchy.  If the hierarchy is pruned via 'ignore' and we don't get down that
far in the hierarchy, the 'UNIVERSAL' class will not be added.

=cut

sub universal       { $_[0]->{universal} }

=head2 C<classes>

 my $num_classes = $sniff->classes;
 my @classes     = $sniff->classes;

In scalar context, lists the number of classes in the hierarchy.

In list context, lists the classes in the hierarchy, in default search order.

=cut

sub classes      { @{ $_[0]->{list_classes} } }

=head2 C<parents>

 # defaults to 'target_class'
 my $num_parents = $sniff->parents;
 my @parents     = $sniff->parents;

 my $num_parents = $sniff->parents('Some::Class');
 my @parents     = $sniff->parents('Some::Class');

In scalar context, lists the number of parents a class has.

In list context, lists the parents a class has.

=head3 Code Smell

If a class has more than one parent, you may have unreachable or conflicting
methods.

=cut

sub parents {
    my ( $self, $class ) = @_;
    $class ||= $self->target_class;
    unless ( exists $self->{classes}{$class} ) {
        croak "No such class '$class' found in hierarchy";
    }
    return @{ $self->{classes}{$class}{parents} };
}

=head2 C<children>

 # defaults to 'target_class'
 my $num_children = $sniff->children;
 my @children     = $sniff->children;

 my $num_children = $sniff->children('Some::Class');
 my @children     = $sniff->children('Some::Class');

In scalar context, lists the number of children a class has.

In list context, lists the children a class has.

=cut

sub children {
    my ( $self, $class ) = @_;
    $class ||= $self->target_class;
    unless ( exists $self->{classes}{$class} ) {
        croak "No such class '$class' found in hierarchy";
    }
    return @{ $self->{classes}{$class}{children} };
}

=head2 C<methods>

 # defaults to 'target_class'
 my $num_methods = $sniff->methods;
 my @methods     = $sniff->methods;

 my $num_methods = $sniff->methods('Some::Class');
 my @methods     = $sniff->methods('Some::Class');

In scalar context, lists the number of methods a class has.

In list context, lists the methods a class has.

=cut

sub methods {
    my ( $self, $class ) = @_;
    $class ||= $self->target_class;
    unless ( exists $self->{classes}{$class} ) {
        croak "No such class '$class' found in hierarchy";
    }
    return @{ $self->{classes}{$class}{methods} };
}

sub _get_parents {
    my ( $self, $class ) = @_;
    return if $class eq 'UNIVERSAL';
    no strict 'refs';

    my @parents = uniq @{"$class\::ISA"};
    if ( $self->universal && not @parents ) {
        @parents = 'UNIVERSAL';
    }
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

=head1 CAVEATS AND PLANS

=over 4

=item * Circular Inheritance

Currently, any circular inheritances causes a 'Deep recursion' failure, so
don't do that.

=item * Package Variables

User-defined package variables in OO code are a code smell, but with versions
of Perl < 5.10, any subroutine also creates a scalar glob entry of the same
name, so I've no done a package variable check yet.  This will happen in the
future (there will be exceptions, such as with @ISA).

=item * C3 Support

I'd like support for alternate method resolution orders.  If your classes use
C3, you may get erroneous results.  See L<paths> for a workaround.

=item * Exporting

Many packages (such as L<Data::Dumper>) export functions by default and these
show up as methods.  We'll detect those later.

=item * Duplicate Methods

It's rather common for someone to cut-n-paste a method from one class to
another.  We'll try and detect that, too.  L<Sub::Information> may help there.

=back

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
