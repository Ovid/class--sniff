package Class::Sniff;

use warnings;
use strict;

use Carp ();
use Devel::Symdump;
use Graph::Easy;
use List::MoreUtils ();
use Sub::Information ();
use Text::SimpleTable;
use Tree;

=head1 NAME

Class::Sniff - Look for class composition code smells

=head1 VERSION

Version 0.04

=cut

our $VERSION = '0.04';

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

The interface is rather ad-hoc at the moment and is likely to change.  After
creating a new instance, calling the C<report> method is your best option.
You can then visually examine it to look for potential problems:

 my $sniff = Class::Sniff->new({class => 'Some::Class'});
 print $sniff->report;

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
      or Carp::croak("'class' argument not supplied to 'new'");
    if ( exists $arg_for->{ignore} && 'Regexp' ne ref $arg_for->{ignore} ) {
        Carp::croak("'ignore' requires a regex");
    }
    my $self = bless {
        classes      => {},
        class_order  => {},
        exported     => {},
        methods      => {},
        paths        => [ [$target_class] ],
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
    my $self         = shift;
    my $target_class = $self->target_class;
    $self->width(72);
    $self->_add_class($target_class);
    $self->{classes}{$target_class}{count} = 1;
    $self->{tree} = Tree->new($target_class);
    $self->_build_tree( $self->tree );

    my $graph = Graph::Easy->new;
    for my $node ( $self->tree->traverse ) {
        my $class = $node->value;
        next if $class eq $target_class;
        $graph->add_edge_once( $node->parent->value, $class );
    }
    $graph->set_attribute( 'graph', 'flow', 'up' );
    $self->{graph} = $graph;
    $self->_finalize;
}

sub _finalize {
    my $self    = shift;
    my @classes = $self->classes;
    my $index   = 0;
    my %classes = map { $_ => $index++ } @classes;

    # sort in inheritance order
    while ( my ( $method, $classes ) = each %{ $self->{methods} } ) {
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

    foreach my $method (@methods) {
        my $coderef = $class->can($method)
            or Carp::croak("Panic: $class->can($method) returned false!");
        my $info = Sub::Information::inspect($coderef);
        if ( $info->package ne $class ) {
            $self->{exported}{$class}{$method} = $info->package;
        }
    }

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

=head2 C<report>

 print $sniff->report;

Prints out a detailed, human readable report of C<Class::Sniff>'s analysis of
the class.  Returns an empty string if no issues found.  Sample:

 Report for class: Grandchild
 
 Overridden Methods
 .--------+--------------------------------------------------------------------.
 | Method | Class                                                              |
 +--------+--------------------------------------------------------------------+
 | bar    | Grandchild                                                         |
 |        | Abstract                                                           |
 |        | Child2                                                             |
 | foo    | Grandchild                                                         |
 |        | Child1                                                             |
 |        | Abstract                                                           |
 |        | Child2                                                             |
 '--------+--------------------------------------------------------------------'
 Unreachable Methods
 .--------+--------------------------------------------------------------------.
 | Method | Class                                                              |
 +--------+--------------------------------------------------------------------+
 | bar    | Child2                                                             |
 | foo    | Child2                                                             |
 '--------+--------------------------------------------------------------------'
 Multiple Inheritance
 .------------+----------------------------------------------------------------.
 | Class      | Parents                                                        |
 +------------+----------------------------------------------------------------+
 | Grandchild | Child1                                                         |
 |            | Child2                                                         |
 '------------+----------------------------------------------------------------'

=cut

sub report {
    my $self = shift;

    # I know this is all a nasty hack, but I don't yet know how I want to
    # refactor this.

    my $report = '';
    my $overridden = $self->overridden;
    if ( %$overridden ) {
        my @methods = sort keys %$overridden;
        my @classes;
        foreach my $method (@methods) {
            push @classes => join "\n" => @{ $overridden->{$method} };
        }
        $report .= "Overridden Methods\n"
          . $self->_build_report( 'Method', 'Class', \@methods, \@classes );
    }

    if ( my @unreachable = $self->unreachable ) {
        my ( @methods, @classes );
        for my $fq_method (@unreachable) {
            $fq_method =~ /^(.*)::(.*)$/;    # time to rethink the API
            push @methods => $2;
            push @classes => $1;
        }
        $report .= "Unreachable Methods\n"
          . $self->_build_report( 'Method', 'Class', \@methods, \@classes );
    }

    if ( my @multis = $self->multiple_inheritance ) {
        my @classes = map { join "\n" => $self->parents($_) } @multis;
        $report .= "Multiple Inheritance\n"
          . $self->_build_report( 'Class', 'Parents', \@multis, \@classes );
    }

    $report .= $self->_get_exported_report;

    if ($report) {
        my $target = $self->target_class;
        $report = "Report for class: $target\n\n$report";
    }
    return $report;
}

sub _get_exported_report {
    my $self = shift;
    my $exported = $self->exported;
    my $report = '';
    if ( my @classes = sort keys %$exported ) {
        my ($longest_c, $longest_m) = (length('Class'), length('Method') );
        my (@subs,@sources);
        foreach my $class (@classes) {
            my (@temp_subs, @temp_sources);
            foreach my $sub (sort keys %{ $exported->{$class} } ) {
                push @temp_subs => $sub;
                push @temp_sources => $exported->{$class}{$sub};
                $longest_c = length($class) if length($class) > $longest_c;
                $longest_m = length($sub)   if length($sub) > $longest_m;
            }
            push @subs    => join "\n" => @temp_subs;
            push @sources => join "\n" => @temp_sources;
        }
        my $width = $self->width - 3;
        my $third = int($width/3);
        $longest_c = $third if $longest_c > $third;
        $longest_m = $third if $longest_m > $third;
        my $rest = $width - ($longest_c + $longest_m);
        my $text = Text::SimpleTable->new(
            [ $longest_c, 'Class' ],
            [ $longest_m, 'Method' ],
            [ $rest,      'Exported From Package' ]
        );
        for my $i ( 0 .. $#classes ) {
            $text->row( $classes[$i], $subs[$i], $sources[$i] );
        }
        $report .= "Exported Subroutines\n".$text->draw;
    }
    return $report;
}

sub _build_report {
    my ( $self, $title1, $title2, $strings1, $strings2 ) = @_;
    unless ( @$strings1 == @$strings2 ) {
        Carp::croak("PANIC:  Attempt to build unbalanced report");
    }
    my ( $width1, $width2 ) = $self->_get_widths( $title1, @$strings1 );
    my $text =
      Text::SimpleTable->new( [ $width1, $title1 ], [ $width2, $title2 ] );
    for my $i ( 0 .. $#$strings1 ) {
        $text->row( $strings1->[$i], $strings2->[$i] );
    }
    return $text->draw;
}

sub _get_widths {
    my ( $self, $title, @strings ) = @_;

    my $width = $self->width;
    my $longest = length($title);
    foreach my $string (@strings) {
        my $length = length $string;
        $longest = $length if $length > $longest;
    }
    $longest = int( $width / 2 ) if $longest > ($width / 2);
    return ($longest, $width - $longest);
}
=head2 C<width>

 $sniff->width(80);

Set the width of the report.  Defaults to 72.

=cut

sub width {
    my $self = shift;
    return $self->{width} unless @_;
    my $number = shift;
    unless ( $number =~ /^\d+$/ && $number >= 40 ) {
        Carp::croak(
            "Argument to 'width' must be a number >= than 40, not ($number)");
    }
    $self->{width} = $number;
}

=head2 C<overridden>

 my $overridden = $sniff->overridden;

This method returns a hash of arrays.  Each key is a method in the hierarchy
which has been overridden and the arrays are lists of all classes the method
is defined in (not just which one's it's overridden in).  The order of the
classes is in Perl's default inheritance search order.

=head3 Code Smell:  overridden methods

Overridden methods are not necessarily a code smell, but you should check them
to find out if you've overridden something you didn't expect to override.
Accidental overriding of a method can be very hard to debug.

=cut

sub overridden {
    my $self = shift;
    my %methods;
    while ( my ( $method, $classes ) = each %{ $self->{methods} } ) {
        $methods{$method} = $classes if @$classes > 1;
    }
    return \%methods;
}

=head2 C<exported>

    my $exported = $sniff->exported;

Returns a hashref of all classes which have subroutines exported into them.
The structure is:

 {
     $class1 => {
         $sub1 => $exported_from1,
         $sub2 => $exported_from2,
     },
     $class2 => { ... }
 }

Returns an empty hashref if no exported subs are found.

=head3 Code Smell:  exported subroutines

Generally speaking, you should not be exporting subroutines into OO code.
Quite often this happens with things like C<Carp::croak> and other modules
which export "helper" functions.  These functions may not behave like you
expect them to since they're generally not intended to be called as methods.

=cut

sub exported { $_[0]->{exported} }

=head2 C<unreachable>

 my @unreachable = $sniff->unreachable;
 for my $method (@unreachable) {
     print "Cannot reach '$method'\n";
 }

Returns a list of fully qualified method names (e.g.,
'My::Customer::_short_change') which are unreachable by Perl's normal search
inheritance search order.  It does this by searching the "paths" returned by
the C<paths> method.

=head3 Code Smell:  unreachable methods

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
                    if ( $curr_class eq $class ) {
                        next CLASS;
                    }
                    if ( not $method_found && $curr_class->can($method) ) {
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
    while ( my ( $method, $classes ) = each %unreachable ) {
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

=head3 Code Smell:  paths

Multiple inheritance paths are tricky to get right, make it easy to have
'unreachable' methods and have a greater cognitive load on the programmer.
For example, if C<Animal::Duck> and C<Animal::SpareParts> both define the same
method, C<Animal::SpareParts>' method is likely unreachable.  But what if
makes a required state change?  You now have broken code.

See L<http://use.perl.org/~Ovid/journal/38373> for a more in-depth
explanation.

=cut

sub paths {
    my $self = shift;
    return @{ $self->{paths} } unless @_;
    $self->{paths} = [@_];
    return $self;
}

=head2 C<multiple_inheritance>

 my $num_classes = $sniff->multiple_inheritance;
 my @classes     = $sniff->multiple_inheritance;

Returns a list of all classes which inherit from more than one class.

=head3 Code Smell:  multiple inheritance

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
    $self->_add_child( $_, $class ) foreach @parents;
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

sub to_string { $_[0]->graph->as_ascii }

=head2 C<tree>

 my $tree = $sniff->tree;

Returns a L<Tree> representation of the inheritance hierarchy.

=cut

sub tree { $_[0]->{tree} }

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

sub graph { $_[0]->{graph} }

=head2 C<target_class>

 my $class = $sniff->target_class;

This is the class you originally asked to sniff.

=cut

sub target_class { $_[0]->{target} }

=head2 C<ignore>

 my $ignore = $sniff->ignore;

This is the regex provided (if any) to the constructor's C<ignore> parameter.

=cut

sub ignore { $_[0]->{ignore} }

=head2 C<universal>

 my $universal = $sniff->universal;

This is the value provided (if any) to the 'universal' parameter in the
constructor.  If it's a true value, 'UNIVERSAL' will be added to the
hierarchy.  If the hierarchy is pruned via 'ignore' and we don't get down that
far in the hierarchy, the 'UNIVERSAL' class will not be added.

=cut

sub universal { $_[0]->{universal} }

=head2 C<classes>

 my $num_classes = $sniff->classes;
 my @classes     = $sniff->classes;

In scalar context, lists the number of classes in the hierarchy.

In list context, lists the classes in the hierarchy, in default search order.

=cut

sub classes { @{ $_[0]->{list_classes} } }

=head2 C<parents>

 # defaults to 'target_class'
 my $num_parents = $sniff->parents;
 my @parents     = $sniff->parents;

 my $num_parents = $sniff->parents('Some::Class');
 my @parents     = $sniff->parents('Some::Class');

In scalar context, lists the number of parents a class has.

In list context, lists the parents a class has.

=head3 Code Smell:  multiple parens (multiple inheritance)

If a class has more than one parent, you may have unreachable or conflicting
methods.

=cut

sub parents {
    my ( $self, $class ) = @_;
    $class ||= $self->target_class;
    unless ( exists $self->{classes}{$class} ) {
        Carp::croak("No such class '$class' found in hierarchy");
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
        Carp::croak("No such class '$class' found in hierarchy");
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
        Carp::croak("No such class '$class' found in hierarchy");
    }
    return @{ $self->{classes}{$class}{methods} };
}

sub _get_parents {
    my ( $self, $class ) = @_;
    return if $class eq 'UNIVERSAL';
    no strict 'refs';

    my @parents = List::MoreUtils::uniq( @{"$class\::ISA"} );
    if ( $self->universal && not @parents ) {
        @parents = 'UNIVERSAL';
    }
    if ( my $ignore = $self->ignore ) {
        @parents = grep { !/$ignore/ } @parents;
    }
    return @parents;
}

sub _build_tree {
    my ( $self, @nodes ) = @_;

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

    # XXX strictly speaking, we can skip $do_chg, but if path() get's
    # expensive (such as testing for valid classes or circularity), then we
    # need it.
    my $do_chg;

    my @paths = map {
        my $path = $_;
        $path->[-1] eq $class
          ? do {
            ++$do_chg;
            map { [ @$path, $_ ] } @parents;
          }
          : $path
    } $self->paths;

    $self->paths(@paths) if $do_chg;
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

1;    # End of Class::Sniff
