#!/usr/bin/perl

use strict;
use warnings;

use Test::Most tests => 29;
use Class::Sniff;

{

    package Abstract;

    sub new { bless {} => shift }
    sub foo { }
    sub bar { }
    sub baz { }

    package Child1;
    our @ISA = 'Abstract';
    sub foo { }

    package Child2;
    our @ISA = 'Abstract';
    sub foo { }
    sub bar { }

    package Grandchild;
    our @ISA = qw<Child1 Child2>;
    sub foo  { }   # diamond inheritance
    sub bar  { }   # Not a problem because it's inherited through 1 path
    sub quux { }   # no inheritance
}

# Constructor with tree, graph, and ascii representations.

can_ok 'Class::Sniff', 'new';
$DB::single = 1;
isa_ok my $sniff = Class::Sniff->new({ class => 'Grandchild'}), 'Class::Sniff',
  '... and the object it returns';

can_ok $sniff, 'tree';
isa_ok $sniff->tree, 'Tree', '... and the object it returns';

can_ok $sniff, 'graph';
isa_ok $sniff->graph, 'Graph::Easy', '... and the object it returns';

can_ok $sniff, 'to_string';
like $sniff->to_string, qr/\| \s+ Grandchild \s+ \|/x,
    '... and it should look sane';

# Fetch general data about object hierarchy

can_ok $sniff, 'classes';
is scalar $sniff->classes, 4,
  '... and in scalar context, should return the number of classes';

eq_or_diff [ $sniff->classes ],
  [ qw/Grandchild Child1 Abstract Child2/ ],
  '... and it should return the classes in default inheritance order';

can_ok $sniff, 'parents';
eq_or_diff [$sniff->parents], [qw/Child1 Child2/],
    '... and it should return the ordered parent classes for the target class';
eq_or_diff [$sniff->parents('Child1')], [qw/Abstract/],
    '... or the parents for the named class';

throws_ok { $sniff->parents('no_such_class') }
    qr/No such class/,
    '... and it should croak if passed an unknown class';

can_ok $sniff, 'children';

eq_or_diff [$sniff->children], [],
    '... and it should return an empty array for the target class';
eq_or_diff [$sniff->children('Child1')], [qw/Grandchild/],
    '... or the children for the named class';
eq_or_diff [$sniff->children('Abstract')], [qw/Child1 Child2/],
    '... even if it has more than one child';

throws_ok { $sniff->children('no_such_class') }
    qr/No such class/,
    '... and it should croak if passed an unknown class';

can_ok $sniff, 'methods';

eq_or_diff [sort $sniff->methods], [qw/bar foo quux/],
    '... and it should return the methods for the target class';
eq_or_diff [$sniff->methods('Child1')], [qw/foo/],
    '... or the methods for the named class';
eq_or_diff [sort $sniff->methods('Abstract')], [qw/bar baz foo new/],
    '... or the methods for the named class';

throws_ok { $sniff->methods('no_such_class') }
    qr/No such class/,
    '... and it should croak if passed an unknown class';

# ignore allows us to ignore classes matching a pattern
# This is useful if you inherit from a framework such as DBIx::Class and you
# don't want that showing up.

can_ok $sniff, 'ignore';
$sniff = Class::Sniff->new( { class => 'Grandchild', ignore => qr/Abstract/ } );

throws_ok { $sniff->methods('Abstract') }
    qr/No such class/,
    '... and ignored classes are ignored';

$sniff = Class::Sniff->new( { class => 'Grandchild', ignore => qr/Child/ } );

throws_ok { $sniff->methods('Child1') }
    qr/No such class/,
    '... and ignored classes are ignored';
throws_ok { $sniff->methods('Abstract') }
    qr/No such class/,
    '... as are all parents of those classes';
