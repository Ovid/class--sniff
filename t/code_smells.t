#!/usr/bin/perl

use strict;
use warnings;

use Test::Most qw/no_plan die/;
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
    sub foo  { }    # diamond inheritance
    sub bar  { }    # Not a problem because it's inherited through 1 path
    sub quux { }    # no inheritance
}

can_ok 'Class::Sniff', 'new';
my $sniff = Class::Sniff->new( { class => 'Grandchild' } );

can_ok $sniff, 'paths';
my $expected_paths = [
    [ 'Grandchild', 'Child1', 'Abstract' ],
    [ 'Grandchild', 'Child2', 'Abstract' ]
];
eq_or_diff [$sniff->paths], $expected_paths,
    '... and it should report inheritance paths';

{
    package One;
    our @ISA = qw/Two Three/;
    package Two;
    package Three;
    our @ISA = qw/Four Six/;
    package Four;
    our @ISA = 'Five';
    package Five;
    package Six;
}
#    5
#    |
#    4  6
#    | /
# 2  3
#  \ |
#    1
# 1 -> 2
# 1 -> 3 -> 4 -> 5
# 1 -> 3 -> 6
my $complex_sniff = Class::Sniff->new({class => 'One'});
$expected_paths = [
    [ 'One', 'Two' ],
    [ 'One', 'Three', 'Four', 'Five' ],
    [ 'One', 'Three', 'Six' ]
];
eq_or_diff [$complex_sniff->paths], $expected_paths,
    '... even for convoluted hierarchies';

can_ok $sniff, 'overridden';
my $expected_overridden = {
    'bar' => [ 'Grandchild', 'Abstract', 'Child2' ],
    'foo' => [ 'Grandchild', 'Child1',   'Abstract', 'Child2' ]
};
eq_or_diff $sniff->overridden, $expected_overridden,
  '... and it should return an HoA with overridden methods and the classes';

can_ok $sniff, 'unreachable';
my $expected_unreachable = {
    'bar' => [ 'Child2' ],
    'foo' => [ 'Child2' ]
};
eq_or_diff $sniff->unreachable, $expected_unreachable,
  '... and it should return an HoA with unreachable methods and the classes';

# also test for MI
