#!/usr/bin/perl

use strict;
use warnings;

use Test::Most qw/no_plan die/;
use Class::Sniff;

{

    package Parent;

    sub new {}
    sub foo { }
    sub bar { }
    sub baz { }

    package Child;
    our @ISA = 'Parent';
}

# The eval'ing a string require regrettably creates a symbol table entry for
# the non-existent module and any parent stashes:
# There::Is::No::
# There::Is::
# There::
# We need to trap this entry.
eval "require There::Is::No::Spoon";

ok !Class::Sniff->new_from_namespace({
    namespace => qr/There/,
    universal => 1,
}), 'New from namespace should not find packages which did not load';
