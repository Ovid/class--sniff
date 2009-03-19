#!/usr/bin/env perl

use strict;
use warnings;

use lib 'lib';
use Class::Sniff;
use HTML::TokeParser::Simple;
my @sniffs = Class::Sniff->new_from_namespace({
    namespace => qr/(?i:tag)/,
});
my $graph    = $sniffs[0]->combine_graphs( @sniffs[ 1 .. $#sniffs ] );
print $graph->as_ascii;
__END__
my $graphviz = $graph->as_graphviz();
open my $DOT, '|dot -Tpng -o b.png' or die("Cannot open pipe to dot: $!");
print $DOT $graphviz;
