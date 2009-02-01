#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'Class::Sniff' );
}

diag( "Testing Class::Sniff $Class::Sniff::VERSION, Perl $], $^X" );
