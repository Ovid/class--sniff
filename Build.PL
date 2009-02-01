use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name       => 'Class::Sniff',
    license           => 'perl',
    dist_author       => 'Curtis "Ovid" Poe <ovid@cpan.org>',
    dist_version_from => 'lib/Class/Sniff.pm',
    build_requires    => {
        'Test::Most'      => 0,
        'Tree'            => 1.01,
        'Graph::Easy'     => 0.64,
        'List::MoreUtils' => 0.22,
        'Devel::Symdump'  => 2.08,
    },
    add_to_cleanup     => ['Class-Sniff-*'],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();
