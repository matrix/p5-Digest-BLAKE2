use strict;
use Test::More;
eval q{ use Test::Spelling };
plan skip_all => "Test::Spelling is not installed." if $@;
add_stopwords(map { split /[\s\:\-]/ } <DATA>);
$ENV{LANG} = 'C';
my $spell_cmd;
foreach my $path (split(/:/, $ENV{PATH})) {
    -x "$path/spell"  and $spell_cmd = "spell",       last;
    -x "$path/ispell" and $spell_cmd = "ispell -l",   last;
    -x "$path/aspell" and $spell_cmd = "aspell list", last;
}
plan skip_all => "no spell/ispell/aspell" unless $spell_cmd;

set_spell_cmd($spell_cmd);
all_pod_files_spelling_ok('lib');
__DATA__
ATAT
Tasuku SUENAGA
gunyarakun
Gabriele Gristina
matrix
ARMs
Ascii
SHA
cryptographic
urlsafe
