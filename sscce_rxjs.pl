use strict;
use warnings;
use feature 'say';
use utf8;
use open ':std', ':encoding(UTF-8)';
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 2;

my $data = $ARGV[0] || '{"id":42}';

my $o = from_json($data);
say Dumper $o;

sub TRACE_JSON {1}

# Return a Perl structure corresponding to a json string
sub from_json {
    my $i = '⋅';
    my $l = 0;
    my $rx = qr{
    # NOTES:
    # this regex is a recusrive descent parser - see https://www.perlmonks.org/?node_id=995856
    # and chapter 1 "Recursive regular expressions" of Mastering Perl (Brian d Foy)
    #
    # Inside the block (?(DEFINE) ...)  (?<FOOBAR> ...) defines a named pattern FOOBAR
    #                                   that can be called with (?&FOOBAR)
    # (?{ ... }) is a block of Perl code that is evaluated at the time we reach it while running the pattern
    # $^R is the value returned by the last runned (?{ }) block
    # $^N is the last matched group

    (?&VALUE) (?{ $_ = $^R->[1] }) # <== entry point of the parser
    
    (?(DEFINE) # this does not try to match, it only defines a serie of named patterns
    
      (?<VALUE> (?{ say $i x $l++,'Value?' if TRACE_JSON;$^R })
        \s*
        (
        (?{ say $i x $l,'try object' if TRACE_JSON;$^R }) (?&OBJECT)
        |
        (?{ say $i x $l,'try number' if TRACE_JSON;$^R }) (?&NUMBER) (?{ say $i x $l,'post number' if TRACE_JSON;$^R })
        |
        (?{ say $i x $l,'try string' if TRACE_JSON;$^R }) (?&STRING)
        |
        (?{ say $i x $l,'try array'  if TRACE_JSON;$^R }) (?&ARRAY)
        |
        (?{ say $i x $l,'try true'  if TRACE_JSON;$^R }) true  (?{ say $i x $l,'->true' if TRACE_JSON; [$^R, 1] })
        |
        (?{ say $i x $l,'try false'  if TRACE_JSON;$^R }) false (?{ say $i x $l,'->false' if TRACE_JSON; [$^R, 0] })
        |
        (?{ say $i x $l,'try null'  if TRACE_JSON;$^R }) null  (?{ say $i x $l,'->null' if TRACE_JSON; [$^R, undef] })
        ) 
        \s* (?{ say $i x $l--,'end of value' if TRACE_JSON;$^R })
      )
    
      (?<OBJECT> # will generate a Perl hash
        (?{ [$^R, {}] })  # init structure
        \{ # start of object
          \s*
          (?: 
            (?&KV) # [[$^R, {}], $k, $v]   # first pair 
            (?{ say($i x $l,'first object pair ', Dumper($^R)) if TRACE_JSON; [$^R->[0][0], {$^R->[1] => $^R->[2]}] })
      
            (?: # additional pairs 
            \s* , \s* (?&KV) # [[$^R, {...}], $k, $v]
              (?{ say($i x $l,'additional object pair ', Dumper($^R)) if TRACE_JSON; [$^R->[0][0], {%{ $^R->[0][1]}, $^R->[1] => $^R->[2]}] })
            )* # additional pairs are optional
          )? # object may be empty
        \}  # end of object
      )
    
      (?<KV>  # tuple <key, value>
        (?{ say $i x $l,'tuple rule' if TRACE_JSON;$^R })
        (?&STRING) # [$^R, "string"]
        \s* : \s* (?&VALUE) # [[$^R, "string"], $value]
      
        (?{ say $i x $l,'->have tuple' if TRACE_JSON; [$^R->[0][0], $^R->[0][1], $^R->[1]] })
      )
    
      (?<ARRAY> # will generate a Perl array
        (?{ [$^R, []] })  # init structure
        \[ # start of array
          (?: 
            (?&VALUE)   # first element 
            (?{ say($i x $l,'first array item ', Dumper($^R)) if TRACE_JSON; [$^R->[0][0], [$^R->[1]]] })
      
            (?: # additional elements
            \s* , \s* (?&VALUE) # additional elements
              (?{ say($i x $l,'additional array item ', Dumper($^R)) if TRACE_JSON; [$^R->[0][0], [@{$^R->[0][1]}, $^R->[1]]] })
            )* # additional elements are optional
          )? # array may be empty
        \] # end of array
      )
    
      (?<STRING> (?{ say $i x $l,'string rule' if TRACE_JSON;$^R })
        (
          "
          (?:
            [^\\"]+
          |
            \\ ["\\bfnrt]  # escaped backspace, form feed, newline, carriage return, tab, \, "
          |
            \\ u [0-9a-fA-F]{4} 
          )*
          "
        )
        (?{ 
            my $s = $^N; 
            $s =~ s/\\u([0-9A-Fa-f]{4})/\\x{$1}/g;
            $s =~ s/@/\\@/g;
            my $v = eval $s;
            say $i x $l,"->have string '$v'" if TRACE_JSON;
            [ $^R, $v ] })
      )
    
      (?<NUMBER> (?{ say $i x $l,'number rule' if TRACE_JSON;$^R })
        (
          -?
          (?: 0 | [1-9]\d* )
          (?: \. \d+ )?
          (?: [eE] [-+]? \d+ )?
        )
        (?{ my $v = eval $^N;
            say $i x $l,"->have number $v" if TRACE_JSON; 
            [$^R, $v] })
      )
    
    ) #DEFINE
    }xms;
    my $struct;
    {
        local $_ = shift;
        local $^R;
        eval { m{\A$rx\z}; } and $struct = $_;
    }
    return $struct;
}
