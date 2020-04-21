use strict;
use warnings;
use feature 'say';
use utf8;
use open ':std', ':encoding(UTF-8)';
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 0;    # compact dump

my $data = $ARGV[0] || '{"id":42}';
if (-f $data){
    open my $f, '<', $data or die "cannot open $data: $@";
    $data = do { local $/; <$f> };
    close $f;
}

my $o = from_json($data);
$Data::Dumper::Indent   = 2;    # fancy dump
say Dumper $o;

sub TRACE_JSON {0}

sub eval_json_string {
    my $s = shift;
    $s =~ s/\\u([0-9A-Fa-f]{4})/\\x{$1}/g;
    $s =~ s/@/\\@/g;
    return eval $s;
}

my @eval_stack;

sub dump_stack  { say "stack is ",scalar(@eval_stack),' =>' , Dumper(\@eval_stack) }
sub push_val    { push @eval_stack, shift; }
sub peek_val    { my $idx = shift || -1; return $eval_stack[ $idx ]; }
sub pop_val     { return pop @eval_stack; }
sub add_obj_val { my ($k,$v) = @_; $eval_stack[-1]->{$k} = $v; }
sub add_arr_val { my $v = shift; push @{$eval_stack[-1]}, $v; }

# Return a Perl structure corresponding to a json string
sub from_json {
    my $i = '⋅';                # indent char
    my $l = 0;                  # indent level
    say "Initial stack is ", Dumper(\@eval_stack) if TRACE_JSON;
    my $rx = qr{

    # NOTES:
    # this regex is a recusrive descent parser - see https://www.perlmonks.org/?node_id=995856
    # and chapter 1 "Recursive regular expressions" of Mastering Perl (Brian d Foy)
    #
    # Inside the block (?(DEFINE) ...)  (?<FOOBAR> ...) defines a named pattern FOOBAR
    #                                   that can be called with (?&FOOBAR)
    # (?{ ... }) is a block of Perl code that is evaluated at the time we reach it while running the pattern
    # $^R is the value returned by the LAST runned (?{ }) block, so it is overriden at each (?{ ... })
    #     if you want to run random code, remember to add $^R as last statement to always keep the value
    # $^N is the last matched (non-anonymous) group

    (?&VALUE) (?{ $_ = pop_val() }) # <== entry point of the parser

    (?(DEFINE) # this does not try to match, it only defines a serie of named patterns

     (?<VALUE>
      \s*+
      (
      (?&STRING)
      |
      (?&NUMBER)
      |
      (?&OBJECT)
      |
      (?&ARRAY)
      |
      true (?{ push_val(1) })
      |
      false (?{ push_val(0) })
      |
      null (?{ push_val(undef) })
      )
      \s*+
     )

     (?<OBJECT> # will generate a Perl hash
       \{ # start of object 
         (?{ push_val({}); }) # init structure
         \s*+
         (?: 
           (?&KV) # first pair
           (?{ 
               my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v);
           })
           (?: # additional pairs 
             \s* , \s* (?&KV)
             (?{ 
                 my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v);
             })
           )* # additional pairs are optional
         )? # object may be empty
         \s*+ 
       \}
     )

     (?<KV> # tuple <key, value>
       (?&STRING) \s*+ : \s*+ (?&VALUE)
       (?{

       })
     )

     (?<ARRAY> # will generate a Perl array
       \[ 
         (?{ push_val([]); }) # init structure
         \s*+
         (?: # first element 
           (?&VALUE) 
           (?{  my $v = pop_val(); add_arr_val( $v )
           })
           (?: # additional elements
             \s*+ , \s*+ (?&VALUE) 
             (?{
                 my $v = pop_val(); add_arr_val( $v )
             })
           )*  # additional elements are optional
         )? # array may be empty
         \s*+ 
       \]  # end of array
     )

     (?<STRING>
       (
         "
         (?:
           [^\\"]+
           |
           \\ ["\\/bfnrt]
           |
           \\ u [0-9a-fA-f]{4}
         )*+
         "
       )

       (?{ 
            my $v = eval_json_string($^N); 
            push_val($v);
       })
     )

     (?<NUMBER>
       (
         -?
         (?: 0 | [1-9]\d*+ )
         (?: \. \d+ )?
         (?: [eE] [-+]? \d+ )?
       )
       (?{ 
           my $v = eval $^N;
           push_val($v);
       })
     )
    ) #End of DEFINE
    }xms;
    my $struct;
    {
        local $_ = shift;
        local $^R;
        eval { m{\A$rx\z}; } and $struct = $_;
        say "eval error: $@" if $@;
    }
    return $struct;
}
