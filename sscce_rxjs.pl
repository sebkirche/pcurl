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
    # $s =~ s/\\u([0-9A-Fa-f]{4})/\\x{$1}/g;
    # $s =~ s/@/\\@/g;
    # return eval $s;
    return $s;
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
    
      (?<OBJECT> # will generate a Perl hash
        \{ # start of object 
          (?{ push_val({}); }) # init structure
          \s*+
          (?: 
            (?&KV) # first pair 
            (?{ say($i x $l,'first object pair ', Dumper([ peek_val(-2),peek_val(-1)])) if TRACE_JSON; my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v); })
      
            (?: # additional pairs 
            \s*+ , \s*+ (?&KV)
              (?{ say($i x $l,'additional object pair ', Dumper([ peek_val(-2),peek_val(-1) ])) if TRACE_JSON; my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v), })
            )* # additional pairs are optional
          )? # object may be empty
        \s*+ \}  # end of object
      )
    
      (?<KV>  # tuple <key, value>
        (?{ say $i x $l,'tuple rule' if TRACE_JSON; $l++; })
        (?&STRING) \s*+ : \s*+ (?&VALUE)
      
        (?{ $l--; say($i x $l,'->have tuple ', Dumper([peek_val(-2),peek_val(-1)]) ) if TRACE_JSON; })
      )
    
      (?<ARRAY> # will generate a Perl array
        \[ \s*+ # start of array 
          (?{ push_val([]); }) # init structure
          (?: 
            (?&VALUE)   # first element 
            (?{ say($i x $l,'first array item ', peek_val(-1)) if TRACE_JSON; my $v = pop_val(); add_arr_val( $v ) })
      
            (?: # additional elements
            \s*+ , \s*+ (?&VALUE) # additional elements
              (?{ say($i x $l,'additional array item ', peek_val(-1)) if TRACE_JSON; add_arr_val( pop_val() ) })
            )* # additional elements are optional
          )? # array may be empty
        \s*+ \] # end of array (?{ say $i x $l,'->array: ',Dumper(\@eval_stack) })
      )
    
      (?<VALUE> (?{ say $i x $l++,'Value?' if TRACE_JSON })
        \s*+
        (
        (?{ say $i x $l,'try string' if TRACE_JSON; }) (?&STRING)
        |
        (?{ say $i x $l,'try number' if TRACE_JSON; }) (?&NUMBER) (?{ say $i x $l,'post number' if TRACE_JSON })
        |
        (?{ say $i x $l,'try object' if TRACE_JSON; $l++; }) (?&OBJECT)
        |
        (?{ say $i x $l,'try array'  if TRACE_JSON; $l++; }) (?&ARRAY) (?{ $l-- })
        |
        (?{ say $i x $l,'try true'  if TRACE_JSON; }) true  (?{ say $i x $l,'->true' if TRACE_JSON; push_val(1) })
        |
        (?{ say $i x $l,'try false'  if TRACE_JSON; }) false (?{ say $i x $l,'->false' if TRACE_JSON; push_val(0) })
        |
        (?{ say $i x $l,'try null'  if TRACE_JSON; }) null  (?{ say $i x $l,'->null' if TRACE_JSON; push_val(undef) })
        ) 
        \s*+ (?{ $l--; say ($i x $l,'->have value: ', Dumper(peek_val)) if TRACE_JSON; })
      )
    
      (?<STRING> (?{ say $i x $l,'string rule' if TRACE_JSON;$^R })
        (
          "
          (?:
            [^\\"]++
          |
            \\ ["\\/bfnrt]  # escaped backspace, form feed, newline, carriage return, tab, \, "
#          |
#            \\ u [0-9a-fA-F]{4} 
          )*+
          "
        )
        (?{ 
            my $v = $^N; #eval_json_string($^N); 
            say $i x $l,"->have string '$v'" if TRACE_JSON;
            push_val($v) })
      )
    
      (?<NUMBER> (?{ say $i x $l,'number rule' if TRACE_JSON;$^R })
        (
          -?
          (?: 0 | [1-9]\d*+ )
          (?: \. \d+ )?
          (?: [eE] [-+]? \d+ )?
        )
        (?{ my $v = eval $^N;
            say $i x $l,"->have number $v" if TRACE_JSON; 
            push_val($v); })
      )
    
    ) #DEFINE
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
