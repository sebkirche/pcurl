#!/usr/bin/env perl

# pCurl - a cURL-like implemented in Perl
#         with built-in json and xml parsers
#         and custom features like STOMP message sending
#
# (c) 2019, 2020, 2022 - Sébastien Kirche

package Pcurl;

use Exporter qw/import/;
@EXPORT_OK = qw/hexdump parse_uri process_http/;

use warnings;
use strict;
use feature 'say';
use feature 'state';
use utf8;
use open ':std', ':encoding(UTF-8)';
use version;
use Data::Dumper;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 2;
use Getopt::Long qw(:config no_ignore_case bundling auto_version); # debug
use IO::Select;
use IO::Socket::INET;
use IPC::Open3;
use MIME::Base64 'encode_base64';
use Pod::Usage;
use Socket qw( IPPROTO_TCP TCP_NODELAY );
use Symbol qw( gensym );
use Time::Local;
# use Carp::Always;

our $VERSION = '0.9.9';
$|++; # auto flush messages

# vars declared before signal handlers because we show a message using them
my %args;
my %processed_request;          # Requests done, for not doing again

# -------- Signal handlers -------------------------
BEGIN{                          # automagic breakpoint for warnings when script is run by perl -d
    $SIG{__WARN__} = sub {
        my $msg = shift;
        chomp $msg;
        say STDERR "Warning: '$msg'";
        no warnings 'once';     # avoid « Warning: 'Name "DB::single" used only once: possible typo »
        $DB::single = 1;        # we stop execution if a warning occurs during run
    };
}
sub tell_recursive {
    if ($args{recursive}){
        say STDERR sprintf("%d link%s processed. Enter Ctrl-C twice to stop.", scalar(keys %processed_request), (scalar keys %processed_request > 1 ? 's' : '')) if $args{recursive};
    }
}
$SIG{INT}  = sub {
    state $last_time = 0;
    my $now = time;
    if ($now - $last_time <= 1){ # Ctrl-C x2 within 1 second
        say STDERR "SIGINT / CTRL-C received (Interrupt from keyboard). Leaving.";
        exit;
    }
    tell_recursive();
    $last_time = $now;
};
$SIG{QUIT} = sub {
    tell_recursive();
    say STDERR "SIGQUIT / CTRL-\\ received (Quit from keyboard). Leaving.";
    exit };
$SIG{ABRT} = sub { say STDERR "SIGABRT received (Probable abnormal process termination requested by a library). Leaving."; exit };
$SIG{TERM} = sub { say STDERR "SIGTERM received - External termination request. Leaving."; exit };
sub suspend_trap {
    say STDERR "SIGTSTP / CTRL-Z received. Suspending...";
    $SIG{TSTP} = 'DEFAULT';
    kill 'TSTP', -(getpgrp $$);
}
$SIG{TSTP} = \&suspend_trap;
$SIG{CONT} = sub { $SIG{TSTP} = \&suspend_trap; say STDERR "SIGCONT received - continue after suspension." };

# the exit_hook is a hack to not terminate the program on exit() when it is called as package
# because the code has been written initially as a program and can exit with a set of return codes
our $do_not_terminate_on_exit = 0;
BEGIN { 
    sub exit_hook(;$) {
        no warnings qw( exiting );
        my $val = $_[0] // 0;
        # say "exit($_[0]) called";
        my ($package, $filename, $line, $subroutine, $hasargs, $wantarray, $evaltext, $is_require, $hints, $bitmask, $hinthash) = caller(0);
        say "exit($val) called from $filename:$line";
        # my $w = (caller(1))[3];
        # say "exit($_[0]) called from $w";
        last EXIT_OVERRIDE if $do_not_terminate_on_exit;
        CORE::exit($_[0] // 0);
    };
    *CORE::GLOBAL::exit = *exit_hook;
}
# --------------------------------------------------

my $max_redirs = 50;            # default value for maximum redirects to follow
my $max_levels = 5;             # default max recursion level
my $def_max_wait = 10;          # default value for response timeout
my %defports = ( http  => 80,   # default ports
                 https => 443,
                 stomp => 61613,
                 dict  => 2628
    );
my $default_page = 'index.html'; # default name for directory index

# when writing output in a file, holder of the initial STDOUT
# my $STDOLD;
my @output_stack = ( *STDOUT );
# my $current_output = $output_stack[0];
# my $is_out_redirected = 0;

my ($http_vers, $tunnel_pid, $auto_ref, $use_cookies, $cookies, $process_action);
my %rel_url_to_local_dir;

my $index_name;
my $acceptrx;
my $rejectrx;
my $prefix = '';
my %broken_url;                 # URLs that are not valid
my %failed_url;                 # URLs that resulted in failure
my %discovered_url;
my $asset_counter = 0;

%args = ( 'tcp-nodelay'      => 1,
          'data-urlencode'   => [],
          header             => [],
          'json-pp-indent'   => 2,
          'user-agent'       => "pCurl/$VERSION",
          'xml-pp-indent'    => 2,
          'xml-root-element' => 'root'
    );

$http_vers = '1.1';             # default version we want for http

__PACKAGE__->cli( @ARGV ) if !caller() || caller() eq 'PAR'; # handles package called as a script

sub cli {

my @getopt_defs = (
    'accept=s',
    'action=s',
    'action-nullable-values',
    'action-res-delimiter=s',
    'basic|user=s',
    'content=s',
    'cookie|b=s',
    'cookie-jar|c=s',
    'data-binary=s',
    'data-raw=s',
    'data-urlencode=s@',
    'data|data-ascii|d=s',
    'debug',
    'debug-urls',
    'debug-json=s',
    'debug-json-export',
    'fail|f',
    'fail-with-body',
    'header|H=s@',
    'head|I',
    'help|h|?',
    'include-response|include|i',
    'include-request',
    'insecure|k',
    # 'ipv4|4',                   # TODO
    # 'ipv6|6',                   # TODO
    'json=s',
    'json-pp',
    'json-pp-indent=i',
    'json-stringify-null',
    'junk-session-cookies',
    'location|follow|L',
    'man',
    'max-wait=i',
    'max-redirs=i',
    'noproxy=s',
    'output|o=s',
    'parse-only',               # just show how we parse the URL
    'port|p=i',
    'progression|progress',
    'proxy-user|U=s',
    'proxy10=s',
    'proxy|x=s',
    'remote-header-name|J',
    'remote-name|O',
    'remote-time|R',
    'referer|e=s',
    'request|X=s',
    'silent|s',
    'ssl-ca|cacert=s',
    'ssl-cert|cert=s',
    'ssl-key|key=s',
    'sslv3|3',
    # 'stompdest=s',
    'stompmsg=s',
    'stompread',
    'tcp-nodelay!',             # negatable: --notcp-nodelay
    'tlsv1_0|tlsv1|1',
    'tlsv1_1',
    'tlsv1_2',
    'tlsv1_3',
    'url=s',
    'user-agent|A=s',
    'verbose|v',
    'version|V',                # comment this out to have the built-in version handler that shows program/Getopt/Perl versions
    # 'xml-decl=s',
    'xml-pp',
    'xml-pp-indent=i',
    'xml-root-element=s',
    # recursive options -------------------------------
    'accept-list=s',            # a coma-separated list
    'accept-regex=s',
    'cut-dirs=i',
    'directory-prefix|P=s',
    'default-page=s',
    'level|l=i',
    'no-host-directories',
    'no-parent|np',
    'page-requisites',
    'recursive|r',
    'recursive-flat|F',
    'relative',
    'reject-list=s',            # a coma-separated list
    'reject-regex=s',
    'span-hosts',
    'summary',
    );

if ($Getopt::Long::VERSION >= '2.39') { # Getopt::Long does not support alias with dots before 2.39
    push (@getopt_defs,
          'http09|http0.9',
          'http10|0|http1.0',
          'http11|http1.1');
} else {
    push (@getopt_defs,
          'http09',
          'http10',
          'http11');
}

GetOptions(\%args, @getopt_defs ) or pod2usage(-exitval => 2, -verbose => 0);
pod2usage(-exitval => 0, -verbose => 1) if $args{help};
pod2usage(-exitval => 0, -verbose => 2) if $args{man};

if ($args{action} && $args{action} eq 'help:'){
    parse_process_action($args{action}); # will exit
}

if ($args{version}){
    say "pcurl $VERSION";
    exit 0;
}

if ($args{'debug-json'}){
    say STDERR "Testing JSON parser...";
    if ($args{'debug-json'} eq '-'){
        my @lines = <STDIN>;
        $args{'debug-json'} = join '', @lines;
    } elsif (-r $args{'debug-json'}){
        open (my $fh, '<', $args{'debug-json'}) or die "Cannot open $args{'debug-json'}: $!";
        local $/;
        $args{'debug-json'} = <$fh>;
        close $fh;
    }
    say STDERR "Reading done. Parsing...";
    my $obj = from_json($args{'debug-json'});
    say STDERR "Parsing done. Dumping...";
    if ($args{'debug-json-export'}){
        say to_json($obj);
    } else {
        say Data::Dumper->Dump([$obj],[ 'json' ]);
    }
    exit 0;
}

# Referer provided, or auto-referer?
# auto-referer is: take the url of the previous url as referer when following redirects 
if ($args{referer} && $args{referer} =~ /([^;]*)?;auto/){
    $auto_ref = 1;
    $args{referer} = $1;
}

# Cookies
if ($args{cookie} || $args{'cookie-jar'}){
    $use_cookies = 1;
    if ($args{cookie}){
        # parameter is either a file name or a literal cookie
        if (-f $args{cookie}){
            $cookies = load_cookie_jar($args{cookie});
            say STDERR "Cookies from jar:", Dumper $cookies if $args{debug};
            if ($args{'junk-session-cookies'}){
                # keep cookies with expiration (if not it's a session cookie)
                $cookies = [ grep { $_->{expires} } @$cookies ];
            }
        } else {
            $cookies = load_commandline_cookies($args{cookie});
            say STDERR "Cookies from command-line:", Dumper $cookies if $args{debug};
        }
    }
    # keep non-expired cookies
    my $now = time;
    $cookies = [ grep { !$_->{expires} || ($_->{expires} >= $now) } @$cookies ];
    say STDERR "Cookies from jar after purge and expiration:", Dumper $cookies if $args{debug};
}

# shortcut to -H 'Accept: mime'
if ($args{accept}){
    push @{$args{header}}, "Accept: $args{accept}";
}

# shortcut for json payloads
if ($args{json}){
    push @{$args{header}}, "Content-Type: application/json";
    push @{$args{header}}, "Accept: application/json";
    $args{data} = $args{json};
}

my $cli_url = $args{url} || $ARGV[0];
unless ($cli_url){
    say STDERR "No url provided...";
    pod2usage(-exitval => 1);
}

$acceptrx = $args{'accept-regex'};
$rejectrx = $args{'reject-regex'};
$acceptrx = '(' . join ('|', split(/,/, $args{accept})) . ')$' if $args{accept}; 
$rejectrx = '(' . join ('|', split(/,/, $args{reject})) . ')$' if $args{reject};

$index_name = $args{'default-page'} || $default_page;
if ($args{'directory-prefix'}){
    $prefix = $args{'directory-prefix'};
    $prefix .= '/' if $prefix !~ m{/$};
}

if ($args{'parse-only'}){
    my $uri = validate_uri($cli_url);
    if ($uri){
        dump_url($uri);
        exit 0;
    } else {
        exit 1;
    }
}

process_loop([$cli_url], $args{level} // $max_levels);
say STDERR sprintf("* %d link%s processed", scalar(keys %processed_request), (scalar keys %processed_request > 1 ? 's' : '')) if $args{recursive} && ($args{summary} || $args{verbose} || $args{debug});
if ($args{summary}){
    for my $r (sort keys %processed_request){
        if ($processed_request{$r} > 1){
            say STDERR sprintf("%s x %d", $r, $processed_request{$r});
        } else {
            say STDERR $r;
        }
    }
    say STDERR sprintf("* %d Broken URLS:", scalar keys %broken_url) if keys %broken_url;
    say STDERR $_ for sort keys %broken_url;
    say STDERR sprintf("* %d Failed URLS (can be due to dumb url detection):", scalar keys %failed_url) if keys %failed_url;
    say STDERR "$_ -> $failed_url{$_}" for sort keys %failed_url;
}


}

# ------- End of main prog ---------------------------------------------------------------

# TODO this need a refactor to pass arguments to process_http
sub simulate_cli_settings {
    my %params = @_;

    %args = (%args, %params);
}

sub process_loop {
    my ($request_list, $level) = @_;
    my @discovered_at_this_level;

    say STDERR "List of urls for this round:\n" . join("\n", @$request_list) if $args{recursive} && ($args{verbose} || $args{debug});

  REQUEST:
    while (@$request_list){

        my $req = shift @$request_list;
        my $url = validate_uri($req);
        unless ($url){
            $broken_url{$req}++;
            next REQUEST if $args{recursive}; # a broken url is not fatal in recursive mode
            exit 1;
        }

        # complete some default values in case of relative link
        $url = complete_url_default_values($url);

        my $ustr = sprintf("%s://%s%s%s%s",
                            $url->{scheme},
                            auth_string($url),
                            $url->{host} || '',
                            defined $url->{port} ? sprintf(':%d', $url->{port}) : '',
                            canonicalize($url->{path}));
        $asset_counter++;
        if ($url->{scheme} =~ /^http/){
            # HTTP or HTTPS
            # version
            if ($args{http09}){
                $http_vers = '0.9';
            } elsif ($args{http10}){
                $http_vers = '1.0';
            } elsif ($args{http11}){
                $http_vers = '1.1';
            } else {
                $http_vers = '1.1'; # default HTTP version when not specified
            }
            
            if ($args{request}){
                if ($args{request} =~ /^(GET|HEAD|POST|PUT|TRACE|OPTIONS|DELETE)$/i){
                    $args{request} = uc $args{request};
                    if ($args{request} ne 'GET' and HTTP09()){
                        say STDERR "HTTP/0.9 only supports GET method.\n" ;
                        exit 2;
                    }
                } else {
                    # Nothing, one can have a custom HTTP method
                }
            }
            
            my $method;
            if ($args{data} || @{$args{'data-urlencode'}} || $args{'data-binary'} || $args{'data-raw'}){
                $method = $args{request} || 'POST';
            } else {
                $method = $args{head} ? 'HEAD' : $args{request} || 'GET';
            }
            #$url->{path} = '*' if $method eq 'OPTIONS';
            # say STDERR $url->{url} if $args{progression} || $args{verbose} || $args{debug};
            unless (exists $processed_request{$req}){
                # lazy downloader: do it only once
                my $r = process_http(method     => $method,
                                     url        => $url,
                                     discovered => ($level ||
                                                    (defined $args{level} && $args{level} == 0)) ? \@discovered_at_this_level : undef
                    );
                # response might be undef after timeout
                $failed_url{$req} = $r->{status}{code} if defined $r->{status} && $r->{status}{code} >= 400 && $r->{status}{code} <= 599;
                    
                say STDERR sprintf("%s -> %s", $url->{url}, humanize_bytes($r->{body_byte_len})) if $r->{body_byte_len} && ($args{progression} || $args{verbose} || $args{debug});
            }
            $processed_request{$req}++;
            
        } elsif ($url->{scheme} =~ /^stomp(?:\+ssl)?$/){
            unless ($url->{path} && ($args{stompmsg} || $args{stompread})){
                say STDERR "Message sending with --stompmsg <message> or reading with --stompread is supported for now.";
                exit 3;
            }
            process_stomp($url);
        } elsif ($url->{scheme} eq 'file'){
            unless ( ! defined $url->{host}
                     || lc($url->{host}) eq 'localhost'
                     || $url->{host} eq '127.0.0.1'){
                say STDERR "* Invalid file://hostname/, expected localhost or 127.0.0.1 or none";
                exit 4;
            }
            process_file($url, \@discovered_at_this_level);
        } else {
            say STDERR "Unknown scheme $url->{scheme}";
            exit 14;
        }
    }
    # if we need to process a next level of links in recursive crawler mode
    # call us recursively TODO: maybe we could just push in $request_list and return to loop
    #                                               instead of recurse using a doouble while
    # FIXME: $process_action has been changed by side-effect of process_http()
    if (($args{recursive} || $process_action && index($process_action->{what}, 'getlinked')==0)
        && @discovered_at_this_level
        && (
            $level > 0
            || (defined $args{level} && $args{level} == 0)
        )
        ){
        say STDERR "* processing next level" if $args{verbose} || $args{debug};
        my $next_level;
        if (defined $args{level} && $args{level} > 0){
            $next_level = $level - 1;
        } else {
            $next_level = 1;
        }
        process_loop(\@discovered_at_this_level, $next_level);
    }
}

sub prefix_print {
    my ($fd, $prefix, $text) = @_;
    foreach my $line (split /\n/, $text){
        print $fd $prefix . $line . "\n";
    }
}

sub current_output {
    # my $line = [caller(0)]->[2];
    # my $sub = [caller(1)]->[3];
    # say STDERR "DBG: " . scalar @output_stack . " from $sub at $line";
    return $output_stack[$#output_stack];
}

# redirect STDOUT to a file
# unless the out name is '-' to allow binary output to STDOUT
sub redirect_output_to_file {
    my $out_name = shift;
    # say STDERR "redirect -> $out_name";
    if ($out_name && $out_name ne '-'){
        # open $STDOLD, '>&', STDOUT;
        my $new_fd = gensym();
        open $new_fd, '>', $out_name or die "Cannot open '$out_name' for output.";
        push @output_stack, $new_fd;
        # my $line = [caller(0)]->[2];
        # my $sub = [caller(1)]->[3];
        # say "DBG: redirect_output_to_file called from $sub at $line";
        # say STDERR "DBG: output_stack++ (" . $out_name . ") " . join(' ', @output_stack);
        # binmode(STDOUT, ":raw");
        # later, to restore STDOUT:
        # open (STDOUT, '>&', $STDOLD);
        # $is_out_redirected = 1;
        # say STDERR "output is " . current_output;
    }
}

# close out file and restore STDOUT
sub restore_output {
    # my $out_name = $args{output};
    # if ($is_out_redirected && (defined fileno($current_output) && fileno($current_output) != fileno(STDOUT))){
    if (scalar @output_stack > 1){
        close current_output();
        # open (STDOUT, '>&', $STDOLD);
        # $current_output = *STDOUT;
        # $is_out_redirected = 0;
        pop @output_stack;
        # say STDERR "DBG: output_stack-- " . join(' ', @output_stack);
        # say STDERR "restore_output to " . current_output;
    }
}

# parse uri and print message if unsuccessful
sub validate_uri {
    my $uri = shift;
    my $parsed = parse_uri($uri);
    unless ($parsed){
        say STDERR "It's strange to me that `$uri` does not look like a valid URI...";
    }
    return $parsed;
}

# perform an HTTP[S] request / response
sub process_http {
    my %params = @_;
    
    my $method = $params{method};
    my $url_final = $params{url};
    my $discovered_links =  $params{discovered};
    
    my ($IN, $OUT, $ERR, $host, $port, $resp, $following, $error_code);

    $max_redirs = $args{'max-redirs'} if defined $args{'max-redirs'};
    my $redirs = $max_redirs;   # redirs is a countdown of remaining allowed redirections

    # Action is either a specific value to extract from the result (header, json field)
    # an can be more sophisticated actions
    if ($args{action}){
        # FIXME: bad, bad, bad: should not use that global var anymore
        $process_action = parse_process_action($args{action});
        $process_action->{done} = undef;
    }

    my $fname;
    my $out_file;

    my $next_url;
    my $no_follow_after_body = 0; # flag if we want to break the follow loop
  REDIRECT:
        # we can loop in case of 3xx redirect
    do {
        say STDERR "* Processing url $url_final->{url}" if $args{verbose} || $args{debug};
        $next_url = '';

        # set the filename for output when redirecting or using url name
        if ($args{output}){
            $fname = $args{output};
        } elsif ($args{'remote-name'} && !$args{'remote-header-name'}){
            if ($rel_url_to_local_dir{$url_final->{url}}){
                # if this is a file from crawler mode
                $fname = $rel_url_to_local_dir{$url_final->{url}};
                if ($fname =~ m{/$}){
                    $fname .= "${index_name}";
                }
            } elsif ($url_final->{path} =~ m{.*/([^/]+)$}){
                # get filename from url
                if ($args{recursive} && !$args{'recursive-flat'}){
                    $fname = urldecode($&);
                } else {
                    $fname = urldecode($1);
                }
                $fname = substr($fname, 1) if $fname =~ m{^/}; # drop initial /
            } elsif ($url_final->{path} =~ m{/$}){
                $fname = $url_final->{path} . ${index_name};
                $fname = substr($fname, 1); # drop initial /
            } else {
                unless ($following || $process_action && index($process_action->{what}, 'getlinked') == 0){
                    say STDERR "Cannot get remote file name from url.";
                    exit 7;
                }
            }
        }
        if ($fname && $fname ne '-'){
            # process cut-dirs
            if ($args{'cut-dirs'}){
                # split the path segments
                my @path = split(m{/}, $fname);
                my $f = pop @path;  # keep the file
                # remove the required number of elements
                if ($args{'recursive-flat'}){
                    @path = ();
                } else {
                    for (my $i=1; $i <= $args{'cut-dirs'}; $i++){
                        shift @path;
                    }
                }
                if (@path){
                    $fname = join('/', @path) . "/$f";
                } else {
                    $fname = $f;
                }
            }
            my $h = '';
            if ($args{recursive} && !$args{'no-host-directories'}){
                $h = $url_final->{host};
                if ($url_final->{port} != $defports{$url_final->{scheme}}){
                    $h .= ':' . $url_final->{port};
                }
                $h .= '/';
            }
            $out_file = "${prefix}${h}${fname}";
            # make_path($out_file);
            # redirect_output_to_file($out_file);
        }
        
        my $redirect_pending = 0;
        my $discard_output_creation = 0;
        my $url_proxy = get_proxy_settings($url_final);
        my $pheaders = [];
        if ($url_proxy){
            if ($url_final->{scheme} eq 'https' && $url_proxy->{auth}){
                # try to get the openSSL version
                my $ver = `openssl version` or die "Cannot get openssl version: $!";
                chomp $ver;
                say STDERR "* https tunelling via openSSL is unlikely to work unless openSSL is v3.0-beta1 (found $ver)!";
            }
            $pheaders = build_http_proxy_headers($url_proxy, $url_final);
            $url_final->{proxified} = 1 if $url_final->{scheme} eq 'http'; # direct
            $url_final->{tunneled} = 1 if $url_final->{scheme} eq 'https'; # openSSL
        }

        # connect directly a socket to the server or to a proxy
        # or open a tunnel for HTTPS
        if ($url_proxy){
            ($OUT, $IN, $ERR) = connect_direct_socket($url_proxy->{host},
                                                      $url_proxy->{port}) if $url_final->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final, $url_proxy) if $url_final->{scheme} eq 'https';
        } else {
            ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host},
                                                      $url_final->{port}) if $url_final->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final) if $url_final->{scheme} eq 'https';
        }

        my $body = prepare_http_body_to_post();
        my $headers = build_http_request_headers($method, $url_final, $url_proxy, $body);
        if ($url_final->{proxified} && @$pheaders){
            # ask proxy to connect
            send_http_request($IN, $OUT, $ERR, $pheaders, undef);
            my $presp = process_http_response_headers(IN  => $IN,
                                                      ERR => $ERR,
                                                      url => $url_proxy);
            say STDERR "* Proxy returned " . $presp->{status}->{code} . " / " . $presp->{status}->{message} if $args{verbose} || $args{debug};
            unless ($presp->{status}->{code} == 200){
                say STDERR sprintf "Proxy connection unsuccessful: %d / %s", $presp->{status}->{code}, $presp->{status}->{message};
                goto BREAK;
            }
        }

        say STDERR "* Sending request to server" if $args{verbose} || $args{debug};

        # Write to the server
        send_http_request($IN, $OUT, $ERR, $headers, $body);
        
        # Receive the response
        if (!HTTP09()){
            # there is no header in HTTP/0.9
            $resp = process_http_response_headers(IN        => $IN,
                                                  OUT       => current_output(),
                                                  ERR       => $ERR,
                                                  url       => $url_final,
                                                  url_proxy => $url_proxy,
                                                  out_file  => $fname,
                                                  follow    => $following);
            print {current_output} ${$resp->{captured_head}} if ($args{head} || $args{'include-response'} || $args{verbose}) && defined ${$resp->{captured_head}};
            say STDERR "* received $resp->{head_byte_len} headers bytes" if $args{verbose} || $args{debug};
            say STDERR Dumper $resp if $args{debug};
            if ($resp->{head_byte_len}){
                my $code = $resp->{status}{code};
                say STDERR '* ' . $url_final->{url} . ' -> ' . $code if $args{verbose} || $args{debug};
                say STDERR Dumper $resp->{headers} if $args{debug};
               
                if ($args{location} && $code && (300 < $code) && ($code <= 399)){
                    # we want to follow redirects and we have a redirect
                    unless($redirs){
                        say STDERR sprintf("* Maximum (%d) redirects followed", $max_redirs);
                        $no_follow_after_body = 1;
                    } else {
                        $redirect_pending = 1;
                    }
                    my ($old_scheme, $old_host, $old_port) = ($url_final->{scheme}, $url_final->{host}, $url_final->{port});

                    my $redirected_url = get_redirected_url($url_final, $resp->{headers}{location});

                    # check to prevent full site download because of a redirect (eg: a link get a 302 to the root dir)
                    my $cur = canonicalize($url_final->{url});
                    my $next = canonicalize($redirected_url->{url});
                    if (!is_descendant_or_equal($next, $cur) && $args{'no-parent'}){
                        say STDERR "* ignoring redirected url $redirected_url->{url} from $url_final->{url} because of --no-parent" if $args{verbose} || $args{debug} || $args{'debug-urls'};
                        goto BREAK;
                    }
                    $url_final = $redirected_url;
                    $next_url = $url_final->{url};
                    
                    # compare new url with previous and reconnected if needed
                    if (($url_final->{scheme} ne $old_scheme) || ($url_final->{host} ne $old_host) || ($url_final->{port} != $old_port)){
                        say STDERR "* Closing connection because of scheme/server redirect" if $args{verbose} || $args{debug};
                        say STDERR sprintf("* scheme %s -> %s", $old_scheme, $url_final->{scheme}) if $url_final->{scheme} ne $old_scheme && $args{verbose} || $args{debug};
                        say STDERR sprintf("* host %s -> %s", $old_host, $url_final->{host}) if $url_final->{host} ne $old_host && $args{verbose} || $args{debug};
                        say STDERR sprintf("* port %s -> %s", $old_port, $url_final->{port}) if $url_final->{port} ne $old_port && $args{verbose} || $args{debug};
                        close $IN;
                        close $OUT;
                        close $ERR if $ERR;
                    }
                    say STDERR sprintf("* Redirecting #%d to %s", $max_redirs - $redirs,  $url_final->{url}) if $args{verbose} || $args{debug} || $args{'debug-urls'};
                    $redirs--;
                } elsif ($code == 300){
                    # server do not know what to serve
                    say STDERR "* 300 'Multiple Choices' on $url_final->{url}" if $args{verbose} || $args{debug};
                    $discard_output_creation = 1;
                } elsif ($code >= 400 && $code <= 599){
                    # something is wrong
                    say STDERR "* $code on $url_final->{url}" if $args{verbose} || $args{debug};
                    if ($args{fail} || $args{'fail-with-body'}){
                        # we are not in crawling mode
                        # $error_code = $code; # FIXME: max is 255
                        $error_code = 11 if $code >= 400 && $code <= 499;
                        $error_code = 12 if $code >= 500 && $code <= 599;
                        $no_follow_after_body = 1;
                        goto BREAK if $args{fail};
                    }
                    $discard_output_creation = 1;
                    # if ($out_file){
                    #    # do not leave empty files
                    #    unlink $out_file;
                    #}

                }
            }
        }

        if (!$redirect_pending
            && !$discard_output_creation
            && ($args{output}
            || $args{'remote-name'}
            || $args{recursive})){
            make_path($out_file);
            redirect_output_to_file($out_file);
        }

        # for some actions we need to capture the output into a variable
        # also an external caller could want the output saved in the $resp object
        my $need_capture;
        if ($params{capture}
            || (defined $process_action && !$process_action->{done})
            || ($args{recursive} && $resp->{headers}{'content-type'} && $resp->{headers}{'content-type'} =~ m{(text/html|text/css)})){
            $need_capture = 1;
        }
        
        $resp = process_http_response_body(IN        => $IN,
                                           OUT       => current_output(),
                                           ERR       => $ERR,
                                           url       => $url_final,
                                           url_proxy => $url_proxy,
                                           response  => $resp,
                                           capture   => $need_capture,
                                           out_file  => $fname,
                                           follow    => $following);
        
        say STDERR "* received $resp->{body_byte_len} body bytes" if $args{verbose} || $args{debug};
        if ($resp->{head_byte_len} + $resp->{body_byte_len}){
            
            # result other than redirect
            if ($process_action){
                if (!$process_action->{done}){
                    perform_action($process_action, $url_final, $resp, $discovered_links, ($params{capture} ? $params{capture} == 1 : 0));
                    $process_action->{done} = 1;
                }
            } elsif ($resp->{headers}{'content-type'} && $resp->{headers}{'content-type'} =~ '(text/html|text/css)'){
                if ($discovered_links){
                    push @$discovered_links, discover_links($resp, $url_final, $acceptrx, $rejectrx, !$args{'recursive-flat'});
                }
            }                                   

            # save eventually the captured data into a file for getlinked or recursive
            if ($resp->{captured}
                && (
                    ($process_action && index($process_action->{what}, 'getlinked') == 0)
                    ||
                    ($args{recursive} && $resp->{status}{code} && $resp->{status}{code} != 404)
                )){
                # need to use select as "print current_output ${$resp->{captured}}" prints "GLOB(0x1f75cd8)" (the current_output) to STDOUT
                # my $old_selected = select current_output;
                # say STDERR "output is " . current_output;
                print {current_output} ${$resp->{captured}} if defined ${$resp->{captured}};
                # select $old_selected;
            }

            # goto BREAK;         # weird, 'last' is throwing a warning "Exiting subroutine via last"
        }

        last REDIRECT if $no_follow_after_body;

  } while (($resp->{head_byte_len} + $resp->{body_byte_len}) && $next_url && $redirs >= 0);
  BREAK:
    restore_output();
    if ($args{'remote-time'}    # FIXME: add test on redirection
        && $fname #$resp->{redirected}
        && $resp->{headers}{'last-modified'}){
        my $timestamp = $resp->{headers}{'last-modified'};
        my $epoch = str2epoch($timestamp);
        if (-f $out_file && $epoch > -1){
            utime($epoch, $epoch, $out_file) or say STDERR "Cannot set modification time of $resp->{redirected}: $!";
        }
    }

    close $IN;
    close $OUT;
    close $ERR if $ERR;

    # save the cookie jar if requested
    if ($args{'cookie-jar'}){
        save_cookie_jar($args{'cookie-jar'}, $cookies);
    }

    exit $error_code if $error_code;
    
    return $resp;
}

# when getting a 3xx redirect in HTTP, compute the next URL attributes
# from the Location header
sub get_redirected_url {
    my ($url, $location) = @_;
    
    $args{referer} = $url->{url} if $auto_ref;      # use previous url as next referer
    my ($old_scheme, $old_host, $old_port) = ($url->{scheme}, $url->{host}, $url->{port});
    if ($location !~ m{^https?://}){
        # fix URLs when scheme is missing
        my $user_info = auth_string($url);
        my $authority = $url->{host};
        $authority = $user_info . $authority if $user_info;
        $authority .= sprintf(":%s", $url->{port}) if $url->{port} != $defports{$url->{scheme}};
        $location = sprintf("%s://%s%s",
                            $url->{scheme},
                            $authority,
                            canonicalize($location));
    }
    $url = parse_uri($location);
    $url = complete_url_default_values($url); # is this correct??
    # FIXME: in case of local schemeless url...  <=======
    # relative redirect urls may miss some parameters
    if (($url->{scheme} ne $old_scheme) || ($url->{host} ne $old_host) || ($url->{port} != $old_port)){
        $url->{scheme} = $old_scheme unless $url->{scheme};
        $url->{port} = $defports{$url->{scheme}} unless $url->{port};
    }
    $url->{port} = $old_port unless $url->{port};
    $url->{host} = $old_host unless $url->{host};

    return $url;
}

# perform a file:// query
sub process_file {
    my $url = shift;
    my $discovered_links = shift;
    my $path = $url->{path};
    my $content;
    my $resp = { headers => {} }; # simulate the network answer for action processing
    
    unless ( -r $path ){
        say STDERR "file $path seems not to exist";
        exit 6;
    }
    my $size = (stat $path)[7];
    say STDERR "* size of $path is $size" if $args{debug};
    $resp->{body_byte_len} = $size;

    redirect_output_to_file($args{output});

    open (my $fh, '<', $path) or die "Couldn't open file $path: $!";
    if (defined $process_action){
        local $/;
        $content = <$fh>;
        close $fh;
        $resp->{captured} = \$content;
        perform_action($process_action, $url, $resp, $discovered_links);
    } else {
        binmode $fh;
        my $buf = '';
        while (1){
            my $success = read($fh, $buf, 1024, length($buf));
            die $! if not defined $success;
            last if not $success;
            print {current_output} $buf;
        }
        close $fh;
    }
    restore_output();
}

# transmission of headers + body to the server
sub send_http_request {
    my ($IN, $OUT, $ERR, $headers, $body) = @_;
    
    push @$headers, '';         # empty line to terminate request
    if ($args{verbose} || $args{debug}){
        print STDERR "> $_\n" for @$headers;
    }

    my $headers_txt = join "", map { "$_\r\n" } @$headers;
    print $OUT $headers_txt;    # send headers to server
    print {current_output} $headers_txt if $args{'include-request'};

    if (defined $body){
        my $sent = 0;
        if (ref $body eq 'HASH'){
            if (exists $body->{data}){
                print $OUT $body->{data};
                print {current_output} $body->{data} if $args{'include-request'} || $args{debug};
                $sent = $body->{size};
            } 
        } else {
            if ($body){
                print $OUT $body;
                print {current_output} $body if $args{'include-request'} || $args{debug};
            }
            $sent = length $body;
        }
        say STDERR "* upload completely sent off: $sent bytes" if $args{verbose} || $args{debug};
    }
    
    $OUT->flush;
    say STDERR "* HTTP request sent" if $args{debug};
}

# check if we need to connect to a proxy
# returns the address of the proxy, else undef
sub get_proxy_settings {
    my $url_final = shift;
    my $proxy;

    # if we match an explicit no_proxy argument or no_proxy environment, get out
    my $no_p = $args{noproxy} || $ENV{no_proxy};
    if ($no_p){
        $no_p =~ s/,/|/g;
        $no_p =~ s/\./\\./g;
        $no_p =~ s/\*/.*/g;
        if ($url_final->{host} =~ /$no_p/){
            return undef;
        }
    }
    
    my $proxy_set;
    if ($args{proxy}){
        $proxy_set = $args{proxy};
    } elsif ($args{proxy10}){
        $proxy_set = $args{proxy10};
    } elsif ($url_final->{scheme} eq 'http'){
        $proxy_set = $ENV{http_proxy};
    } elsif ($url_final->{scheme} eq 'https'){
        $proxy_set = $ENV{https_proxy};
    }
    return undef unless $proxy_set;
    
    $proxy = parse_uri($proxy_set);
    unless ($proxy){
        say STDERR "It's strange to me that `$proxy_set` does not look as a valid url for proxy...";
        exit 4;
    }
    $proxy = complete_url_default_values($proxy);
    
    say STDERR "* Using proxy $proxy->{url}" if $args{verbose} || $args{debug};
    return $proxy;
}

# add implicit parameters in an url
sub complete_url_default_values {
    my $url = shift;

    $url->{scheme} = 'http' unless $url->{scheme};
    unless ($url->{port}){
        $url->{port} = $defports{$url->{scheme}};
        if (!$url->{port} && $url->{scheme} ne 'file') {
            say STDERR "* Default port unknown for scheme '$url->{scheme}'...";
            exit 1;
        }
    }
    if ($url->{scheme} eq 'file' && $url->{path} =~ m{^///}){
        $url->{path} = substr($url->{path}, 2);
    }
    return $url;
}

# Construct the Request headers using
# - HTTP method
# - url we want
# - url for the proxy
# - the body (if any, to compute length and content-type)
sub build_http_request_headers {
    my ($method, $u, $p, $body) = @_;
    my $headers = [];

    if (HTTP09()){
        push @$headers, "${method} $u->{path}", ''; # This is the minimal request (in 0.9)
    } else {
        if ($u->{proxified}){
            push @$headers, "${method} $u->{url} HTTP/${http_vers}"; # via a proxy, request full url
        } else {
            my $path = $u->{path} . ($u->{query} ? "?$u->{query}" : '');
            push @$headers, "${method} ${path} HTTP/${http_vers}"; # else request only the path
        }

        # FIXME: the headers must not be in a hash as we can send repeated headers
        # when they can be also a coma-separated list https://tools.ietf.org/html/rfc7230#section-3.2.2

        # process the custom headers
        my %custom;
        for my $ch (@{$args{header}}){
            # curl man: Remove an internal header by giving a replacement without content
            #           on the right side of the colon, as in: -H "Host:".
            #           If you send the custom header with no-value then its header must be terminated with a semicolon,
            #           such as -H "X-Custom-Header;" to send "X-Custom-Header:".
            if ($ch =~ /^([A-Za-z0-9-]+)([:;])\s*(.*)$/){
                # undef will make header removal
                if ($2 eq ':'){
                    if ($3){
                        $custom{lc $1} = "$1: $3";
                    } else {
                        $custom{lc $1} = undef;
                    }
                } elsif ($2 eq ';'){
                    $custom{lc $1} = "$1:";
                } else {
                    say STDERR "* Unsupported syntax for custom header: '$ch' ignored";
                }
            } else {
                say STDERR "* Unsupported syntax for custom header: '$ch' ignored";
            }
        }

        # we need to pass the port after host only when the port is not the default associated to the protocol
        # see RFC2616 §14.23
        my $hostport = '';      
        if ($u->{port} != $defports{$u->{scheme}}){
            $hostport = ":$u->{port}";
        }
        push @$headers, "Host: $u->{host}${hostport}" unless exists $custom{host};
        add_http_header($headers, \%custom, 'User-Agent', $args{'user-agent'});
        add_http_header($headers, \%custom, 'Accept', '*/*');
        add_http_header($headers, \%custom, 'Connection', 'close');
        my $auth = $args{basic} || ($u->{auth} ? $u->{auth}->{user} . ':' . $u->{auth}->{password} : undef);
        add_http_header($headers, \%custom, 'Authorization', 'Basic ' . encode_base64($auth, '')) if $auth;
        # if ($u->{tunneled}){
            # my $auth = $args{'proxy-user'} || ($p->{auth} ? $p->{auth}{user} . ':' . $p->{auth}{password} : undef);
            # add_http_header($headers, \%custom, 'Proxy-Authorization', 'Basic ' . encode_base64($auth, '')) if $auth;
        # }
        add_http_header($headers, \%custom, 'Referer', $args{referer}) if defined $args{referer};
        add_http_header($headers, \%custom, 'Content-Type', $args{content}) if defined $args{content};
        
        if (defined $body){
            if (ref $body eq 'HASH'){
                # if ($body->{kind} eq 'stdin'){
                    add_http_header($headers, \%custom, 'Content-Length', $body->{size});
                    add_http_header($headers, \%custom, 'Content-type', $body->{ctype}) unless defined $args{content};
                # }
            } else {
                add_http_header($headers, \%custom, 'Content-Length', length $body);
                add_http_header($headers, \%custom, 'Content-type', 'application/x-www-form-urlencoded') unless defined $args{content};
            }
        }
        map { push @$headers, $custom{$_} if defined $custom{$_} } keys %custom;
    }

    # Process Cookies - No more than a single header - https://tools.ietf.org/html/rfc6265#section-5.4
    if ($use_cookies){
        my $head = get_matching_cookies($u, $cookies);
        push @$headers, $head if $head;
    }    

    return $headers;
}

# add a header to the custom headers, depending on existing custom headers (if any)
# - set to the default value if not in custom headers
sub add_http_header {
    my ($headers, $custom, $name, $default) = @_;

    my $field = lc $name;
    if (! exists $custom->{$field} ){
        $custom->{$field} = "$name: $default";
    }
}

# When POSTing data, compute length, content-type and data to POST
sub prepare_http_body_to_post{
    my $post = $args{data} || $args{'data-binary'} || $args{'data-raw'};
    my $buf;
    
    if ($post){
        if ($args{'data-raw'}){
            return $args{'data-raw'}; # we do not interpret the @ in raw mode
        } elsif ($post =~ /^@(.*)/){
            if ($1){
                my $fd;
                if ($1 eq '-'){
                    $fd = *STDIN;
                } elsif (-e $1){
                    open $fd, '<', $1 or die "cannot open $1: $!";
                } else {
                    # file does not exist
                    say STDERR "Warning: Couldn't read data from file \"$1\", this makes an empty POST.";
                    return { kind => 'empty',
                             ctype => 'application/x-www-form-urlencoded'
                    };
                }
                my $data;
                if ($args{data}){
                    while (my $l = <$fd>){
                        $l =~ s/[\r\n]+//g;
                        $data .= $l;
                    }
                } elsif ($args{'data-binary'}){
                    my $buf_size = 1024 * 1024;
                    while(my $bytes = $fd->sysread($buf, $buf_size)){
                        # syswrite $OUT, $buf, $bytes;
                        # $sent += $bytes;
                        $data .= $buf;
                    }
                }
                close $fd unless fileno($fd) == fileno(STDIN);
                
                return {
                    size => length $data,
                    ctype => 'application/x-www-form-urlencoded',
                    data => $data
                };
            }
        } else {
            return $args{data}; # it's a plain text 
        }        
    } elsif (@{$args{'data-urlencode'}}){
        my @encoded;
        for my $data (@{$args{'data-urlencode'}}){
            $data =~ s/^(\w+)=(.*)/"$1=" . urlencode($2)/e;
            push @encoded, $data;
        }
        return join('&', @encoded);
    } else {
        return undef;
    }
}

sub build_http_proxy_headers {
    my $p = shift;              # proxy url
    my $u = shift;              # url to retrieve
    my $headers = [];

    if ($u->{scheme} eq 'https'){
        if ($args{proxy10} || HTTP10()){
            push @$headers, "CONNECT $u->{host}:$u->{port} HTTP/1.0";
        } elsif (HTTP11()){
            push @$headers, "CONNECT $u->{host}:$u->{port} HTTP/1.1";
        }
        push @$headers, "Host: $u->{host}:$u->{port}";
        push @$headers, "User-Agent: " . $args{'user-agent'};
    }
    
    my $auth = $args{'proxy-user'} || ($p->{auth} ? $p->{auth}->{user} . ':' . $p->{auth}->{password} : undef);
    push @$headers, 'Proxy-Authorization: Basic ' . encode_base64($auth, '') if $auth;
    if (HTTP11()){
        # push @$headers, 'Proxy-Connection: close';
    }
    return $headers;
}

# Given the STDOUT/STDERR of the server or tunnel client
# process the response and returns a hashref with
# - status: hash of {proto, code, message}
# - headers: hash of response headers from server
# - byte_len: the size of the response
# - captured: when performing actions, store the response content in this key
sub process_http_response_headers {
    my %params       = @_;
    my $IN           = $params{IN};
    my $ERR          = $params{ERR};
    my $url_final    = $params{url};
    my $url_proxy    = $params{url_proxy};
    my $output_name  = $params{out_file};
    my $following    = $params{follow};
    my $headers_done = 0;       # flag to know if we are processing headers or body
    my $status_done = 0;        # flag to know if we have processed the status
    my $received = 0;           # counter for total bytes received
    my %headers;                # a map for all received headers
    my %resp;                   # response meta-data

    my $out;
    my $head_buf;
    # FIXME: always capture
    if (1){ #$args{recursive}){
        redirect_output_to_file(\$head_buf);
    
        # my $old_out;                # for actions & recursive mode we need to redirect to memory, this will keep previous $out
        # when we receive the server response, we print the result to STDOUT (and possibly the headers)
        # but when we need to process actions (e.g. for pattern matching) we capture output to a memory buffer
        $out = current_output();
    } else {
        $out = $params{OUT};                    # we print in $out that can be a file or STDOUT
    }
    
    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    say STDERR "* Processing response head" if $args{debug};

    # reading loop on both server output and errors, with a timeout
    while (my @ready = $selector->can_read($args{'max-wait'} || $def_max_wait)) {
        foreach my $fh (@ready) {
            if ($ERR && (fileno($fh) == fileno($ERR))) {
                my $line = <$fh>;
                $line =~ s/[\r\n]+$// if $line;
                say STDERR "* proxy/tunnel STDERR: $line" if $args{debug};
                if ($url_final->{tunneled} && ($line =~ /^s_client: HTTP CONNECT failed: (\d+) (.*)/)){
                    my $err_txt = sprintf("Received '%d %s' from tunnel after CONNECT", $1, $2);
                    say STDERR $err_txt;
                    exit 5;
                }
            } elsif (fileno($fh) == fileno($IN)) {
                say STDERR "* processing STDIN" if $args{debug};
                if (! $headers_done && !HTTP09()){ # there is no header in HTTP/0.9
                    # local $/ = "\r\n";
                  HEAD: while(defined (my $line = <$IN>)){
                      # print $out $line;
                      $received += length($line);
                      $line =~ s/[\r\n]+$//;
                      say STDERR '< ', $line if $args{verbose} || $args{debug};
                      say $out $line if $args{head} || $args{'include-response'};
                      if ($line =~ /^$/){
                          $headers_done++;
                          last HEAD;
                      }
                      if (!$status_done && $line =~ m{^([^\s]+) (\d+) (.*)$}){
                          # this is the response status
                          $resp{status}{proto}   = $1;
                          $resp{status}{code}    = $2;
                          $resp{status}{message} = $3;
                          $status_done++;
                      }
                      if ($line =~ /^([A-Za-z0-9-]+):\s*(.*)$/){
                          # this is a header
                          my $hname = lc $1;
                          my $hvalue = $2;
                          if ($hname eq 'set-cookie'){
                              my @head_cookies = parse_cookie_header($hvalue, $url_final);
                              say STDERR "Cannot parse cookie header: $hvalue" unless @head_cookies;
                              HCOOKIE: for my $hcook (@head_cookies){
                                  # replace identical cookies
                                  for (my $c = 0; $c <= $#{$cookies}; $c++){
                                      if ($cookies->[$c]->{domain} eq $hcook->{domain}
                                          && $cookies->[$c]->{path} eq $hcook->{path}
                                          && $cookies->[$c]->{name} eq $hcook->{name}){
                                          say STDERR sprintf("* Replaced cookie %s=\"%s\" for domain %s, path %s, expire %d",
                                                     $hcook->{name},
                                                     $hcook->{value},
                                                     $hcook->{domain},
                                                     $hcook->{path},
                                                     $hcook->{'max-age'} || 0) if $args{verbose} || $args{debug};
                                          # say STDERR "Replacing cookie ".$hcook->{name} if $args{debug};
                                          # splice @$cookies, $c, 1, $hcook;
                                          $cookies->[$c] = $hcook;
                                          next HCOOKIE;
                                      }
                                  }
                                  # if we arrive here, the cookie was not found, add it
                                  say STDERR sprintf("* Added cookie %s=\"%s\" for domain %s, path %s, expire %d",
                                                     $hcook->{name},
                                                     $hcook->{value},
                                                     $hcook->{domain},
                                                     $hcook->{path},
                                                     $hcook->{'max-age'} || 0) if $args{verbose} || $args{debug};
                                  push @$cookies, $hcook;
                              }
                          }

                          if (exists $headers{$hname}){
                              # header fields can be extended over multiple lines
                              # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
                              if (ref $headers{$hname} eq 'ARRAY'){
                                  # already an array ref, add item
                                  push @{$headers{$hname}}, $hvalue;
                              } else {
                                  # replace the single item by an array ref of previous value + new item
                                  $headers{$hname} = [ $headers{$hname}, $hvalue ];
                              }
                          } else {
                              # most of headers are single values
                              $headers{$hname} = $hvalue;
                          }
                      }                            
                  }
                } # end of headers processing --------------------------------------------
                goto AFTER_HEADERS;# interrupt reading, the body will be processed in another sub
                
            };
            
            # if (eof($fh)){
               # say STDERR "* Nothing left in the filehandle $fh" if $args{debug};
               # $selector->remove($fh);
            # }
        }
    }
  AFTER_HEADERS:
    
    $resp{headers} = \%headers;
    $resp{head_byte_len} = $received; # keep the size of read data
    # FIXME: always capture
    if (1){ #$args{recursive}){
        restore_output();
        $resp{captured_head} = \$head_buf;
    }
    say STDERR "* end of response head" if $args{debug};
    say STDERR "Parsed cookies: ", Dumper $cookies if $cookies && $args{debug};
    return \%resp;
}

sub process_http_response_body {
    my %params       = @_;
    my $IN           = $params{IN};
    my $ERR          = $params{ERR};
    my $url_final    = $params{url};
    my $url_proxy    = $params{url_proxy};
    my $need_capture = $params{capture};
    my $output_name  = $params{out_file};
    my $following    = $params{follow};
    my $response     = $params{response};
    my $headers_done = 0;       # flag to know if we are processing headers or body
    my $status_done = 0;        # flag to know if we have processed the status
    my $received = 0;           # counter for total bytes received
    my $chunked_mode = 0;       # flag set when chunked mode
    my $content_length = 0;     # size of response, according to the response header
    my $resp_buf;               # buffer to store response instead of STDOUT/file

    my $out = $params{OUT};                    # we print in $out that can be a file or STDOUT
    # my $old_out;                # for actions & recursive mode we need to redirect to memory, this will keep previous $out
    # when we receive the server response, we print the result to STDOUT (and possibly the headers)
    # but when we need to process actions (e.g. for pattern matching) we capture output to a memory buffer
    if ($need_capture){
        # open($out, '>', \$resp_buf) or die "Cannot capture output: $!"; # out is a variable
        redirect_output_to_file(\$resp_buf);
    # } else {
        # $out = $current_output; # open file or STDOUT
    }
    $out = current_output();
    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    say STDERR "* Processing response body" if $args{debug};

    if ($response->{headers}{'transfer-encoding'} && $response->{headers}{'transfer-encoding'} eq 'chunked'){
        $chunked_mode = 1;
    }
    
    # reading loop on both server output and errors, with a timeout
    while (my @ready = $selector->can_read($args{'max-wait'} || $def_max_wait)) {
        foreach my $fh (@ready) {
            if ($ERR && (fileno($fh) == fileno($ERR))) {
                my $line = <$fh>;
                if ($line){
                    $line =~ s/[\r\n]+$//;
                    say STDERR "* proxy/tunnel STDERR: $line" if $args{debug};
                    if ($url_final->{tunneled} && ($line =~ /^s_client: HTTP CONNECT failed: (\d+) (.*)/)){
                        my $err_txt = sprintf("Received '%d %s' from tunnel after CONNECT", $1, $2);
                        say STDERR $err_txt;
                        exit 5;
                    }
                }
            } elsif (fileno($fh) == fileno($IN)) {
                say STDERR "* processing STDIN" if $args{debug};
                                
                # avoid unwanted binary output
                if ($response->{headers}{'content-type'}){
                    if ($response->{headers}{'content-type'} =~ /charset=binary/){
                        if (!$args{output}
                            && (!$args{'remote-name'} && !$args{'remote-header-name'})
                            && -t $out){
                            prefix_print(\*STDERR, 'Warning: ', <<"NO_BIN");
Binary output can mess up your terminal. Use "--output -" to tell 
curl to output it to your terminal anyway, or consider "--output 
<FILE>" to save to a file.
NO_BIN
                            exit 10;
                        }
                    }
                }

                # try to get the output file name from header
                my $fname = '';
                if ($args{'remote-name'}){
                    if ($args{'remote-header-name'}
                        && ($response->{headers}{'content-disposition'}
                            && $response->{headers}{'content-disposition'} =~ /attachment; filename="([^"]+)"/)
                        ){
                        my $remote_header_name = $1;
                        if (!$args{output} && $remote_header_name && -w $remote_header_name){
                            prefix_print(\*STDERR, 'Warning: ', "Refusing to overwrite ${remote_header_name}: File exists");
                            exit 10;
                        } else {
                            $fname = $remote_header_name;
                        }
                    }
                }
                if ($fname){
                    # we received the name from server
                    # we should not have redirected in this case
                    redirect_output_to_file("${prefix}${fname}");
                    $response->{redirected} = "${prefix}${fname}";
                }
                
                # we show body contents only when not following redirects
                my $is_redirected = $response->{status} && $response->{status}{code} && $response->{status}{code} =~ /^3/;
                say STDERR "* Ignoring the response-body" if ($is_redirected && $args{location}) && (! $fh->eof ) && ($args{verbose} || $args{debug});
                binmode($out, ":raw"); # pass in raw layer to prevent utf8 or cr/lf conversion in binary files

                $content_length = $response->{headers}{"content-length"};
                if (defined $content_length){                                         
                    say STDERR "* need to read $content_length bytes in response" if $args{debug};
                } else {
                    say STDERR "* Unknown size of response to read" if $args{debug};
                }
                say STDERR "* Reading using chunked mode" if $chunked_mode && $args{debug};
                # print STDERR sprintf("%s: ", $output_name || $fname) if defined($content_length) && $args{progression} && !$args{debug};
                my $prog = 0;   # accumulator for progression
                my $chunk_len;
                my $buf;
              CHUNK:
                while (! $fh->eof){ # loop on the remaining of response
                    if ($chunked_mode){
                        my $line = <$fh>;
                        last CHUNK unless defined $line;
                        # say STDERR sprintf("%*vX", ' ', $line); # vector dump = simple hex dump
                        $line =~ s/[\r\n]+$//;
                        $chunk_len = hex($line); # block size is in hex ascii
                        say STDERR sprintf("* Next block is %d (0x%x) bytes long", $chunk_len, $chunk_len) if $args{debug}; 
                    }
                    my $buf_size = $chunked_mode ? $chunk_len : (2 * 1024 * 1024);
                    if ($buf_size){
                        my $bytes = $fh->read($buf, $buf_size);
                        if ($bytes){
                            if (defined($content_length) && $args{progression} && !$args{debug}){
                                my $BAR_LENGTH = 72;
                                $prog += $bytes;
                                my $pchars = $BAR_LENGTH / $content_length * $prog;
                                my $pct = 100 / $content_length * $prog;
                                print STDERR sprintf("\r%s: %s%s %.1f%%", $output_name || $fname, '#' x int($pchars), '.' x ($BAR_LENGTH - int($pchars)), $pct);
                                flush STDERR;
                            }
                            say STDERR "* Read $bytes bytes" if $args{debug};
                            $received += $bytes;
                            print $out $buf unless ($is_redirected && $args{location}); # print to STDOUT or memory buffer
                        }
                    }
                    if ($chunked_mode){
                        my $line = <$fh>; # the block is followed by a CR LF
                    }
                }
                # there may have additional info... (body > Content-Length)

                print STDERR "\n" if defined($content_length) && $args{progression} && !$args{debug};
            };
            
            if (eof($fh)){
               say STDERR "* Nothing left in the filehandle $fh" if $args{debug};
               $selector->remove($fh);
            }
        }
    }
    
    $response->{body_byte_len} = $received; # keep the size of read data
    if ($need_capture){
        # restore the output to the original value before capture
        say STDERR sprintf("* Captured %d bytes:\n%s", length $resp_buf, $resp_buf // '') if $args{debug};
        # close $out;
        # $out = $old_out;
        restore_output();
        $out = current_output();
        $response->{captured} = \$resp_buf;
    }

    say STDERR "* end of response body" if $args{debug};
    return $response;
}

# Build the value of a Cookie: header containing the cookies
# suitable for the given url
sub get_matching_cookies {
    my ($url, $cookies) = @_;
    return () unless @$cookies;
    my $udomain = $url->{host};
    my $upath = $url->{path};
    my @matching;
    for my $cookie (@$cookies){
        next if $cookie->{secure} && !($url->{scheme} eq 'https'); # secure cookies are only for https
        my $dom_rx = $cookie->{domain};
        $dom_rx =~ s/\./\\./g;
        $dom_rx = "\\b${dom_rx}\$";
        my $path_rx = '^' . $cookie->{path} . '\b';
        if ((($cookie->{domain} eq '*') || ($udomain =~ /$dom_rx/)) && ($upath =~ /$path_rx/)){
            push @matching, $cookie;
        }
    }
    my $txt = join '; ', map { "$_->{name}=$_->{value}" } @matching;
    return $txt ? "Cookie: ${txt}" : undef;
}

# Return the list of cookie definitions contained in a Set-Cookie header
sub parse_cookie_header {
    my ($head_val, $url) = @_;
    # the local our fixes the Warning: 'Variable "%months" will not stay shared at (re_eval 22) line 2.'
    # because the $rx captures the %months variable, but a different $rx is built every time the function may be called
    # https://stackoverflow.com/a/19454419/317266
    local our %months = ( Jan=>0, Feb=>1, Mar=>2, Apr=>3, May=>4, Jun=>5, Jul=>6, Aug=>7, Sep=>8, Oct=>9, Nov=>10, Dec=>11 );
    my $cookies;
    my $rx = qr{
    # NOTES:
    # this regex is a recursive descent parser - see https://www.perlmonks.org/?node_id=995856
    # and chapter 1 "Recursive regular expressions" of Mastering Perl (Brian d Foy)
    #
    # Inside the block (?(DEFINE) ...)  (?<FOOBAR> ...) defines a named pattern FOOBAR
    #                                   that can be called with (?&FOOBAR)
    # (?{ ... }) is a block of Perl code that is evaluated at the time we reach it while running the pattern
    # $^R is the value returned by the last runned (?{ }) block
    # $^N is the last matched group

    (?&LIST) (?{ $_ = $^R->[1] })

    (?(DEFINE)                      # define some named patterns to call with (?&RULENAME)
    
      (?<LIST>
       (?{ [ $^R, [] ] }) # initialize an array ref for the list of cookies
       (?&COOKIE)           (?{ [ $^R->[0][0], [ $^R->[1] ] ] }) # fill the first cookie in the list
       (?:
        \s* , \s* (?&COOKIE) (?{ [ $^R->[0][0], [ @{$^R->[0][1]}, $^R->[1] ] ] }) # append a new cookie to the list
       )*
      )
      
      (?<COOKIE>
       (?{ [ $^R, {} ] }) # initialize an hashref for the content of the cookie
       # at least we have a key=value
       (?&KV)             (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, name=>$^R->[1], value=>$^R->[2] } ] })
       ( ; \s    # but we can have additional attributes
         ( 
           (?&SINGLEATTR) (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, lc $^R->[1] => 1 } ] })
          |(?&KV)         (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, lc $^R->[1] => $^R->[2] } ] })
         )
       )*
      )
      
      (?<KV> # a pair key=value
       (?&KEY) = (?&VALUE) (?{ [$^R->[0][0], $^R->[0][1], $^R->[1]] })
      )
      
      (?<KEY> # cookie attributes that have a value
       ( [^;,= ]+ ) #| expires | domain | path | max-age | samesite ) 
       (?{ [ $^R, $^N ] })
      )
      
      (?<SINGLEATTR> # cookie attribute that do not accept value
       ( HttpOnly | Secure )  (?{ [ $^R, $^N ] })
      )
      
      (?<VALUE> # get the value for a key with special handling of dates
       (?: (?&EXPIRES) | (?&STRING) )
      )
      
      (?<EXPIRES> # legal format = Wdy, DD-Mon-YYYY HH:MM:SS GMT
                                 # RFC 822, 850, 1036, 1123, with only GMT time zone 
                                 # and date separators must be dashes
                                 # but I have seen 
                                 # Tue, 2 Mar 2021 21:27:55 GMT
                                 # Tue, 03 Mar 2020 00:27:55 GMT
       \w\w\w , \s (?<DAY>\d?\d) [- ] (?<MONTH>\w\w\w) [- ] (?<YEAR>(?:\d\d)?\d\d)
       \s (?<HOUR>\d\d) : (?<MINUTE>\d\d) : (?<SECOND>\d\d) \s GMT 
       (?{ #printf STDERR "parsed date: %s %s %s %s %s %s\n", $+{SECOND}, $+{MINUTE}, $+{HOUR}, $+{DAY}, $+{MONTH}, $+{YEAR};
           [ $^R, timelocal( $+{SECOND}, $+{MINUTE}, $+{HOUR}, $+{DAY}, $months{$+{MONTH}}, ($+{YEAR} < 100 ? $+{YEAR} + 2000 : $+{YEAR}) ) ] })
      )
      
      (?<STRING>
       ([^;,]*) (?{ [$^R, $^N] })
      )
    
    ) # end of DEFINE set
    }xims;
    {
        local $_ = shift;
        local $^R;
        eval { m{$rx}; } and $cookies = $_;
    }
    if ($cookies){
        say STDERR Dumper $cookies if $args{debug};
        # sanitize cookies: without domain or path, use url current values
        for my $c (@$cookies){
            $c->{domain} = $url->{host} unless $c->{domain};
            $c->{path} = $url->{path} unless $c->{path};
            if ($c->{'max-age'}){
                # max-age should always take precedence on Expires (if any)
                $c->{expires} = time + $c->{'max-age'};
            }
        }
    }
    return $cookies ? @$cookies : ();
}

# Load cookies given on the command line
# we only support one occurrence of the --cookie parameter
sub load_commandline_cookies {
    my $arg = shift;
    my @jar;
    while ($arg =~ /(\w+)=([^; ]*)/g){
        my $cookie = {};
        $cookie->{name} = $1;
        $cookie->{value} = $2;
        $cookie->{domain} = '*';
        $cookie->{path} = '/';
        push @jar, $cookie;
    }
    return \@jar;
}

# Load cookies from the cookie-jar file
# The cookie jar is either in Netscape format
# or in Set-Cookie header format
sub load_cookie_jar {
    my $file = shift;
    my @jar;
    open my $in, '<', $file or die "Cannot open cookie-jar '$file': $!";
    my $header_done = 0;
    while (defined (my $line = <$in>)){
        chomp $line;
        # TODO: add the support for http headers format
        next if $line =~ /^#/ && !$header_done;
        $header_done++ and next if $line =~ /^$/ && !$header_done;
        if ($line =~ /^([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)\t([^\t]+)$/){
            my $cookie = {};
            $cookie->{tailmatch} = $2 eq 'TRUE';
            $cookie->{path} = $3;
            $cookie->{secure} = $4 eq 'TRUE';
            $cookie->{expires} = $5; # legal format = Wdy, DD-Mon-YYYY HH:MM:SS GMT, if undef, it's a session cookie
            $cookie->{name} = $6;
            $cookie->{value} = $7;
            $cookie->{domain} = $1; # do this as last because of next match that resets the vars $1..$7
            if ($cookie->{domain} =~ /^#HttpOnly_(.*)/){
                $cookie->{domain} = $1;
                $cookie->{httponly} = 1;
            }
            push @jar, $cookie;
        }
    }
    close $in;
    return \@jar;
}

# Save the cookie in the Netscape format
# this format is also supported by cURL
sub save_cookie_jar {
    my ($file, $cookies) = @_;
    return unless @$cookies; # emulate curl: do nothing if encountered no cookie
    say STDERR '* ' . scalar(@$cookies) . " cookie(s) to save in cookie-jar '$file'" if $args{verbose} or $args{debug};
    my $out;
    if ($file eq '-'){
        $out = *STDOUT;
    } else {
        open $out, '>', $file or do { say STDERR "* WARNING: failed to save cookies in $file"; return}; # emulate curl
    }
    my $uagent = $args{'user-agent'};
    print $out <<HEADER;
# Netscape HTTP Cookie File
# https://curl.haxx.se/docs/http-cookies.html
# This file was generated by $uagent! Edit at your own risk.

HEADER
    for my $cookie (@$cookies){
        say $out sprintf ("%s\t%s\t%s\t%s\t%s\t%s\t%s",
                          $cookie->{httponly} ? '#HttpOnly_' . $cookie->{domain} : $cookie->{domain},
                          $cookie->{tailmatch} ? 'TRUE' : 'FALSE',
                          $cookie->{path},
                          $cookie->{secure} ? 'TRUE' : 'FALSE',
                          $cookie->{expires} // 0,
                          $cookie->{name},
                          $cookie->{value});
    }
    close $out unless $file eq '-';
}

# prepare the action handler(s)
sub parse_process_action {
    my $param = shift;
    my $action;
    if ($param =~ /^([\w-]+):(.*)/){
        my $type = $1;
        my $param = $2 || '';
        if ($type eq 'header'){
            $action = { what => $type, value => $param };
        } elsif ($type eq 'bodyrx'){
            $action = { what => $type, value => $param };
        } elsif ($type eq 'listlinks'){
            $action = { what => $type, value => $param };
        } elsif (index($type, 'getlinked') == 0){ # getlinked / getlinked-tree
            $action = { what => $type, value => $param };
        } elsif ($type eq 'json'){
            $action = { what => $type, value => $param };
        } elsif ($type eq 'xml'){
            $action = { what => $type, value => $param };
        } elsif ($type eq 'help'){
            list_actions();
            exit 0;
        } else {
            say STDERR "Unknown action $type";
            list_actions();
            exit 10;
        }
    } else {
        list_actions();
        exit 2;
    }
    say STDERR "Processed action:" . Dumper $action if $args{debug};
    return $action;
}

sub list_actions {
    say <<"ACTIONS";
Actions are in the form type:value
Supported actions:
  header          return the response header 'value'
  bodyrx          return the regex match from the response body
  listlinks       discover the linked resource from the given URL
  getlinked       discover all the dependencies recursively
  getlinked-tree  discover all the dependencies recursively
  json            return the xpath-like value from a json response
  xml             return the xpath-like value from an xml response
  help            this help
ACTIONS
}        
    
# Do something with the retrieved resource
sub perform_action {
    my ($action, $url, $resp, $discovered_links, $store_result) = @_;

    if ($action->{what} eq 'header'){
        my $vals = $action->{value};
        my $sep = $args{'action-res-delimiter'} || ',';
        $sep =~ s/\\n/\n/;
        # $sep =~ s/\\r/\r/;
        $sep =~ s/\\t/\t/;
        my $res = join($sep, map{ $resp->{headers}{lc $_} || '' } split(/,/, $vals) );
        if ($store_result){
            $resp->{action_result} = $res; 
        } else {
            say {current_output} $res;
        }
    } elsif ($action->{what} eq 'json'){
        json_action($action, $url, $resp, $store_result);
    } elsif ($action->{what} eq 'xml'){
        xml_action($action, $url, $resp, $store_result);
    } elsif ($action->{what} eq 'bodyrx'){
        if (${$resp->{captured}} =~ /$action->{value}/){
            my $res = $&;
            if ($store_result){
                $resp->{action_result} = $res;
            } else {
                say {current_output} $res;
            }
        }
    } elsif ($action->{what} eq 'listlinks'){
        unless ($resp->{captured} && ${$resp->{captured}}){
            # say STDERR "* Error??!: no data captured to perform action " . $action->{what};
            return;
        }
        my @url = discover_links($resp, $url, $action->{value}, undef, 0);
        say {current_output} $_ for @url;
    } elsif (index($action->{what}, 'getlinked') == 0 && !$action->{done}){
        my @refs = getlinked_action($action, $url, $resp);
        push @$discovered_links, @refs;
    } else {
        say STDERR "I am afraid that I do not know what to do for '$action->{what}'";
        exit 10;
    }
}

sub json_action {
    my ($action, $url, $resp, $store_result) = @_;
    my $hash = from_json(${$resp->{captured}});
    if ($hash){
        # say Dumper $js;
        my $jp = $action->{value};
        my $jval = get_jpath($hash, $jp) // '<null>'; # if undef value, stringify to avoid message
        my $res = (ref $jval ? to_json($jval) : $jval);
        if ($store_result){
            $resp->{action_result} = $res;
        } else {
            say {current_output} $res;
        }
    } else {
        say STDERR "Request did not returned a valid JSON for an action.";
        exit 8;
    }
}

sub xml_action {
    my ($action, $url, $resp, $store_result) = @_;
    my $treepp = XML::TreePP->new(
        xml_decl => '',
        pretty_print => $args{'xml-pp'}
        );
        my $hash = $treepp->parse(${$resp->{captured}});
        if ($hash){
            # say Dumper $js;
            my $jp = $action->{value};
            my $jval = get_jpath($hash, $jp);
            my $res = (ref $jval ? xmlify($jval, $treepp) : $jval);
            if ($store_result){
                $resp->{action_result} = $res;
            } else {
                say {current_output} $res;
            }
        } else {
            say STDERR "Request did not returned a valid XML for an action.";
            exit 9;
        }
}

sub getlinked_action {
    my ($action, $url, $resp) = @_;
    discover_links($resp, $url, $action->{value}, undef, ($action->{what} eq 'getlinked-tree'))
}

sub discover_links {
    my ($resp, $url, $acc, $rej, $keep_tree) = @_;
    return () unless $resp->{captured} && ${$resp->{captured}};

    # TODO: look only for img/css for first url, unless --page-requisites

    my @links = grep { defined && ! /^["']$/ } ${$resp->{captured}} =~ m{
                                                           (?|<a[^>]+href\s*=\s*(["']?)(.+?)\1
                                                           |<frame[^>]+src\s*=\s*(["']?)(.+?)\1)}gix; # dumb link collector

    my @resources = grep { defined && ! /^["']$/ } ${$resp->{captured}} =~ m{
                (?|
                <img[^>]+src=\s*(["']?)(.+?)\1
                |<link[^>]+href=\s*(["']?)(.+?)\1
                |background(?:-image)?:\s*url\((["']?)(.+?)\1\)
                )}gix; # dumb link collector

    my %requisites;
    map { $requisites{$_}++ } @resources;
    my @reqs;
    if ($acc || $rej){
        if ($acc){
            say STDERR "grepping accept on $acc" if $args{debug};
            @links     = grep { /$acc/ } @links;
            @resources = grep { /$acc/ } @resources;
        }
        if ($rej){
            say STDERR "grepping reject on $rej" if $args{debug};
            @links     = grep { ! /$rej/ } @links;
            @resources = grep { ! /$rej/ } @resources;
        }            
    }
    @reqs = (@links, @resources);
    
    # say for @reqs;
    my @discovered_urls;
    my %dups;
  RES:
    for my $r (@reqs){          # build the list of urls from the anchors/hrefs

        # fix URLs when scheme is missing
        if ($r !~ m{^https?://} && index($r, '//') == 0){
            $r = $url->{scheme} . ':' . $r;
        }

        # remove fragment (avoid duplicates)
        $r =~ s/#.*$//;

        next RES unless $r;           # url without fragment is empty
        next RES if $dups{$r};        # avoid multiple downloads
        next RES if $r =~ /^mailto:/; # avoid mail links
        next RES if $r =~ /^news:/;   # avoid news links
        next RES if $r =~ /^ftp:/;    # avoid ftp links

        $dups{$r}++;
        my $local_dest = '';
        if ($r =~ /^https?:/){
            # arbitrary fully qualified url
            my $linked = parse_uri($r);
            if (
                # !$linked->{host} # ??
                $linked->{host} ne $url->{host}){
                if ($args{'span-hosts'}){
                    push @discovered_urls, $r;
                }
                next RES;
            } else {
                # it is an absolute url on the same server
                complete_url_default_values($linked);
                # if ($linked->{scheme} eq $url->{scheme}
                    # && $linked->{port} eq $url->{port}){
                    # if same scheme and port, just use the path
                    $r = $linked->{path};
                # } else {
                    # consider it needs a different connection
                    # push @discovered_urls, $r;
                    # next RES;
                    
                # }   
            }
        }
        
        my $p;
        my $parent_dir = '';
        $parent_dir = $url->{path};
        $parent_dir =~ s{[^/]*$}{};
        # we want either links with tree structure (keep_tree), or not
        if (!$keep_tree){
            # remove path to retrieve all in flat directory
            $local_dest = $r;
            $local_dest =~ s{^.*/}{};
        } else {
            # we keep the tree structure
            if ($r =~ m{^/}){
                next if $args{relative}; # ignore if we want only relative links
                $local_dest = $r;
            } else {
                if ($parent_dir){
                    $local_dest = "$parent_dir$r";
                } else {
                    $local_dest = $r;
                }
            }
        }
        $local_dest =~ s{^/}{};
        # $local_dest =~ s/%20/ /g; # FIXME: do not decode urls
        # and remove the fragment
        if ($r =~ m{^/}){
            # absolute local url, use it instead of current path + link
            $p = $r;
        } else {
            # relative local url, add to the current path
            $p = "$parent_dir$r";
        }
        # avoid getting too much of a site if unwanted
        my $canon = canonicalize($p);
        my $current_path = canonicalize($url->{path});
        $current_path =~ s{[^/]*$}{};
        if ($args{'page-requisites'} && $requisites{$r}){
            # nothing special
        } elsif (!is_descendant_or_equal($canon, $current_path) && $args{'no-parent'}){
            next;
        }
        
        $p = $canon;
        my $user_info = auth_string($url);
        my $authority = $url->{host};
        $authority = $user_info . $authority if $user_info;
        $authority .= sprintf(":%s", $url->{port}) if $url->{port} != $defports{$url->{scheme}};
        my $u = sprintf("%s://%s%s",
                        $url->{scheme},
                        $authority,
                        $p);
        
        $rel_url_to_local_dir{$u} = $local_dest if $local_dest; # store the local relative path
        unless(exists $discovered_url{$u}){
            # say STDERR "* adding $u to discoverd urls" if $args{verbose} || $args{debug};
            push @discovered_urls, $u;
            $discovered_url{$u}++;
        }
        
    }
    say STDERR sprintf("Discovered %d urls:\n%s",
                       scalar(@discovered_urls),
                       join("\n", @discovered_urls)) if $args{verbose} || $args{'debug-urls'};
    # if ($args{verbose}){
        # say STDERR sprintf("%s -> %s", $_, $rel_url_to_local_dir{$_}) for keys %rel_url_to_local_dir;
    # }
    return @discovered_urls;
}

sub to_absolute_url {
    
}

sub auth_string {
    my $url = shift;
    my $auth = '';
    if ($url->{'auth:user'}){
        $auth = $url->{'auth:user'};
        if ($url->{'auth:password'}){
            $auth .= ':' . $url->{'auth:password'};
        }
        $auth .= '@';
    }
    return $auth;
}
    
sub is_descendant_or_equal {
    my ($other, $current) = @_;

    # keep only paths (note: a directory is supposed to be directory/ )
    
    my @other = split(m{/}, $other);
    my @current = split(m{/}, $current);

    # all are descendant if current is root directory
    return 1 if $#current == -1;
        
    # cannot be descendant if lesser directories
    return 0 if $#other < $#current;
    
    # wget compatibility:
    # different absolute paths are not retrieved with --no-parent
    if ($other[0] ne $current[0]){
        return 0;
    }
    my $i;
    for ($i=1; $i <= $#other && $i <= $#current; $i++){
        return 0 if $other[$i] ne $current[$i];
    }
    return 1;
}

# compute full path from a possible relative path from another
# replace . and .. with actual values
sub canonicalize {
    my ($path, $rel_to) = @_;
    if ($path =~ m{^/}){
        undef $rel_to;
    }
    my @st = split(m{/}, $rel_to // '');
    # $path =~ s{[^/]*$}{};       # remove trailing /
    for my $d (split(m{/}, $path)){
        next if $d eq '.';
        if ($d eq '..'){
            pop @st;
        } elsif ($d){
            push @st, $d;
        }
    }
    my $r = '/' . join('/', @st);
    $r .= '/' if $path =~ m{/$}; # put back final / if needed
    return $r;
}

# =========== Built-in JSON parser =============================================

sub TRACE_JSON {
    return $args{'debug-json'} ? 1 : 0;
}

my @eval_stack; my $trace_indent; my $object_count;
sub json_trace  { say STDERR ' ' x $trace_indent, @_ if TRACE_JSON}
sub dump_stack  { json_trace $_ for ("stack is -----", scalar(@eval_stack) . ' =>' . Dumper(\@eval_stack), '-----') }
sub push_val    { push @eval_stack, shift; }
sub peek_val    { my @idx = @_; @idx=(-1) unless @idx; return @eval_stack[ @idx ]; }
sub pop_val     { return pop @eval_stack; }
sub add_obj_val { my ($k,$v) = @_; $eval_stack[-1]->{$k} = $v; }
sub add_arr_val { my $v = shift; push @{$eval_stack[-1]}, $v; }
sub eval_json_string {
    my $s = shift;
    $s =~ s/\\u([0-9A-Fa-f]{4})/\\x{$1}/g;
    $s =~ s/([@\$*%])/\\$1/g;            # prevent interpolation of sigils
    return eval $s;
}

# Return a Perl structure corresponding to a json string
sub from_json {
    @eval_stack = ();
    $trace_indent = 0;
    $object_count = 0;
    
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

    (?&VALUE)             # <== entry point of the parser
    (?{ $_ = pop_val() }) # if the match succeeds, we assign $_ as the return value of the parser
    
    (?(DEFINE) # this does not try to match, it only defines a serie of named patterns
    
      (?<VALUE> (?{ json_trace 'value?' })
        \s*+
        (
         (?{ $trace_indent++; })
         (?&STRING)
         |
         (?&NUMBER)
         |
         true  (?{ push_val(1); json_trace '->true' })
         |
         false (?{ push_val(0); json_trace '->false' })
         |
         null  (?{ push_val($args{'json-stringify-null'}?'null':undef); json_trace '->null' })
         |
         (?&ARRAY)
         |
         (?&OBJECT)
        )
        \s*+
        (?{ $trace_indent--; })
        (?{ json_trace '->value'; dump_stack() if TRACE_JSON })
      )
    
      (?<OBJECT> # will generate a Perl hash
        (?{ json_trace "try object" })
        \{ # start of object
          (?{ push_val({}); $trace_indent++; })  # init structure
          \s*+
          (?: 
            (?&KV) # first pair
            (?{ 
               my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v);
               json_trace '->pair';
            })      
            (?: # additional pairs 
            \s*+ , \s*+ (?&KV)
             (?{ 
                 my $v = pop_val(); my $k = pop_val(); add_obj_val($k, $v);
               json_trace '->pairN';
             })
            )* # additional pairs are optional
          )? # object may be empty
          \s*+
        \}  # end of object
        (?{ $trace_indent--; $object_count++; say STDERR "$object_count objects" if $object_count % 10 == 0 and TRACE_JSON; json_trace "->object " . Dumper(peek_val()) })
      )
    
      (?<KV>  # tuple <key, value>
        (?{ json_trace 'try tuple' })
        (?&STRING)
        (?{ json_trace 'key done' })
        \s*+ : \s*+ 
        (?{ json_trace 'try tuple value' })
        (?&VALUE)
        (?{ json_trace '->tuple ', Dumper(peek_val(-2,-1)) })
      )
    
      (?<ARRAY> # will generate a Perl array
        (?{ json_trace "try array" })
        \[ # start of array
          (?{ push_val([]) })  # init structure
          \s*+
          (?: 
            (?&VALUE)   # first element 
            (?{  my $v = pop_val(); add_arr_val( $v )
            })
            (?: # additional elements
            \s*+ , \s*+ (?&VALUE) # additional elements
             (?{
                 my $v = pop_val(); add_arr_val( $v )
             })
            )* # additional elements are optional
          )? # array may be empty
          \s*+
        \] # end of array
        (?{ json_trace "->array " . Dumper(peek_val()) })
      )
    
      (?<STRING>
        (?{ json_trace "try string" })
        (
          "
          (?:
            [^"\\]+
          |
            \\ ["\\bfnrt]  # escaped backspace, form feed, newline, carriage return, tab, \, "
          | 
            \\ .           # other escaped characters (can be merged with previous one)
          |
            \\ u [0-9a-fA-F]{4} 
          )*
          "
        )
        (?{ 
            my $v = eval_json_string($^N); 
            push_val($v);
            json_trace sprintf('->string "%s"', peek_val());
        })
      )
    
      (?<NUMBER>
        (?{ json_trace "try number" })
        (
          -?
          (?: 0 | [1-9]\d* )
          (?: \. \d+ )?
          (?: [eE] [-+]? \d+ )?
        )
        (?{ my $v = eval $^N;
            push_val($v);
            json_trace "->number $v"; 
        })
      )
    
    ) #DEFINE
    }xms;
    my $struct;
    {
        local $_ = shift;
        # we do not use $^R anymore
        # local $^R;
        eval { m{\A$rx\z}; } and $struct = $_;
        #$DB::single = 1 unless $struct;
    }
    return $struct;
}

sub to_json {
    my $data = shift;
    # return 'expecting a hashref as input' unless ref $h eq 'HASH';

    my $j;
    state $level = 0;
    my $indent = $args{'json-pp-indent'};
    if (!defined $data){
        $j = "null";
    } elsif (ref $data eq 'HASH'){
        $j = '{';
        $level++;
        my @items;
        for my $k (keys %$data){
            my $v = $data->{$k};
            my $c = to_json($v);
            push @items, '"' . $k . '":' . ($args{'json-pp'} ? ' ' : '') . $c;
        }
        if ($args{'json-pp'}){
            $j .= "\n" . (' ' x $indent x $level) . join(",\n" . (' ' x $indent x $level), @items) . "\n";
        } else {
            $j .= join(',', @items);
        }
        $level--;
        $j .= (' ' x $indent x $level) if $args{'json-pp'};
        $j .= '}';
    } elsif (ref $data eq 'ARRAY'){
        my @items;
        $j = '[';
        $level++;
        (push @items, to_json($_)) for @$data;
        if ($args{'json-pp'}){
            $j .= "\n" . (' ' x $indent x $level) . join(",\n" . (' ' x $indent x $level), @items) . "\n";
        } else {
            $j .= join(',', @items);
        }
        $level--;
        $j .= (' ' x $indent x $level) if $args{'json-pp'};
        $j .= ']';
    } elsif ($data =~ /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/){
        $j = eval $&; # $& = last successful match
    } elsif ($data =~ /true/i){
        $j = "true";
    } elsif ($data =~ /false/i){
        $j = "false";
    } else {
        # return a string while escaping some chars
        $data =~ s/([\\"])/\\$1/g; 
        $data =~ s/[\n]/\\n/g;
        $data =~ s/[\r]/\\r/g;
        $data =~ s/[\b]/\\b/g;
        $data =~ s/[\f]/\\f/g;
        $data =~ s/[\t]/\\t/g;
        # $data =~ s/([\x00-\x1f]|[\x7f-\x{ffff}])/sprintf('\u%04x', ord($1))/eg; # for unicode chars
        $j = '"' . $data . '"';
    }
    return $j;
}

# =========== End of Built-in JSON parser ======================================
    
# get a value from a structure using an xpath-like
# can be a scalar or a complex struct
# in case of complex struct, return the jsonification   
sub get_jpath {
    my ($ref, $path, $fullpath) = @_;
    unless (ref $path eq 'ARRAY'){
        $fullpath = $path;              # keep a copy of initial path for reference in errors
        $path = substr($path, 1) if index($path, '/') == 0; # remove initial slash - supports /absolute/path
        $path = [ split /\//, $path ] ; # for first call path is not an array ref
    }
    print STDERR "Path: " . join(' / ', @$path) . "\n" if $args{debug};
    my $p = shift @$path || ''; # next element to get from path
    my $v;                      # placeholder for data
    if ($p =~ /(.+)(\[[^]]*\])$/){
        # support foo[] and foo/[] in the path
        $p = $1;
        unshift @$path, $2;
    }        
    if (ref $ref eq 'ARRAY'){
        if ($p =~ /^\[([^)]*)\]$/){ # we try to access an index ?
            my @indexes;
            my $idx = $1;
            if ($idx eq '*' || $idx eq ''){
                # array[] or array[*]
                @indexes = 0 .. $#{ $ref };
            } elsif ($idx =~ /^\d+(,\d+)*$/ ) { # notation foo()
                # array[1] or array[1,2,3]
                @indexes = split /,/, $&;
            } elsif ($idx =~ /^(\d+)\s*\.\.\s*(\d+)$/){
                # array[2 .. 12]
                @indexes = $1 .. $2;
            } else {
                die "Invalid index $idx in path $path";
            }
            if (scalar @indexes > 1){
                $v = [ map { jpath_array_accessor($ref, $_, $path, $fullpath) } @indexes ];
            } elsif (scalar @indexes == 1){
                $v = jpath_array_accessor($ref, $indexes[0], $path, $fullpath);
            } else {
                if (@$path){
                    return get_jpath($ref, $path, $fullpath);
                } else {
                    $v = $ref;
                }
            }
        } elsif ($p =~ /^(\w+)\(\)$/){
            return jpath_function($1, $ref);
        } else {
            die "Array is not accessible with '$p' in path '$fullpath'" if $p; # non-numeric index
            # return t
            $v = $ref;
        }
    } elsif (ref $ref eq 'HASH'){
        if ($p){
            # we still have a remaining path
            if ($p =~ /,/){     # we have a list of keys
                $v = { map { $_ => jpath_hash_accessor($ref, $_, $path, $fullpath) } split(/,/,$p) };
            } elsif (exists $ref->{$p}){ # we have a single key
                $v = $ref->{$p};
                return get_jpath($v, $path, $fullpath) if @$path;
            } elsif ($p =~ /^(\w+)\(\)$/){ # notation foo()
                return jpath_function($1, $ref);
            } elsif ($p =~ /^\[([^)]*)\]$/){
                die "Element of path is object, not array";
            } else {
                if ($args{'action-nullable-values'}){
                    return undef;
                } else {
                    die Dumper($ref) . "object does not contain '$p' in path '$fullpath'";
                }
            }
        } else {
            # no more path, return the object
            $v = $ref;
        }
    }
    return $v;
}

sub jpath_array_accessor {
    my ($array, $index, $path, $fullpath) = @_;
    say STDERR "Iterate index $index of array" if $args{debug};
    die sprintf("Index %d is greater than max index of array (%d) in path '%s'", $index, $#{$array}, $fullpath) if $index >= scalar @$array;

    my $elem = $array->[$index];
    if (@$path){
        my $path_copy = [ map { $_ } @$path ]; # deep copy of path
        return get_jpath($elem, $path_copy, $fullpath);
    }
    return $elem;
}

sub jpath_hash_accessor {
    my ($hash, $key, $path, $fullpath) = @_;
    say STDERR "Get key $key of hash" if $args{debug};

    my $elem = $hash->{$key};
    if (@$path){
        my $path_copy = [ map { $_ } @$path ]; # deep copy of path
        return get_jpath($elem, $path_copy, $fullpath);
    }
    return $elem;
}
sub jpath_function {
    my ($func, $ref) = @_;
    if ($func eq 'length'){     # pseudo function for size
        if (ref $ref eq 'ARRAY'){
            # array -> size of array
            return scalar @$ref;
        } elsif (ref $ref eq 'HASH'){
            # hash -> numberof keys
            return scalar keys %$ref;
        }
    } elsif ($func eq 'to_json'){
        return to_json($ref);
    } elsif ($func eq 'to_xml'){
        return xmlify($ref);
    } else {
        die "Unknown function $func() in action";
    }
}

sub xmlify {
    my ($val, $treepp) = @_;
    $treepp = XML::TreePP->new(
        xml_decl => '',
        pretty_print => $args{'xml-pp'}
        ) unless $treepp;
    if ($args{'xml-pp'}) {
        $treepp->set( indent => $args{'xml-pp-indent'} );
    }
    # say ref $val;
    # say Dumper $val;
    if (!ref $val || (ref $val eq 'HASH' && scalar keys %$val == 1)){
        return $treepp->write( $val );
    } else {
        if (ref $val eq 'ARRAY'){
            return $treepp->write( { $args{'xml-root-element'} => { item => $val } } );
        } else {
            return $treepp->write( { $args{'xml-root-element'} => $val } );
        }
    }
}

sub process_stomp {
    my $url_final = shift;
    my ($IN, $OUT, $ERR, $host, $port, $resp);

    redirect_output_to_file($args{output});

    # ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host}, $url_final->{port});
    ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host}, $url_final->{port}) if $url_final->{scheme} eq 'stomp';
    ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final) if $url_final->{scheme} eq 'stomp+ssl';

    my $USE_ACK = 1;
    
    my $connect = [
        'CONNECT',
        # "accept-version:1.1"
        ];
    if ($args{basic}){
        my ($user, $passwd) = split(/:/, $args{basic});
        push @$connect, ("login:${user}", "passcode:${passwd}");
    }
    send_stomp_request($OUT, $IN, $connect);
    $resp = process_stomp_response($IN, $args{'max-wait'} || $def_max_wait);
    if (keys %{$resp->[0]}){
        if ($resp->[0]->{command} eq 'CONNECTED'){
            if ($args{stompmsg}){
                my $body = $args{stompmsg};
                my $len = length($body);
                my $type = 'text/plain';
                send_stomp_request($OUT, $IN, [
                                       'SEND',
                                       "destination:$url_final->{path}",
                                       "content-type:${type}",
                                       "content-length:${len}",
                                       # "receipt: msg42"  # if using receipt header, server will send RECEIPT response
                                   ], $body );
            } elsif ($args{stompread}){
                send_stomp_request($OUT, $IN, [
                                       'SUBSCRIBE',
                                       "destination:$url_final->{path}",
                                       # 'ack: client', auto | client / if client and no ACK frame, message will persist
                                       sprintf('ack:%s', $USE_ACK ? 'client' : 'auto')
                                   ]);
                $resp = process_stomp_response($IN, 1);
                for my $frame (@$resp){
                    if (keys %$frame && $frame->{command} eq 'MESSAGE'){
                        say "Stomp headers:" . Dumper $frame if $args{debug};
                        say STDOUT "Message-ID:" . $frame->{headers}{'message-id'};
                        say STDOUT "Timestamp: " . scalar localtime $frame->{headers}{timestamp} / 1000;
                        say STDOUT "Priority: " . $frame->{headers}{priority};
                        say STDOUT $frame->{body} || 'No body';;
                        if ($USE_ACK){
                            my $mid = $frame->{headers}{'message-id'};
                            $mid =~ s/message-id:\s*//;
                            send_stomp_request($OUT, $IN, [
                                                   'ACK',
                                                   "message-id:$mid",
                                               ]);
                        }
                    }
                }
            }
            # be gentle and tell the server we have finished
            send_stomp_request($OUT, $IN, [ 'DISCONNECT' ]);
            # no answer expected
            
            # my $disc_resp = process_stomp_response($IN);
            # say "Stomp headers:" . Dumper $disc_resp->{headers};
        } else {
            say STDERR "Unexpected STOMP response: $resp->{command}";
            exit 13;
        }
    } else {
        say STDERR "STOMP not connected.";
        exit 13;
    }
    close $IN;
    close $OUT;
    close $ERR if $ERR;

    restore_output();
}

sub send_stomp_request {
    my ($OUT, $IN, $headers, $body) = @_;
    if ($args{verbose} || $args{debug}){
        say STDOUT "> $_" for @$headers;
    }
    my $request = join( "\n", @$headers ) . "\n\n" . ($body || '') . "\000\n";
    print $OUT $request;
}

sub process_stomp_response {
    my $IN = shift;
    my $timeout = shift;

    my $resp = [];
    my $buf;                    # allocate the buffer once and not in loop - thanks Ikegami!
    my $buf_size = 1024 * 1024;

    my $selector = IO::Select->new();
    $selector->add($IN);
  FRAME:
    while (1){
        my @ready = $selector->can_read($timeout);
        last FRAME unless @ready;     # empty array = timed-out
        foreach my $fh (@ready) {
            if (fileno($fh) == fileno($IN)) {
                my $bytes = $fh->sysread($buf, $buf_size);
                # if bytes undef -> error, if 0 -> eof, else number of read bytes
                my %frame;
                if (defined $bytes){
                    if($bytes){
                        # if ($args{debug}){
                        # print for unpack('(h2)*', $buf);
                        # say STDOUT for hexdump($buf) if $args{debug};
                        if ($buf =~ s/^\n*([^\n].*?)\n\n//s){
                            my $headers = $1;
                            for my $line (split /\n/,  $headers){
                                say STDOUT "< $line" if $args{verbose} || $args{debug};
                                if ($line =~ /^(\w+)$/){
                                    $frame{command} = $1;
                                }
                                if ($line =~ /^([^:]+):(.*)$/){
                                    $frame{headers}{$1} = $2;
                                }
                            }
                            if ($frame{headers}{'content-length'}){
                                if (length($buf) > $frame{headers}{'content-length'}){
                                    $frame{body} = substr($buf, 0, $frame{headers}{'content-length'}, '');
                                }
                            }
                        }
                        if ($buf =~ s/^(.*?)\000\n*//s ){
                            $frame{body} = $1 unless $frame{body};
                            push @$resp, \%frame;
                            $timeout = 0.1; # for next read short timeout
                            next FRAME;
                        } else {
                            die;
                        }
                    } else {
                        $selector->remove($fh); # EOF
                        last FRAME;
                    }
                } else {
                    # something is wrong
                    say STDERR "Error reading STOMP response: $!";
                }
            } else {
                # what? not the given fh
            }
        }
    }
    return $resp;
}

# Extract the differents parts from an URL
# return a hashref or undef if it fails
# this uses a extended regex as a recursive descent parser    
sub parse_uri {
    my $given = shift;
    unless( $given =~ qr{^
        # See RFC3986 - URI Generic Syntax
        #     foo://example.com:8042/over/there?name=ferret#nose
        #     \_/   \______________/\_________/ \_________/ \__/
        #      |           |            |            |        |
        #   scheme     authority       path        query   fragment
        #      |   _____________________|__
        #     / \ /                        \
        #     urn:example:animal:ferret:nose

        (?: (?<SCHEME> (?&SCHEME_ELEMS)) : )
        (?:  # HIERARCHICAL PART
          (?: / /
            (?: # AUTHORITY                # authority begins with '//'
              (?<USERINFO>
                (?<USER> (?&USERCHARS)+ )? (?: : (?<PWD>[^@]+) )? @   # note that password in URL is deprecated
              )?
              (?<HOST> (?&HOSTCHARS) )?
              (?: : (?<PORT> \d+ ))?
            (?<PATH1> (?: / (?&PCHAR)* )*              ) # begins with '/' or is empty
            )
          )
          | (?<PATH2> / (?&PCHAR)+ (?: / (?&PCHAR)* )* ) # begins with '/' but not '//'
          | (?<PATH3> (?&PATH_NOSCHEME)                ) # begins with a non-colon segment
          | (?<PATH4> (?&PATH_ROOTLESS)                ) # begins with a segment
          | (?<PATH5>                                  ) # zero characters
        )
        (?: \? (?<QUERY>    ( (?&PCHAR) | / | \? )* ) )?
        (?: \# (?<FRAGMENT> ( (?&PCHAR) | / | \? )* ) )?

        (?(DEFINE) # from here, define some callable sub-parts
                   # note that named capturing groups cannot be accessed via $+{} after match

          (?<SCHEME_ELEMS>  [A-Za-z0-9] [A-Za-z0-9+.-]*                          )
          #(?<PATH_ABEMPTY>  / (?&SEGMENT)                                       )
          #(?<PATH_ABSOLUTE> / (?&SEGMENT_NZ) (?: / (?&SEGMENT))*                )
          (?<PATH_NOSCHEME> (?&SEGMENT_NZ_NC)+ (?: / (?&SEGMENT))*               )
          (?<PATH_ROOTLESS> (?&SEGMENT_NZ) (?: / (?&SEGMENT))*                   )
          (?<PATH_EMPTY>                                                         ) # empty rule
          (?<SEGMENT>       (?&PCHAR)*                                           )
          (?<SEGMENT_NZ>    (?&PCHAR)+                                           )
          (?<SEGMENT_NZ_NC> (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL) | @     )
          (?<PCHAR>         (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL) | : | @ )
          (?<PCTENCODED>    % (?&HEXDIG) (?&HEXDIG)                              ) # Percent encoded
          (?<HEXDIG>        [0-9A-Za-z]                                          ) # hexadecimal digit
          (?<UNRESERVED>    [A-Za-z0-9._~-]                                      )
          #(?<RESERVED>     (?&GENDEL) | (?&SUBDEL)                              ) # reserved
          #(?<GENDEL>       [:/?\#\[\]@]                                         ) # generic delimiters
          (?<SUBDEL>        [!\$&'()\*\+,;=\.]                                   ) # subcomponent delimiters
          (?<USERCHARS>     (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL)         ) 
          (?<HOSTCHARS>     (?&IPLIT) | (?&IPV4) | (?&REG_NAME)                  )
          (?<IPLIT>         \[ ( (?&IPV6) | (?&IPFUTURE) ) \]                    ) # IP literal
          (?<IPFUTURE>      v (?&HEXDIG)+ \. ( (?&UNRESERVED) | (?&SUBDEL) | :)+ ) # future versions of IP
          (?<IPV6>            (?:                                        (?: (?&H16) : ){6} (?&LS32) )
                            | (?:                                     :: (?: (?&H16) : ){5} (?&LS32) )
                            | (?: (?:                      (?&H16) )? :: (?: (?&H16) : ){4} (?&LS32) )
                            | (?: (?: (?: (?&H16) : ){0,1} (?&H16) )? :: (?: (?&H16) : ){3} (?&LS32) )
                            | (?: (?: (?: (?&H16) : ){0,2} (?&H16) )? :: (?: (?&H16) : ){2} (?&LS32) )
                            | (?: (?: (?: (?&H16) : ){0,3} (?&H16) )? :: (?: (?&H16) : )    (?&LS32) )
                            | (?: (?: (?: (?&H16) : ){0,4} (?&H16) )? ::                    (?&LS32) )
                            | (?: (?: (?: (?&H16) : ){0,5} (?&H16) )? ::                    (?&H16)  )
                            | (?: (?: (?: (?&H16) : ){0,6} (?&H16) )? ::                             )
)
          (?<H16>           (?&HEXDIG) (?&HEXDIG)? (?&HEXDIG)? (?&HEXDIG)?       ) # up to 4 hex digits
          (?<LS32>          ( (?&H16) : (?&H16) ) | (?&IPV4)                     )
          (?<IPV4>          (?&DEC_OCTET) \. (?&DEC_OCTET) \. (?&DEC_OCTET) \. (?&DEC_OCTET) )
          (?<DEC_OCTET>     (?&DIGIT)                                              # 0-9
                            | (?:       [1-9] (?&DIGIT) )                          # 10-99
                            | (?: 1 (?&DIGIT) (?&DIGIT) )                          # 100-199
                            | (?: 2   [0-4]   (?&DIGIT) )                          # 200-249
                            | (?: 2 5 [0-5]             )                        ) # 250-255
          (?<DIGIT>         [0-9]                                                )
          (?<REG_NAME>      (?: (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL) )+  ) # Registered name (domain)
        )
            $}x ){
        return undef;
    }
    my $url = {};
    $url->{url} = $given;
    $url->{scheme} = $+{SCHEME};
    if ($+{USERINFO}){
        $url->{auth} = {
            user => $+{USER},
            $+{PWD} ? (password => $+{PWD}) : ()
        };
    }
    $url->{host}     = $+{HOST};
    # FIXME: parsing should only return port given in url (or default port corresponding to scheme)
    $url->{port}     = $args{port} || $+{PORT}; # if port given in parameter, override url port
    $url->{path}     = $+{PATH1} // $+{PATH2} // $+{PATH3} // $+{PATH4} // $+{PATH5} ;#|| '/';
    $url->{query}    = $+{QUERY};
    $url->{fragment} = $+{FRAGMENT};
    if ($args{debug}){
        say STDERR "* Parsed URL '$given'";
        say(STDERR "*  $_ = " . (defined $url->{$_} ? $url->{$_} : "undef")) for(sort(keys %$url));
    }
    return $url;
}

# dump of URL parts
sub dump_url {
    my $url = shift;
    for my $k (sort grep { defined $url->{$_} } keys %$url){
        if (ref $url->{$k} eq 'HASH'){
            my $h = $url->{$k};
            say STDOUT "$k:$_ = $h->{$_}" for sort keys %$h;
        } else {
            say STDOUT "$k = $url->{$k}";
        }
    }
}

# make local directory tree
sub make_path {
    my ($path, $from) = @_;
    if (index($path, '/') == 0){
        # remove initial separator
        $path = substr($path, 1);
    }
    if ($path =~ m{(.+)/[^/]*$}){
        my @dirs = split '/', $1;
        for (my $i=0; $i<= $#dirs; $i++){
            my $dir_to_create = join '/', @dirs[ 0 .. $i ];
            unless (-d $dir_to_create){
                mkdir $dir_to_create or die "Cannot create directory $dir_to_create: $!";
            }
        }
    } # else a file?
}

# try to interpret the Last-Modified timestamp
sub str2epoch {
    my $s = shift;
    my $e = -1;
    my %months = ( Jan=>0, Feb=>1, Mar=>2, Apr=>3, May=>4, Jun=>5, Jul=>6, Aug=>7, Sep=>8, Oct=>9, Nov=>10, Dec=>11 );
    # Last-Modified: <nom-jour>, <jour> <mois> <année> <heure>:<minute>:<seconde> GMT
    if ($s =~ /\w\w\w, (\d?\d) (\w\w\w) (\d\d\d\d) (\d\d):(\d\d):(\d\d) GMT/){
        $e = timegm($6, $5, $4, $1, $months{$2}, $3-1900);
    } else {
        say STDERR "* FIXME: cannot interpret Last-Modified timestamp: `$s`";
    }
    return $e;
}
    
# perform a string encoding compatible with url
sub urlencode {
    my $s = shift;
    $s =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/eg;
    return $s;
}

# decode an url-encoded string
sub urldecode {
    my $s = shift;
    $s =~ s/\+/ /g;
    $s =~ s/%(..)/pack('c', hex($1))/eg;
    return $s;
}

# tell if we requested HTTP v0.9
sub HTTP09 {
    return ($http_vers && $http_vers eq '0.9') ? 1 : undef;
}

# tell if we requested HTTP v1.0
sub HTTP10 {
    return ($http_vers && $http_vers eq '1.0') ? 1 : undef;
}

# tell if we requested HTTP v1.1
sub HTTP11 {
    return ($http_vers && $http_vers eq '1.1') ? 1 : undef;
}

# creation of a direct socket connection 
sub connect_direct_socket {
    my ($host, $port) = @_;
    my $sock = new IO::Socket::INET(PeerAddr => $host,
                                    PeerPort => $port,
                                    Proto    => 'tcp') or die "Can't connect to $host:$port\n";
    if ($args{'tcp-nodelay'}){
        $sock->setsockopt(IPPROTO_TCP, TCP_NODELAY, 1);
        say STDERR "* TCP_NODELAY set" if $args{verbose} || $args{debug};
    }
    $sock->autoflush(1);
    say STDERR "* connected to $host port $port" if $args{verbose} || $args{debug};
    
    return $sock, $sock, undef;
}

# for HTTPS, we are "cheating" by creating a tunnel with OpenSSL in s_client mode
sub connect_ssl_tunnel {
    my ($dest, $proxy) = @_;
    my ($host, $port, $phost, $pport);
    $host = $dest->{host};
    $port = $dest->{port};
    if ($proxy){
        $phost = $proxy->{host};
        $pport = $proxy->{port};
    }
    my $ossl_version = `openssl version`;
    
    my $cmd = "openssl s_client -connect ${host}:${port} -servername ${host} -quiet";# -quiet -verify_quiet -partial_chain';
    $cmd .= ' -4' if ($ossl_version =~ /^\w+ 3/); # use IPv4 only (unsupported by OpenSSL 1.02)
    $cmd .= ' -no_check_time' if $args{insecure}; # useless?
    $cmd .= " -proxy ${phost}:${pport}" if $phost;
    $cmd .= ' -ssl3' if $args{'sslv3'};
    $cmd .= ' -tls1' if $args{'tlsv1_0'};
    $cmd .= ' -tls1_1' if $args{'tlsv1_1'};
    $cmd .= ' -tls1_2' if $args{'tlsv1_2'};
    $cmd .= ' -tls1_3' if $args{'tlsv1_3'};
    $cmd .= " -CAfile $args{'ssl-ca'}" if $args{'ssl-ca'};
    $cmd .= " -cert $args{'ssl-cert'}" if $args{'ssl-cert'};
    $cmd .= " -key $args{'ssl-key'}" if $args{'ssl-key'};
    $tunnel_pid = open3(*CMD_IN, *CMD_OUT, *CMD_ERR, $cmd);
    say STDERR "* connected via OpenSSL to $host:$port" if $args{verbose} || $args{debug};
    say STDERR "* command = $cmd" if $args{debug};

    $SIG{CHLD} = sub {
        print STDERR "* REAPER: status $? on ${tunnel_pid}\n" if waitpid($tunnel_pid, 0) > 0 && $args{debug};
    };
    return *CMD_IN, *CMD_OUT, *CMD_ERR;
}

# poor man's hex dumper :)
sub hexdump {
    use bytes;                  # ensure to work on bytes
    my $data = shift;
    my $data_len = shift || 16;
    my $ascii_only = shift || 0;
    my $hex_len = $data_len * 3;
    my $addr = 0;
    my @out;
    for my $s (unpack("(a${data_len})*", $data)){
        last unless $s;
        my $h = join ' ', unpack('(H2)*', $s);
        $s =~ s/[\x00-\x1f]/./g;
        $s =~ s/[\x80-\xff]/./g if $ascii_only;        
        push @out, sprintf("%06x  %-${hex_len}s %s", $addr, $h, $s);
        $addr += length($s);
    }
    return @out;
}

sub humanize_bytes {
    my $len = shift;
    my $r;
    
    if ($len >= 2 ** 30){
        $r = sprintf("%.1f GiB", $len / 2 ** 30);
    } elsif ($len >= 2 ** 20){
        $r = sprintf("%.1f MiB", $len / 2 ** 20);
    } elsif ($len >= 2 ** 10){
        $r = sprintf("%.1f KiB", $len / 2 ** 10);
    } else {
        $r = $len;
    }
    return $r;
}



BEGIN {
# ================== XML::TreePP =======================

package XML::TreePP;
use strict;
use Carp;
use Symbol;

use vars qw( $VERSION );
$VERSION = '0.41';

my $XML_ENCODING      = 'UTF-8';
my $INTERNAL_ENCODING = 'UTF-8';
my $USER_AGENT        = 'XML-TreePP/'.$VERSION.' ';
my $ATTR_PREFIX       = '-';
my $TEXT_NODE_KEY     = '#text';
my $USE_ENCODE_PM     = ( $] >= 5.008 );
my $ALLOW_UTF8_FLAG   = ( $] >= 5.008001 );

sub new {
    my $package = shift;
    my $self    = {@_};
    bless $self, $package;
    $self;
}

sub die {
    my $self = shift;
    my $mess = shift;
    return if $self->{ignore_error};
    Carp::croak $mess;
}

sub warn {
    my $self = shift;
    my $mess = shift;
    return if $self->{ignore_error};
    Carp::carp $mess;
}

sub set {
    my $self = shift;
    my $key  = shift;
    my $val  = shift;
    if ( defined $val ) {
        $self->{$key} = $val;
    }
    else {
        delete $self->{$key};
    }
}

sub get {
    my $self = shift;
    my $key  = shift;
    $self->{$key} if exists $self->{$key};
}

sub writefile {
    my $self   = shift;
    my $file   = shift;
    my $tree   = shift or return $self->die( 'Invalid tree' );
    my $encode = shift;
    return $self->die( 'Invalid filename' ) unless defined $file;
    my $text = $self->write( $tree, $encode );
    if ( $ALLOW_UTF8_FLAG && utf8::is_utf8( $text ) ) {
        utf8::encode( $text );
    }
    $self->write_raw_xml( $file, $text );
}

sub write {
    my $self = shift;
    my $tree = shift or return $self->die( 'Invalid tree' );
    my $from = $self->{internal_encoding} || $INTERNAL_ENCODING;
    my $to   = shift || $self->{output_encoding} || $XML_ENCODING;
    my $decl = $self->{xml_decl};
    $decl = '<?xml version="1.0" encoding="' . $to . '" ?>' unless defined $decl;

    local $self->{__first_out};
    if ( exists $self->{first_out} ) {
        my $keys = $self->{first_out};
        $keys = [$keys] unless ref $keys;
        $self->{__first_out} = { map { $keys->[$_] => $_ } 0 .. $#$keys };
    }

    local $self->{__last_out};
    if ( exists $self->{last_out} ) {
        my $keys = $self->{last_out};
        $keys = [$keys] unless ref $keys;
        $self->{__last_out} = { map { $keys->[$_] => $_ } 0 .. $#$keys };
    }

    my $tnk = $self->{text_node_key} if exists $self->{text_node_key};
    $tnk = $TEXT_NODE_KEY unless defined $tnk;
    local $self->{text_node_key} = $tnk;

    my $apre = $self->{attr_prefix} if exists $self->{attr_prefix};
    $apre = $ATTR_PREFIX unless defined $apre;
    local $self->{__attr_prefix_len} = length($apre);
    local $self->{__attr_prefix_rex} = $apre;

    local $self->{__indent};
    if ( exists $self->{indent} && $self->{indent} ) {
        $self->{__indent} = ' ' x $self->{indent};
    }

    if ( ! UNIVERSAL::isa( $tree, 'HASH' )) {
        return $self->die( 'Invalid tree' );
    }

    my $text = $self->hash_to_xml( undef, $tree );
    if ( $from && $to ) {
        my $stat = $self->encode_from_to( \$text, $from, $to );
        return $self->die( "Unsupported encoding: $to" ) unless $stat;
    }

    return $text if ( $decl eq '' );
    join( "\n", $decl, $text );
}

sub load_tie_ixhash {
    return $Tie::IxHash::VERSION if defined $Tie::IxHash::VERSION;
    local $@;
    eval { require Tie::IxHash; };
    $Tie::IxHash::VERSION;
}

sub parsefile {
    my $self = shift;
    my $file = shift;
    return $self->die( 'Invalid filename' ) unless defined $file;
    my $text = $self->read_raw_xml($file);
    $self->parse( \$text );
}

sub parse {
    my $self = shift;
    my $text = ref $_[0] ? ${$_[0]} : $_[0];
    return $self->die( 'Null XML source' ) unless defined $text;

    my $from = &xml_decl_encoding(\$text) || $XML_ENCODING;
    my $to   = $self->{internal_encoding} || $INTERNAL_ENCODING;
    if ( $from && $to ) {
        my $stat = $self->encode_from_to( \$text, $from, $to );
        return $self->die( "Unsupported encoding: $from" ) unless $stat;
    }

    local $self->{__force_array};
    local $self->{__force_array_all};
    if ( exists $self->{force_array} ) {
        my $force = $self->{force_array};
        $force = [$force] unless ref $force;
        $self->{__force_array} = { map { $_ => 1 } @$force };
        $self->{__force_array_all} = $self->{__force_array}->{'*'};
    }

    local $self->{__force_hash};
    local $self->{__force_hash_all};
    if ( exists $self->{force_hash} ) {
        my $force = $self->{force_hash};
        $force = [$force] unless ref $force;
        $self->{__force_hash} = { map { $_ => 1 } @$force };
        $self->{__force_hash_all} = $self->{__force_hash}->{'*'};
    }

    my $tnk = $self->{text_node_key} if exists $self->{text_node_key};
    $tnk = $TEXT_NODE_KEY unless defined $tnk;
    local $self->{text_node_key} = $tnk;

    my $apre = $self->{attr_prefix} if exists $self->{attr_prefix};
    $apre = $ATTR_PREFIX unless defined $apre;
    local $self->{attr_prefix} = $apre;

    if ( exists $self->{use_ixhash} && $self->{use_ixhash} ) {
        return $self->die( "Tie::IxHash is required." ) unless &load_tie_ixhash();
    }

    # Avoid segfaults when receving random input (RT #42441)
    if ( exists $self->{require_xml_decl} && $self->{require_xml_decl} ) {
        return $self->die( "XML declaration not found" ) unless looks_like_xml(\$text);
    }

    my $flat  = $self->xml_to_flat(\$text);
    my $class = $self->{base_class} if exists $self->{base_class};
    my $tree  = $self->flat_to_tree( $flat, '', $class );
    if ( ref $tree ) {
        if ( defined $class ) {
            bless( $tree, $class );
        }
        elsif ( exists $self->{elem_class} && $self->{elem_class} ) {
            bless( $tree, $self->{elem_class} );
        }
    }
    wantarray ? ( $tree, $text ) : $tree;
}

sub xml_to_flat {
    my $self    = shift;
    my $textref = shift;    # reference
    my $flat    = [];
    my $prefix = $self->{attr_prefix};
    my $ixhash = ( exists $self->{use_ixhash} && $self->{use_ixhash} );

    my $deref = \&xml_unescape;
    my $xml_deref = ( exists $self->{xml_deref} && $self->{xml_deref} );
    if ( $xml_deref ) {
        if (( exists $self->{utf8_flag} && $self->{utf8_flag} ) ||
            ( $ALLOW_UTF8_FLAG && utf8::is_utf8( $$textref ))) {
            $deref = \&xml_deref_string;
        } else {
            $deref = \&xml_deref_octet;
        }
    }

    while ( $$textref =~ m{
        ([^<]*) <
        ((
            \? ([^<>]*) \?
        )|(
            \!\[CDATA\[(.*?)\]\]
        )|(
            \!DOCTYPE\s+([^\[\]<>]*(?:\[.*?\]\s*)?)
        )|(
            \!--(.*?)--
        )|(
            ([^\!\?\s<>](?:"[^"]*"|'[^']*'|[^"'<>])*)
        ))
        > ([^<]*)
    }sxg ) {
        my (
            $ahead,     $match,    $typePI,   $contPI,   $typeCDATA,
            $contCDATA, $typeDocT, $contDocT, $typeCmnt, $contCmnt,
            $typeElem,  $contElem, $follow
          )
          = ( $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13 );
        if ( defined $ahead && $ahead =~ /\S/ ) {
            $ahead =~ s/([^\040-\076])/sprintf("\\x%02X",ord($1))/eg;
            $self->warn( "Invalid string: [$ahead] before <$match>" );
        }

        if ($typeElem) {                        # Element
            my $node = {};
            if ( $contElem =~ s#^/## ) {
                $node->{endTag}++;
            }
            elsif ( $contElem =~ s#/$## ) {
                $node->{emptyTag}++;
            }
            else {
                $node->{startTag}++;
            }
            $node->{tagName} = $1 if ( $contElem =~ s#^(\S+)\s*## );
            unless ( $node->{endTag} ) {
                my $attr;
                while ( $contElem =~ m{
                    ([^\s\=\"\']+)\s*=\s*(?:(")(.*?)"|'(.*?)')
                }sxg ) {
                    my $key = $1;
                    my $val = &$deref( $2 ? $3 : $4 );
                    if ( ! ref $attr ) {
                        $attr = {};
                        tie( %$attr, 'Tie::IxHash' ) if $ixhash;
                    }
                    $attr->{$prefix.$key} = $val;
                }
                $node->{attributes} = $attr if ref $attr;
            }
            push( @$flat, $node );
        }
        elsif ($typeCDATA) {    ## CDATASection
            if ( exists $self->{cdata_scalar_ref} && $self->{cdata_scalar_ref} ) {
                push( @$flat, \$contCDATA );    # as reference for scalar
            }
            else {
                push( @$flat, $contCDATA );     # as scalar like text node
            }
        }
        elsif ($typeCmnt) {                     # Comment (ignore)
        }
        elsif ($typeDocT) {                     # DocumentType (ignore)
        }
        elsif ($typePI) {                       # ProcessingInstruction (ignore)
        }
        else {
            $self->warn( "Invalid Tag: <$match>" );
        }
        if ( $follow =~ /\S/ ) {                # text node
            my $val = &$deref($follow);
            push( @$flat, $val );
        }
    }
    $flat;
}

sub flat_to_tree {
    my $self   = shift;
    my $source = shift;
    my $parent = shift;
    my $class  = shift;
    my $tree   = {};
    my $text   = [];

    if ( exists $self->{use_ixhash} && $self->{use_ixhash} ) {
        tie( %$tree, 'Tie::IxHash' );
    }

    while ( scalar @$source ) {
        my $node = shift @$source;
        if ( !ref $node || UNIVERSAL::isa( $node, "SCALAR" ) ) {
            push( @$text, $node );              # cdata or text node
            next;
        }
        my $name = $node->{tagName};
        if ( $node->{endTag} ) {
            last if ( $parent eq $name );
            return $self->die( "Invalid tag sequence: <$parent></$name>" );
        }
        my $elem = $node->{attributes};
        my $forcehash = $self->{__force_hash_all} || $self->{__force_hash}->{$name};
        my $subclass;
        if ( defined $class ) {
            my $escname = $name;
            $escname =~ s/\W/_/sg;
            $subclass = $class.'::'.$escname;
        }
        if ( $node->{startTag} ) {              # recursive call
            my $child = $self->flat_to_tree( $source, $name, $subclass );
            next unless defined $child;
            my $hasattr = scalar keys %$elem if ref $elem;
            if ( UNIVERSAL::isa( $child, "HASH" ) ) {
                if ( $hasattr ) {
                    # some attributes and some child nodes
                    %$elem = ( %$elem, %$child );
                }
                else {
                    # some child nodes without attributes
                    $elem = $child;
                }
            }
            else {
                if ( $hasattr ) {
                    # some attributes and text node
                    $elem->{$self->{text_node_key}} = $child;
                }
                elsif ( $forcehash ) {
                    # only text node without attributes
                    $elem = { $self->{text_node_key} => $child };
                }
                else {
                    # text node without attributes
                    $elem = $child;
                }
            }
        }
        elsif ( $forcehash && ! ref $elem ) {
            $elem = {};
        }
        # bless to a class by base_class or elem_class
        if ( ref $elem && UNIVERSAL::isa( $elem, "HASH" ) ) {
            if ( defined $subclass ) {
                bless( $elem, $subclass );
            } elsif ( exists $self->{elem_class} && $self->{elem_class} ) {
                my $escname = $name;
                $escname =~ s/\W/_/sg;
                my $elmclass = $self->{elem_class}.'::'.$escname;
                bless( $elem, $elmclass );
            }
        }
        # next unless defined $elem;
        $tree->{$name} ||= [];
        push( @{ $tree->{$name} }, $elem );
    }
    if ( ! $self->{__force_array_all} ) {
        foreach my $key ( keys %$tree ) {
            next if $self->{__force_array}->{$key};
            next if ( 1 < scalar @{ $tree->{$key} } );
            $tree->{$key} = shift @{ $tree->{$key} };
        }
    }
    my $haschild = scalar keys %$tree;
    if ( scalar @$text ) {
        if ( scalar @$text == 1 ) {
            # one text node (normal)
            $text = shift @$text;
        }
        elsif ( ! scalar grep {ref $_} @$text ) {
            # some text node splitted
            $text = join( '', @$text );
        }
        else {
            # some cdata node
            my $join = join( '', map {ref $_ ? $$_ : $_} @$text );
            $text = \$join;
        }
        if ( $haschild ) {
            # some child nodes and also text node
            $tree->{$self->{text_node_key}} = $text;
        }
        else {
            # only text node without child nodes
            $tree = $text;
        }
    }
    elsif ( ! $haschild ) {
        # no child and no text
        $tree = "";
    }
    $tree;
}

sub hash_to_xml {
    my $self      = shift;
    my $name      = shift;
    my $hash      = shift;
    my $out       = [];
    my $attr      = [];
    my $allkeys   = [ keys %$hash ];
    my $fo = $self->{__first_out} if ref $self->{__first_out};
    my $lo = $self->{__last_out}  if ref $self->{__last_out};
    my $firstkeys = [ sort { $fo->{$a} <=> $fo->{$b} } grep { exists $fo->{$_} } @$allkeys ] if ref $fo;
    my $lastkeys  = [ sort { $lo->{$a} <=> $lo->{$b} } grep { exists $lo->{$_} } @$allkeys ] if ref $lo;
    $allkeys = [ grep { ! exists $fo->{$_} } @$allkeys ] if ref $fo;
    $allkeys = [ grep { ! exists $lo->{$_} } @$allkeys ] if ref $lo;
    unless ( exists $self->{use_ixhash} && $self->{use_ixhash} ) {
        $allkeys = [ sort @$allkeys ];
    }
    my $prelen = $self->{__attr_prefix_len};
    my $pregex = $self->{__attr_prefix_rex};
    my $textnk = $self->{text_node_key};

    foreach my $keys ( $firstkeys, $allkeys, $lastkeys ) {
        next unless ref $keys;
        my $elemkey = $prelen ? [ grep { substr($_,0,$prelen) ne $pregex } @$keys ] : $keys;
        my $attrkey = $prelen ? [ grep { substr($_,0,$prelen) eq $pregex } @$keys ] : [];

        foreach my $key ( @$elemkey ) {
            my $val = $hash->{$key};
            if ( !defined $val ) {
                next if ($key eq $textnk);
                if ($self->{pretty_print}){
                    push( @$out, "<$key />" );
                } else {
                    push( @$out, "<$key/>" );
                }
            }
            elsif ( UNIVERSAL::isa( $val, 'HASH' ) ) {
                my $child = $self->hash_to_xml( $key, $val );
                push( @$out, $child );
            }
            elsif ( UNIVERSAL::isa( $val, 'ARRAY' ) ) {
                my $child = $self->array_to_xml( $key, $val );
                push( @$out, $child );
            }
            elsif ( UNIVERSAL::isa( $val, 'SCALAR' ) ) {
                my $child = $self->scalaref_to_cdata( $key, $val );
                push( @$out, $child );
            }
            else {
                my $ref = ref $val;
                $self->warn( "Unsupported reference type: $ref in $key" ) if $ref;
                my $child = $self->scalar_to_xml( $key, $val );
                push( @$out, $child );
            }
        }

        foreach my $key ( @$attrkey ) {
            my $name = substr( $key, $prelen );
            my $val = &xml_escape( $hash->{$key} );
            push( @$attr, ' ' . $name . '="' . $val . '"' );
        }
    }
    my $jattr = join( '', @$attr );

    if ( defined $name && scalar @$out && ! grep { ! /^</s } @$out ) {
        # Use human-friendly white spacing
        if ( defined $self->{__indent} ) {
            s/^(\s*<)/$self->{__indent}$1/mg foreach @$out;
        }
    }

    my $text;
    if ($self->{pretty_print}){
        $text = join( "\n", @$out );
    } else {
        $text = join( '', @$out );
    }
    if ( defined $name ) {
        if ( scalar @$out ) {
            if ($self->{pretty_print}){
                $text = "<$name$jattr>\n$text\n</$name>";
            } else {
                $text = "<$name$jattr>$text</$name>";
            }
        }
        else {
            if ($self->{pretty_print}){
                $text = "<$name$jattr />";
            } else {
                $text = "<$name$jattr/>";
            }
        }
    }
    $text;
}

sub array_to_xml {
    my $self  = shift;
    my $name  = shift;
    my $array = shift;
    my $out   = [];
    foreach my $val (@$array) {
        if ( !defined $val ) {
            if ($self->{pretty_print}){
                push( @$out, "<$name />" );
            } else {
                push( @$out, "<$name/>" );
            }
        }
        elsif ( UNIVERSAL::isa( $val, 'HASH' ) ) {
            my $child = $self->hash_to_xml( $name, $val );
            push( @$out, $child );
        }
        elsif ( UNIVERSAL::isa( $val, 'ARRAY' ) ) {
            my $child = $self->array_to_xml( $name, $val );
            push( @$out, $child );
        }
        elsif ( UNIVERSAL::isa( $val, 'SCALAR' ) ) {
            my $child = $self->scalaref_to_cdata( $name, $val );
            push( @$out, $child );
        }
        else {
            my $ref = ref $val;
            $self->warn( "Unsupported reference type: $ref in $name" ) if $ref;
            my $child = $self->scalar_to_xml( $name, $val );
            push( @$out, $child );
        }
    }

    my $text;
    if ($self->{pretty_print}){
        $text = join( "\n", @$out );
    } else {
        $text = join( '', @$out );
    }
    $text;
}

sub scalaref_to_cdata {
    my $self = shift;
    my $name = shift;
    my $ref  = shift;
    my $data = defined $$ref ? $$ref : '';
    $data =~ s#(]])(>)#$1]]><![CDATA[$2#g;
    my $text = '<![CDATA[' . $data . ']]>';
    $text = "<$name>$text</$name>" if ( $name ne $self->{text_node_key} );
    $text;
}

sub scalar_to_xml {
    my $self   = shift;
    my $name   = shift;
    my $scalar = shift;
    my $copy   = $scalar;
    my $text   = &xml_escape($copy);
    $text = "<$name>$text</$name>" if ( $name ne $self->{text_node_key} );
    $text;
}

sub write_raw_xml {
    my $self = shift;
    my $file = shift;
    my $fh   = Symbol::gensym();
    open( $fh, ">$file" ) or return $self->die( "$! - $file" );
    print $fh @_;
    close($fh);
}

sub read_raw_xml {
    my $self = shift;
    my $file = shift;
    my $fh   = Symbol::gensym();
    open( $fh, $file ) or return $self->die( "$! - $file" );
    local $/ = undef;
    my $text = <$fh>;
    close($fh);
    $text;
}

sub looks_like_xml {
    my $textref = shift;
    my $args = ( $$textref =~ /^(?:\s*\xEF\xBB\xBF)?\s*<\?xml(\s+\S.*)\?>/s )[0];
    if ( ! $args ) {
        return;
    }
    return $args;
}

sub xml_decl_encoding {
    my $textref = shift;
    return unless defined $$textref;
    my $args    = looks_like_xml($textref) or return;
    my $getcode = ( $args =~ /\s+encoding=(".*?"|'.*?')/ )[0] or return;
    $getcode =~ s/^['"]//;
    $getcode =~ s/['"]$//;
    $getcode;
}

sub encode_from_to {
    my $self   = shift;
    my $txtref = shift or return;
    my $from   = shift or return;
    my $to     = shift or return;

    unless ( defined $Encode::EUCJPMS::VERSION ) {
        $from = 'EUC-JP' if ( $from =~ /\beuc-?jp-?(win|ms)$/i );
        $to   = 'EUC-JP' if ( $to   =~ /\beuc-?jp-?(win|ms)$/i );
    }

    my $RE_IS_UTF8 = qr/^utf-?8$/i;
    if ( $from =~ $RE_IS_UTF8 ) {
        $$txtref =~ s/^\xEF\xBB\xBF//s;         # UTF-8 BOM (Byte Order Mark)
    }

    my $setflag = $self->{utf8_flag} if exists $self->{utf8_flag};
    if ( ! $ALLOW_UTF8_FLAG && $setflag ) {
        return $self->die( "Perl 5.8.1 is required for utf8_flag: $]" );
    }

    if ( $USE_ENCODE_PM ) {
        &load_encode();
        my $encver = ( $Encode::VERSION =~ /^([\d\.]+)/ )[0];
        my $check = ( $encver < 2.13 ) ? 0x400 : Encode::FB_XMLCREF();

        my $encfrom = Encode::find_encoding($from) if $from;
        return $self->die( "Unknown encoding: $from" ) unless ref $encfrom;
        my $encto   = Encode::find_encoding($to) if $to;
        return $self->die( "Unknown encoding: $to" ) unless ref $encto;

        if ( $ALLOW_UTF8_FLAG && utf8::is_utf8( $$txtref ) ) {
            if ( $to =~ $RE_IS_UTF8 ) {
                # skip
            } else {
                $$txtref = $encto->encode( $$txtref, $check );
            }
        } else {
            $$txtref = $encfrom->decode( $$txtref );
            if ( $to =~ $RE_IS_UTF8 && $setflag ) {
                # skip
            } else {
                $$txtref = $encto->encode( $$txtref, $check );
            }
        }
    }
    elsif ( (  uc($from) eq 'ISO-8859-1'
            || uc($from) eq 'US-ASCII'
            || uc($from) eq 'LATIN-1' ) && uc($to) eq 'UTF-8' ) {
        &latin1_to_utf8($txtref);
    }
    else {
        my $jfrom = &get_jcode_name($from);
        my $jto   = &get_jcode_name($to);
        return $to if ( uc($jfrom) eq uc($jto) );
        if ( $jfrom && $jto ) {
            &load_jcode();
            if ( defined $Jcode::VERSION ) {
                Jcode::convert( $txtref, $jto, $jfrom );
            }
            else {
                return $self->die( "Jcode.pm is required: $from to $to" );
            }
        }
        else {
            return $self->die( "Encode.pm is required: $from to $to" );
        }
    }
    $to;
}

sub load_jcode {
    return if defined $Jcode::VERSION;
    local $@;
    eval { require Jcode; };
}

sub load_encode {
    return if defined $Encode::VERSION;
    local $@;
    eval { require Encode; };
}

sub latin1_to_utf8 {
    my $strref = shift;
    $$strref =~ s{
        ([\x80-\xFF])
    }{
        pack( 'C2' => 0xC0|(ord($1)>>6),0x80|(ord($1)&0x3F) )
    }exg;
}

sub get_jcode_name {
    my $src = shift;
    my $dst;
    if ( $src =~ /^utf-?8$/i ) {
        $dst = 'utf8';
    }
    elsif ( $src =~ /^euc.*jp(-?(win|ms))?$/i ) {
        $dst = 'euc';
    }
    elsif ( $src =~ /^(shift.*jis|cp932|windows-31j)$/i ) {
        $dst = 'sjis';
    }
    elsif ( $src =~ /^iso-2022-jp/ ) {
        $dst = 'jis';
    }
    $dst;
}

sub xml_escape {
    my $str = shift;
    return '' unless defined $str;
    # except for TAB(\x09),CR(\x0D),LF(\x0A)
    $str =~ s{
        ([\x00-\x08\x0B\x0C\x0E-\x1F\x7F])
    }{
        sprintf( '&#%d;', ord($1) );
    }gex;
    $str =~ s/&(?!#(\d+;|x[\dA-Fa-f]+;))/&amp;/g;
    $str =~ s/</&lt;/g;
    $str =~ s/>/&gt;/g;
    $str =~ s/'/&apos;/g;
    $str =~ s/"/&quot;/g;
    $str;
}

sub xml_unescape {
    my $str = shift;
    my $map = {qw( quot " lt < gt > apos ' amp & )};
    $str =~ s{
        (&(?:\#(\d{1,3})|\#x([0-9a-fA-F]{1,2})|(quot|lt|gt|apos|amp));)
    }{
        $4 ? $map->{$4} : &code_to_ascii( $3 ? hex($3) : $2, $1 );
    }gex;
    $str;
}

sub xml_deref_octet {
    my $str = shift;
    my $map = {qw( quot " lt < gt > apos ' amp & )};
    $str =~ s{
        (&(?:\#(\d{1,7})|\#x([0-9a-fA-F]{1,6})|(quot|lt|gt|apos|amp));)
    }{
        $4 ? $map->{$4} : &code_to_utf8( $3 ? hex($3) : $2, $1 );
    }gex;
    $str;
}

sub xml_deref_string {
    my $str = shift;
    my $map = {qw( quot " lt < gt > apos ' amp & )};
    $str =~ s{
        (&(?:\#(\d{1,7})|\#x([0-9a-fA-F]{1,6})|(quot|lt|gt|apos|amp));)
    }{
        $4 ? $map->{$4} : pack( U => $3 ? hex($3) : $2 );
    }gex;
    $str;
}

sub code_to_ascii {
    my $code = shift;
    if ( $code <= 0x007F ) {
        return pack( C => $code );
    }
    return shift if scalar @_;      # default value
    sprintf( '&#%d;', $code );
}

sub code_to_utf8 {
    my $code = shift;
    if ( $code <= 0x007F ) {
        return pack( C => $code );
    }
    elsif ( $code <= 0x07FF ) {
        return pack( C2 => 0xC0|($code>>6), 0x80|($code&0x3F));
    }
    elsif ( $code <= 0xFFFF ) {
        return pack( C3 => 0xE0|($code>>12), 0x80|(($code>>6)&0x3F), 0x80|($code&0x3F));
    }
    elsif ( $code <= 0x10FFFF ) {
        return pack( C4 => 0xF0|($code>>18), 0x80|(($code>>12)&0x3F), 0x80|(($code>>6)&0x3F), 0x80|($code&0x3F));
    }
    return shift if scalar @_;      # default value
    sprintf( '&#x%04X;', $code );
}
# =========== end of XML::TreePP =======================

} # BEGIN

return 42 if defined(wantarray); # true value when used as package


__END__

=head1 NAME

pCurl - A minimalist cURL in Perl.

=head1 VERSION

v0.7.3

=head1 SYNOPSIS

perl Net/Pcurl.pm [options] [url]

=head1 DESCRIPTION

pCurl is a vanilla Perl tool that mimics cURL without external dependancies but OpenSSL in the case of a SSL connection. It is intented to provide a subset of cURL when cURL is not available. It is designed to work with a fresh installation of Perl without the need for additional CPAN packages.

=head1 OPTIONS

=head2 General resource access

=over 4

=item --accept <mime type>

Specify an accepted MIME type. This is simply a shortcut for -H 'Accept: your/type'. Default is */*.

=item --action <spec>

Perform an action on the response. It can be the display of a value (from header, regex on body, json path).

=item --action-nullable-values

If set an action can return null values, else it fails if the result cannot find a value.

=item --action-res-delimiter

Set the delimiter for action results. Default is ','.

=item --basic, --user <user:password>

Use basic http authentication. Sepcified in the form user:password it is passed to the server in Base64 encoding.

=item --content <content-type>

Specify the request content-type. This is simply a shortcut for -H 'Content-Type: your/type'. It can overrides automatic content-type for POSTed data.

=item -b, --cookie <string or file>

Activate cookie support and read cookie from a string like 'NAME=Value' or a file. The file is either in 'HTTP headers format' or in 'Netscape cookie format'. See the L<Unofficial cookie FAQ|http://www.cookiecentral.com/faq/#3.5>. The file is never modified. If you want to save cookies, see --cookie-jar.

=item -c, --cookie-jar <file or dash>

Save cookies into a 'Netscape cookie format' file, or if the given file is '-', output the cookies into STDOUT.

=item -d, --data, --data-ascii <data>

Define some data that will be POSTed to the server. If data starts with '@', the rest of the string will be taken as a file name whose content will be send as request body. If using '-' as file name, the data will be read from standard input (so you can pipe it from another command). Note that CR+LF characters will be discarded from the output. See --data-binary if you need to send unaltered data.

=item --data-binary <data>

Similar to --data, but do not discard CR+LF characters. When reading from a file, perform binary read.

=item --data-raw <data>

Similar to --data, but do not interpret an initial '@' character.

=item --data-urlencode <data>

Similar to --data-raw, but the data will be url-encoded.

=item -f, --fail

Do not continue on 4xx and 5xx results and return an error. Body response is not returned.

=item --fail-with-body

Do not continue on 4xx and 5xx results and return an error. Body response is returned.

=item -I, --head

Show the document headers only. The shorthand notation for -X HEAD.

=item -H, --header <header_spec>

Send an additional header, or change / discard a default one. Usual syntax is -H 'header_name: value', e.g. -H 'X-my-header: some text'. To send several custom headers, repeat the -H parameter. If you pass only 'header_name:' (without value) the header will not be transmitted. If you need to send an empty header, use 'header_name;' (use semicolon).

=item -h, --help

Display a short help.

=item --http09 | --http0.9, --http10 | --http1.0 | -0, --http11 | --http1.1

Specify the version of HTTP we want to use. In HTTP/0.9 the only method is GET <url> (without version) and the answer does not return headers, only the body of returned resource. In HTTP/1.0 we can use Host:, Connection: and additional headers. IN HTTP/1.1 the Host: is mandatory and if you do not specify Connection: it is kept open by default. We send automatically a Connection: close by default.
Default is HTTP/1.1

Note that pcurl supports curl parameters --http0.9, --http1.0 and http1.1 if only you have Getopt::Long >= 2.39

=item -i, --include, --include-response

Include the response headers in the output.

=item --include-request

Include the request headers in the output.

=item -k, --insecure

Accept insecure https connections (mostly curl option compatibility)

=item --json <data>

Shortcut to POST the specified json data and automatically set the Content-Type: and Accept: headers. This is equivalent to

    --request POST  (implicit with --data)
    --data <arg>
    --header "Content-Type: application/json"  or --content application/json
    --header "Accept: application/json"        or --accept application/json

=item --json-pp

When using a json action (see --action), pretty-print the json.

=item --json-pp-indent

When using --json-pp-indent, number of space characters to use for each level of indentation (default = 2).

=item --json-stringify-null

When parsing json, replace null values by the string 'null'

=item --junk-session-cookies

When using -b, --cookie and loading cookies from file, purge the session cookies (those with no expire date).

=item -L, --location, --follow

Follow HTTP redirects.

=item --man

Display the full manual.

=item --max-wait <seconds>

Specify the timeout in seconds when waiting for a response. Default is 10s.

=item --max-redirs <number>

Specify the maximum number of redirects to follow. Default is 50.

=item --noproxy <domain_list>

Define a coma-separated list of domains that ignore the proxy. 

=item -o, --output <file>

Write to file instead of stdout.

=item --parse-only <url>

Debug usage: parse an url and show its attributes.

=item --port <port>

Specify explicitly the port. If not used, we use the port from the url (if specified), or we will try well-known port 80 for HTTP and 443 for HTTPS, depending on the url scheme.

=item --progression

Shows the name of retrieved files and their size.

=item -x, --proxy <proxy_url>

Set the url of the HTTP/1.1 proxy to use.

=item --proxy10 <proxy_url>

Set the url of the HTTP/1.0 proxy to use.

=item -U, --proxy-user <user:passwd>

Set the proxy authentication. Only Basic Auth is supported.

=item -e, --referer <referer url>

Specify a string for the referer. If followed by ";auto", when following redirections, reuse the previous url as referer. ";auto" can also be used alone with redirections.

=item -J, --remote-header-name

With -O --remote-name, use the name provided by Content-disposition: filename instead of URL.

=item -O, --remote-name

Write output to a file named as the remote file (that name is extracted from the URL).

=item -R, --remote-time

Set the remote file's time on the local output, if provided by Last-Modified response header.

=item -X, --request <method>

Specify the method for the request. Common methods are GET, HEAD, POST, PUT, TRACE, OPTIONS and DELETE, but you can specify a custom method. If not specified, we send a GET. 

=item -s, --silent

Silent mode

=item -3, --sslv3

Force the usage of SSL v3 for openSSL tunneling

=item --stompmsg <message>

Content of the message for the STOMP message broker. Use with a stomp://server:port/queuename url. 

=item --tcp-nodelay, --notcp-nodelay

Disable the Nagle's algorithm for TCP communication (do not wait for a previous ACK before sending data if small amount of data)

=item -1, --tlsv1_0, --tlsv1

Force the usage of TLS v1.0 for openSSL tunneling

=item --tlsv1_1

Force the usage of TLS v1.1 for openSSL tunneling

=item --tlsv1_2

Force the usage of TLS v1.2 for openSSL tunneling

=item --tlsv1_3

Force the usage of TLS v1.3 for openSSL tunneling

=item --url <url>

Specify explicitly the url. If that parameter is not used, we try to get the url as the remaining text after the parameters.

=item -A, --user-agent <ua string>

Specify a string for User-Agent. If not specified the default User-Agent is 'pcurl v$VERSION'.

=item -v, --verbose

Show both headers during the communication.

=item -V, --version

Show version number and quit.

=item --xml-pp

When using an xml action (see --action), pretty-print the xml. Default is not indented.

=item --xml-pp-indent <number_of_spaces>

Number of space characters for each indentation level. Default is 2

=item --xml-root-element <name>

Use the given name for the root element of XML.

=back

=head2 Web crawling features

In web-crawling mode, a first resource is retrieved then in a recursive way, all related resources (linked html, pictures, css) are also retrieved. 

By default a number of 5 successive jumps from initial url are processed. All the files are stored under a common directory named after the host.

=item --accept-list <coma-separated list>

Specify a list of accepted file extensions

=item --accept-regex <pattern>

Specify a pattern that will be validated to accept urls

=item --cut-dirs <number of levels>

Specify a number of path levels to remove from all links.

=item --debug-urls

Show urls discovered in each html/css file when running in recursive mode.

=item --directory-prefix <common path>

Specify a path to prepend for all retrieved resources.

=item --default-page <file name>

Specify the name of the index file when directory browsing is allowed by the server. Default is 'index.html'

=item -l, --level <number>

Specify the maximum number of jump to explore from initial url. Default is 5. 0 is equivalent to 'get all site'.

=item --no-host-directories

Allow to disable the creation of a common ancestor named after the host name for all retrieved resources.

=item --no-parent, --np

Prevent the crawling to go back to the parent of the given url.

=item --page-requisites

Will help to get linked resources (pictures, css) even if stored in a higher directory than resource.

=item -r, --recursive

Use the web-crawling mode: get as many linked resources as possible.

=item --recursive-flat

Disable the creation of directories, all related resources will be stored in the same directory.

=item --relative

Tell that you want to take into account only relative links.

=item --reject-list <coma-separated list>

Specify a list of ignored file extensions

=item --reject-regex <pattern>

Specify a pattern that will be validated to ignore urls

=item --span-hosts

Allow to process resources from external web sites. Beware if you set also --level 0: you will download the whole Internet! ;o)

=item --summary

Ask for a final list of retrieved resources, if you do not want to see other details.

=head2 Examples

=item parse an URI to show its components

    pcurl https://mylogin:mypwd@subdomain.domain.com:1234/some/path/to/resource --parse-only

=item list linked resources on a page

    pcurl https://domain.org/some/path/to/page.html --action listlinks:

=item Get a page and all its direct linked resources (without going up to parent)

    pcurl -ORL --recursive --no-parent --page-requisites --no-host-directories --level 1 --recursive-flat --cut-dirs 2  --progression https://path

=cut

# Local Variables: 
# coding: utf-8-unix
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 sts=4 et :
