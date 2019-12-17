#!/usr/bin/perl
use warnings;
use strict;
use feature 'say';
use utf8;
use Data::Dumper;
use Getopt::Long qw(:config no_ignore_case bundling);
use IO::Select;
use IO::Socket::INET;
use IPC::Open3;
use MIME::Base64 'encode_base64';
use Pod::Usage;
use Socket;
use Time::Local;
# use Carp::Always;

our $VERSION = 0.6;
$|++; # auto flush messages
$Data::Dumper::Sortkeys = 1;

# -------- Signal handlers -------------------------
BEGIN{                          # automagic breakpoint for warnings when script is run by perl -d
    $SIG{__WARN__} = sub {
        my $msg = shift;
        chomp $msg;
        say "Warning: '$msg'";
        no warnings 'once';     # avoid « Warning: 'Name "DB::single" used only once: possible typo »
        $DB::single = 1;        # we stop execution if a warning occurs during run
    };
}
$SIG{INT}  = sub { say "SIGINT / CTRL-C received (Interrupt from keyboard). Leaving."; exit };
$SIG{QUIT} = sub { say "SIGQUIT / CTRL-\\ received (Quit from keyboard). Leaving."; exit };
$SIG{ABRT} = sub { say "SIGABRT received (Probable abnormal process termination requested by a library). Leaving."; exit };
$SIG{TERM} = sub { say "SIGTERM received - External termination request. Leaving."; exit };
sub suspend_trap {
    say "SIGTSTP / CTRL-Z received. Suspending...";
    $SIG{TSTP} = 'DEFAULT';
    kill 'TSTP', -(getpgrp $$);
}
$SIG{TSTP} = \&suspend_trap;
$SIG{CONT} = sub { $SIG{TSTP} = \&suspend_trap; say "SIGCONT received - continue after suspension." };
# --------------------------------------------------

my $max_redirs = 50;            # default value for maximum redirects to follow
my $def_max_wait = 10;          # default value for response timeout
my %defports = ( http  => 80,
                 https => 443 );

my ($url, $cli_url, $auth_basic, $uagent, $http_vers, $tunnel_pid, $auto_ref, $use_cookies, $cookies);
my ($arg_hlp, $arg_man, $arg_debug, $arg_verbose,
    $arg_basic, $arg_url, $arg_port, $arg_agent,
    $arg_cookie, $arg_cookiejar, $arg_junk_session_cookies,
    $arg_httpv09, $arg_httpv10, $arg_httpv11,
    $arg_method, $arg_info, $arg_follow, $arg_maxredirs, $arg_maxwait, $arg_parse_only,
    $arg_proxy, $arg_proxy10, $arg_proxyuser, $arg_noproxy, $arg_referer,
    $arg_postdata, $arg_postraw, $arg_postbinary,
    $arg_stompdest, $arg_stompmsg, $arg_outfile) = ();
my @arg_custom_headers;
my @arg_posturlencode;

GetOptions(
    'agent|a=s'            => \$arg_agent,
    'basic=s'              => \$arg_basic,
    'cookie|b=s'           => \$arg_cookie,
    'cookie-jar|c=s'       => \$arg_cookiejar,
    'data-binary=s'        => \$arg_postbinary,
    'data-raw=s'           => \$arg_postraw,
    'data-urlencode=s'     => \@arg_posturlencode,
    'data|data-ascii|d=s'  => \$arg_postdata,
    'debug'                => \$arg_debug,
    'header|H=s'           => \@arg_custom_headers,
    'head|I'               => \$arg_info,
    'help|h|?'             => \$arg_hlp,
    'http09'               => \$arg_httpv09,
    'http10'               => \$arg_httpv10,
    'http11'               => \$arg_httpv11,
    'junk-session-cookies' => \$arg_junk_session_cookies,
    'location|L'           => \$arg_follow,
    'man'                  => \$arg_man,
    'max-wait=i'           => \$arg_maxwait,
    'max-redirs=i'         => \$arg_maxredirs,
    'noproxy=s'            => \$arg_noproxy,
    'output|o=s'           => \$arg_outfile,
    'parse-only'           => \$arg_parse_only,
    'port|p=i'             => \$arg_port,
    'proxy-user|U=s'       => \$arg_proxyuser,
    'proxy10=s'            => \$arg_proxy10,
    'proxy|x=s'            => \$arg_proxy,
    'referer|e=s'          => \$arg_referer,
    'request|X=s'          => \$arg_method,
    # 'stompdest=s'        => \$arg_stompdest,
    'stompmsg=s'           => \$arg_stompmsg,
    'url=s'                => \$arg_url,
    'verbose|v'            => \$arg_verbose,
    ) or pod2usage(2);
pod2usage(0) if $arg_hlp;
pod2usage(-exitval => 0, -verbose => 2) if $arg_man;

$cli_url = $arg_url || $ARGV[0];
unless ($cli_url){
    say STDERR "No url provided...";
    pod2usage(1);
}
unless ($url = parse_url($cli_url)){
    say STDERR "It's strange to me that `$url` does not look as an url...";
    exit 1;
}
if ($arg_parse_only){
    if ($url){
        say(STDOUT "$_ = $url->{$_}") for(sort(keys %$url));
        exit 0;
    } else {
        exit 1;
    }
}

$uagent = $arg_agent || "pcurl v$VERSION";

if ($arg_httpv09){
    $http_vers = '0.9';
} elsif ($arg_httpv10){
    $http_vers = '1.0';
} elsif ($arg_httpv11){
    $http_vers = '1.1';
} elsif ($url->{scheme} =~ /^http/){
    $http_vers = '1.0';
}

if ($url->{scheme} =~ /^http/ && $arg_method){
    if ($arg_method =~ /^(GET|HEAD|POST|PUT|TRACE|OPTIONS|DELETE)$/i){
        $arg_method = uc $arg_method;
        die "HTTP/0.9 only supports GET method.\n" if $arg_method ne 'GET' and HTTP09();
    } else {
        # Nothing, one can have a custom HTTP method
    }
}

if ($arg_referer && $arg_referer =~ /([^;]*)?;auto/){
    $auto_ref = 1;
    $arg_referer = $1;
}

if ($arg_cookie || $arg_cookiejar){
    $use_cookies = 1;
    if ($arg_cookie){
        if (-f $arg_cookie){
            $cookies = load_cookie_jar($arg_cookie);
            say STDERR "Cookies from jar:", Dumper $cookies if $arg_debug;
            if ($arg_junk_session_cookies){
                # keep cookies with expiration (if not it's a session cookie)
                $cookies = [ grep { $_->{expires} } @$cookies ];
            }
        } else {
            $cookies = load_commandline_cookies($arg_cookie);
            say STDERR "Cookies from command-line:", Dumper $cookies if $arg_debug;
        }
    }
    # keep non-expired cookies
    my $now = time;
    $cookies = [ grep { !$_->{expires} || ($_->{expires} >= $now) } @$cookies ];
    say STDERR "Cookies from jar after purge and expiration:", Dumper $cookies if $arg_debug;
}

my $STDOLD;
if ($arg_outfile){
    open $STDOLD, '>&', STDOUT;
    open STDOUT, '>', $arg_outfile or die "Cannot open $arg_outfile for output.";
    # later, to restore STDOUT:
    # open (STDOUT, '>&', $STDOLD);
}

if ($url->{scheme} =~ /^http/){
    my $method;
    if ($arg_postdata || @arg_posturlencode || $arg_postbinary || $arg_postraw){
        if ($arg_method && ($arg_method ne 'POST')){
            say STDERR 'For posting data, method must be POST.';
            exit 1;
        } else {
            $method = 'POST';
        }
    } else {
        $method = $arg_info ? 'HEAD' : $arg_method || 'GET';
    }
    #$url->{path} = '*' if $method eq 'OPTIONS';    
    process_http($method, $url);
} elsif ($url->{scheme} =~ /^stomp/){
    unless ($url->{path} && $arg_stompmsg){
        say STDERR "Message sending with --stompmsg <message> is supported for now.";
        exit 1;
    }
    process_stomp($url);
}

if ($arg_cookiejar){
    save_cookie_jar($arg_cookiejar, $cookies);
}

if ($arg_outfile){
    close STDOUT;
    open (STDOUT, '>&', $STDOLD);
}

# ------- End of main prog ---------------------------------------------------------------

sub process_http {
    my $method = shift;
    my $url_final = shift;

    my ($IN, $OUT, $ERR, $host, $port, $resp);

    $max_redirs = $arg_maxredirs if defined $arg_maxredirs;
    my $redirs = $max_redirs;
    do {
        say STDERR "* Processing url $url_final->{url}" if $arg_verbose || $arg_debug;
        my $url_proxy = get_proxy_settings($url_final);
        my $pheaders = [];
        if ($url_proxy){
            $pheaders = build_http_proxy_headers($url_proxy, $url_final);
            $url_final->{proxified} = 1 if $url_final->{scheme} eq 'http';
            $url_final->{tunneled} = 1 if $url_final->{scheme} eq 'https';
        }

        if ($url_proxy){
            ($OUT, $IN, $ERR) = connect_direct_socket($url_proxy->{host},
                                                      $url_proxy->{port}) if $url_final->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final, $url_proxy) if $url_final->{scheme} eq 'https';
        } else {
            ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host},
                                                      $url_final->{port}) if $url_final->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final) if $url_final->{scheme} eq 'https';
        }

        my $body = prepare_http_body();
        my $headers = build_http_request_headers($method, $url_final, $url_proxy, $body);
        if ($url_final->{proxified} && $pheaders){
            map { push @$headers, $_ } @$pheaders;
        }

        say STDERR "* Sending request to server" if $arg_verbose || $arg_debug;

        # Write to the server
        send_http_request($IN, $OUT, $ERR, $headers, $body);

        # Receive the response
        $resp = process_http_response($IN, $ERR, $url_final, $url_proxy);
        say STDERR Dumper $resp->{headers} if $arg_debug;
        say STDERR "* received $resp->{byte_len} bytes" if $arg_verbose || $arg_debug;
        if ($resp->{byte_len}){
            my $code = $resp->{status}{code};
            if ($arg_follow && (300 <= $code) && ($code <= 399)){
                # if the result is a redirect, follow it
                unless($redirs){
                    say STDERR sprintf("* Maximum (%d) redirects followed", $max_redirs);
                    goto BREAK;
                }
                $arg_referer = $url_final->{url} if $auto_ref;      # use previous url as next referer
                my ($old_scheme, $old_host, $old_port) = ($url_final->{scheme}, $url_final->{host}, $url_final->{port});
                $url_final = parse_url($resp->{headers}{location}); # get redirected url
                # compare new url with previous and reconnected if needed
                if (($url_final->{scheme} ne $old_scheme) || ($url_final->{host} ne $old_host) || ($url_final->{port} != $old_port)){
                    say STDERR "* Closing connection because of scheme/server redirect" if $arg_verbose || $arg_debug;
                    close $IN;
                    close $OUT;
                    close $ERR if $ERR;
                }
                say STDERR sprintf("* Redirecting #%d to %s", $max_redirs - $redirs,  $url_final->{url}) if $arg_verbose || $arg_debug;
                $redirs--;
            } else {
                # result other than redirect

                goto BREAK;         # weird, 'last' is throwing a warning "Exiting subroutine via last"
            }
        }
    } while ($resp->{byte_len} && $url_final && $redirs >= 0);
  BREAK:
    
    close $IN;
    close $OUT;
    close $ERR if $ERR;
}

# transmission of headers + body to the server
sub send_http_request {
    my ($IN, $OUT, $ERR, $headers, $body) = @_;
    
    push @$headers, '';         # empty line to terminate request
    
    if ($arg_verbose){
        print STDERR "> $_\n" for @$headers;
    }
    my $headers_txt = join "", map { "$_\r\n" } @$headers;
    print $OUT $headers_txt;    # send headers to server

    if (defined $body){
        my $sent = 0;
        if (ref $body eq 'HASH'){
            if (exists $body->{data}){
                print $OUT $body->{data};
                $sent = $body->{size};
            } 
        } else {
            print $OUT $body if $body;
            $sent = length $body;
        }
        say STDERR "* upload completely sent off: $sent bytes" if $arg_verbose || $arg_debug;
    }
    
    $OUT->flush;
    say STDERR "* HTTP request sent" if $arg_debug;
}

# check if we need to connect to a proxy
# returns the address of the proxy, else undef
sub get_proxy_settings {
    my $url_final = shift;
    my $proxy;

    # if we match an explicit no_proxy argument or no_proxy environment, get out
    my $no_p = $arg_noproxy || $ENV{no_proxy};
    if ($no_p){
        $no_p =~ s/,/|/g;
        $no_p =~ s/\./\\./g;
        $no_p =~ s/\*/.*/g;
        if ($url_final->{host} =~ /$no_p/){
            return undef;
        }
    }
    
    my $proxy_set;
    if ($arg_proxy){
        $proxy_set = $arg_proxy;
    } elsif ($arg_proxy10){
        $proxy_set = $arg_proxy10;
    } elsif ($url_final->{scheme} eq 'http'){
        $proxy_set = $ENV{http_proxy};
    } elsif ($url_final->{scheme} eq 'https'){
        $proxy_set = $ENV{https_proxy};
    }
    return undef unless $proxy_set;
    
    $proxy = parse_url($proxy_set);
    unless ($proxy){
        say STDERR "It's strange to me that `$url` does not look as an url for proxy...";
        exit 1;
    }
    say STDERR "* Using proxy $proxy->{url}" if $arg_verbose || $arg_debug;
    return $proxy;
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
            my $path = $u->{path} . ($u->{params} ? "?$u->{params}" : '');
            push @$headers, "${method} ${path} HTTP/${http_vers}"; # else request only the path
        }

        # FIXME: the headers must not be in a hash as we can send repeated headers
        # when they can be also a coma-separated list https://tools.ietf.org/html/rfc7230#section-3.2.2

        # process the custom headers
        my %custom;
        for my $ch (@arg_custom_headers){
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
        if (($u->{scheme} eq 'http') && ($u->{port} != $defports{$u->{scheme}})){
            $hostport = ":$u->{port}";
        }
        push @$headers, "Host: $u->{host}${hostport}" unless exists $custom{host};
        add_http_header($headers, \%custom, 'User-Agent', ${uagent});
        add_http_header($headers, \%custom, 'Accept', '*/*');
        add_http_header($headers, \%custom, 'Connection', 'close');
        my $auth = $arg_basic || $u->{auth};
        add_http_header($headers, \%custom, 'Authorization', 'Basic ' . encode_base64($auth, '')) if $auth;
        add_http_header($headers, \%custom, 'Referer', $arg_referer) if defined $arg_referer;

        if (defined $body){
            if (ref $body eq 'HASH'){
                # if ($body->{kind} eq 'stdin'){
                    add_http_header($headers, \%custom, 'Content-Length', $body->{size});
                    add_http_header($headers, \%custom, 'Content-type', $body->{ctype});
                # }
            } else {
                add_http_header($headers, \%custom, 'Content-Length', length $body);
                add_http_header($headers, \%custom, 'Content-type', 'application/x-www-form-urlencoded');
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

sub prepare_http_body{
    my $post = $arg_postdata || $arg_postbinary || $arg_postraw;
    if ($post){
        if ($arg_postraw){
            return $arg_postraw; # we do not interpret the @ in raw mode
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
                if ($arg_postdata){
                    while (my $l = <$fd>){
                        $l =~ s/[\r\n]+//g;
                        $data .= $l;
                    }
                } elsif ($arg_postbinary){
                    my $buf_size = 1024 * 1024;
                    while(my $block = $fd->sysread(my $buf, $buf_size)){
                        # syswrite $OUT, $buf, $block;
                        # $sent += $block;
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
            return $arg_postdata; # it's a plain text 
        }        
    } elsif (@arg_posturlencode){
        my @encoded;
        for my $data (@arg_posturlencode){
            $data =~ s/^(\w+)=(.*)/"$1=" . urlencode($2)/e;
            push @encoded, $data;
        }
        return join('&', @encoded);
    } else {
        return undef;
    }
}

sub build_http_proxy_headers {
    my $p = shift;
    my $u = shift;
    my $headers = [];

    if ($u->{scheme} eq 'https'){
        if ($arg_proxy10 || HTTP10()){
            push @$headers, "CONNECT $u->{host}:$u->{port} HTTP/1.0";
        } elsif (HTTP11()){
            push @$headers, "CONNECT $u->{host}:$u->{port} HTTP/1.1";
        }
    }
    my $auth = $arg_proxyuser || $p->{auth};
    push @$headers, 'Proxy-Authorization: Basic ' . encode_base64($auth) if $auth;
    if (HTTP11()){
        # push @$headers, 'Proxy-Connection: close';
    }
    return $headers;
}

# Given the STDOUT/STDERR of the server or tunnel client
# process the response
sub process_http_response {
    my ($IN, $ERR, $url_final, $url_proxy) = @_;
    my $headers_done = 0;
    my $status_done = 0;
    my $content_length = 0;
    my $received = 0;
    my %headers;
    my %resp;
    
    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    say STDERR "* Processing response" if $arg_debug;
    
    while (my @ready = $selector->can_read($arg_maxwait || $def_max_wait)) {
        foreach my $fh (@ready) {
            if ($ERR && (fileno($fh) == fileno($ERR))) {
                my $line = <$fh>;
                $line =~ s/[\r\n]+$//;
                say STDERR "* proxy/tunnel STDERR: $line" if $arg_debug;
                if ($url_final->{tunneled} && ($line =~ /^s_client: HTTP CONNECT failed: (\d+) (.*)/)){
                    my $err_txt = sprintf("Received '%d %s' from tunnel after CONNECT", $1, $2);
                    say STDERR $err_txt;
                    exit 1;
                }
            } elsif (fileno($fh) == fileno($IN)) {
                say STDERR "* processing STDIN" if $arg_debug;
                if (! $headers_done && !HTTP09()){ # there is no header in HTTP/0.9
                    # local $/ = "\r\n";
                  HEAD: while(defined (my $line = <$IN>)){
                      $received += length($line);
                      $line =~ s/[\r\n]+$//;
                      say STDERR '< ', $line if $arg_verbose || $arg_debug;
                      say STDOUT $line if $arg_info;
                      if ($line =~ /^$/){
                          $headers_done++;
                          last HEAD;
                      }
                      if (!$status_done && $line =~ m{^([^\s]+) (\d+) (.*)$}){
                          $resp{status}{proto} = $1;
                          $resp{status}{code} = $2;
                          $resp{status}{message} = $3;
                          $status_done++;
                      }
                      if ($line =~ /^([A-Za-z0-9-]+):\s*(.*)$/){
                          my $hname = lc $1;
                          my $hvalue = $2;
                          if ($hname eq 'set-cookie'){
                              my @head_cookies = parse_cookie_header($hvalue, $url_final);
                              HCOOKIE: for my $hcook (@head_cookies){
                                  # replace identical cookies
                                  for (my $c = 0; $c <= $#{$cookies}; $c++){
                                      if ($cookies->[$c]->{domain} eq $hcook->{domain} && $cookies->[$c]->{path} eq $hcook->{path}){
                                          splice @$cookies, $c, 1, $hcook;
                                          next HCOOKIE;
                                      }
                                  }
                                  # if we arrive here, the cookie was not found, add it
                                  push @$cookies, $hcook;
                              }
                          }
                          
                          # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
                          if (exists $headers{$hname}){
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
                }
                # we show body contents only when not following redirects
                my $is_redirected = $resp{status} && $resp{status}{code} && $resp{status}{code} =~ /^3/;
                say STDERR "* Ignoring the response-body" if ($is_redirected && $arg_follow) && (! $fh->eof ) && ($arg_verbose || $arg_debug);
                unless ($fh->eof){
                    $content_length = $headers{'content-length'};
                    if ($content_length){
                        say STDERR "* need to read $content_length bytes in response..." if $arg_debug;
                    } else {
                        say STDERR "* Unknown size of response to read..." if $arg_debug;
                    }
                    my $buf_size = 2 * 1024 * 1024;
                    my $block = $fh->read(my $buf, $buf_size);
                    if ($block){
                        say STDERR "* Read $block bytes" if $arg_debug;
                        $received += $block;
                        print STDOUT $buf unless ($is_redirected && $arg_follow);
                    }
                }
                # there may have additional info... (body > Content-Length)
            };
            
            if (eof($fh)){
               say STDERR "* Nothing left in the filehandle $fh" if $arg_debug;
               $selector->remove($fh);
            }
        }
    }
    $resp{headers} = \%headers;
    $resp{byte_len} = $received; # keep the size of read data
    say STDERR "Parsed cookies: ", Dumper $cookies if $arg_debug;
    say STDERR "* end of response" if $arg_debug;
    return \%resp;
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
        my $dom_rx = $cookie->{domain} =~ s/\./\\./gr;
        $dom_rx = "\\b${dom_rx}\$";
        my $path_rx = '^' . $cookie->{path} . '\b';
        if (($udomain =~ /$dom_rx/) || ($cookie->{domain} eq '*') && ($upath =~ /$path_rx/)){
            push @matching, $cookie;
        }
    }
    my $txt = join '; ', map { "$_->{name}=$_->{value}" } @matching;
    return $txt ? "Cookie: ${txt}" : undef;
}

# Return the list of cookie definitions contained in a Set-Cookie header
sub parse_cookie_header {
    my ($head_val, $url) = @_;
    my %months = ( Jan=>0, Feb=>1, Mar=>2, Apr=>3, May=>4, Jun=>5, Jul=>6, Aug=>7, Sep=>8, Oct=>9, Nov=>10, Dec=>11 );
    my $cookies;
    my $rx = qr{
    # this regex is a recusrive descent parser - see https://www.perlmonks.org/?node_id=995856
    # and chapter 1 "Recursive regular expressions" of Mastering Perl (Brian d Foy)
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
          (?{ [ $^R, {} ] }) # initialize an href for the content of the cookie
          # at least we have a key=value
          (?&KV)             (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, name=>$^R->[1], value=>$^R->[2] } ] })
          ( ; \s    # but we can have additional attributes
            ( (?&KV)         (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, lc $^R->[1] => $^R->[2] } ] })
             |(?&SINGLEATTR) (?{ [ $^R->[0][0], { %{ $^R->[0][1] }, lc $^R->[1] => 1 } ] })
            )
          )*
         )

         (?<KV> # a pair key=value
          (?&KEY) = (?&VALUE) (?{ [$^R->[0][0], $^R->[0][1], $^R->[1]] })
         )

         (?<KEY> # cookie attributes that have a value
          ( [^;,= ]+ | expires | domain | path | max-age | samesite ) (?{ [ $^R, $^N ] })
         )

         (?<SINGLEATTR> # cookie attribute that do not accept value
          ( HttpOnly | Secure )  (?{ [ $^R, $^N ] })
         )

         (?<VALUE> # get the value for a key with special handling of dates
          (?: (?&EXPIRES) | (?&STRING) )  
         )

         (?<EXPIRES> # legal format = Wdy, DD-Mon-YYYY HH:MM:SS GMT
          \w\w\w,\s(?<DAY>\d\d)-(?<MONTH>\w\w\w)-(?<YEAR>(?:\d\d)?\d\d)
          \s(?<HOUR>\d\d):(?<MINUTE>\d\d):(?<SECOND>\d\d)
          \s GMT (?{ [ $^R, timelocal( $+{SECOND}, $+{MINUTE}, $+{HOUR}, $+{DAY}, $months{$+{MONTH}}, ($+{YEAR} < 100 ? $+{YEAR} + 2000 : $+{YEAR}) ) ] })
         )

         (?<STRING>
          ([^;,]+) (?{ [$^R, $^N] })
         )

        ) # end of DEFINE set
    }xims;
    {
        local $_ = shift;
        local $^R;
        eval { m{$rx}; } and $cookies = $_;
    }
    if ($cookies){
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
    my $out;
    if ($file eq '-'){
        $out = *STDOUT;
    } else {
        open $out, '>', $file or do { say STDERR "* WARNING: failed to save cookies in $file"; return}; # emulate curl
    }
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

## An non-blocking filehandle read that returns an array of lines read
## Returns:  ($eof,@lines)
#my %nonblockGetLines_last;
#sub nonblockGetLines {
#    my ($fh,$timeout) = @_;
#
#    $timeout = 0 unless defined $timeout;
#    my $rfd = '';
#    $nonblockGetLines_last{$fh} = '' unless defined $nonblockGetLines_last{$fh};
#
#    vec($rfd,fileno($fh),1) = 1;
#    return unless select($rfd, undef, undef, $timeout)>=0;
#    # I'm not sure the following is necessary?
#    return unless vec($rfd,fileno($fh),1);
#    my $buf = '';
#    my $n = sysread($fh,$buf,1024*1024);
#    # If we're done, make sure to send the last unfinished line
#    return (1,$nonblockGetLines_last{$fh}) unless $n;
#    # Prepend the last unfinished line
#    $buf = $nonblockGetLines_last{$fh}.$buf;
#    # And save any newly unfinished lines
#    $nonblockGetLines_last{$fh} = (substr($buf,-1) !~ /[\r\n]/ && $buf =~ s/([^\r\n]*)$//) ? $1 : '';
#    return $buf ? (0,split(/\n/,$buf)) : (0);
#}

sub process_stomp {
    my $url_final = shift;
    my ($IN, $OUT, $ERR, $host, $port, $resp);
    ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host}, $url_final->{port});

    my ($user, $passwd) = ('guest', 'guest');
    my $connect = [ 'CONNECT', "login:${user}", "passcode:${passwd}"];
    send_stomp_request($OUT, $IN, $connect);
    $resp = process_stomp_response($IN);
    if ($resp->{command} eq 'CONNECTED'){
        my $body = $arg_stompmsg;
        my $len = length($body);
        my $type = 'text/plain';
        send_stomp_request($OUT, $IN, [ 'SEND', "destination:$url_final->{path}", "content-type:${type}", "content-length:${len}" ], $body );
        # this is blocking...
        $resp = process_stomp_response($IN);
    }
    close $IN;
    close $OUT;
    close $ERR if $ERR;
}

sub send_stomp_request {
    my ($OUT, $IN, $headers, $body) = @_;
    if ($arg_verbose){
        say STDOUT "> $_" for @$headers;
    }
    my $request = join( "\n", @$headers ) . "\n\n" . ($body || '') . "\000";
    print $OUT $request;
}

sub process_stomp_response {
    my $IN = shift;
    my $selector = IO::Select->new();
    $selector->add($IN);
    my %frame;
    
    while (my @ready = $selector->can_read($arg_maxwait || $def_max_wait)) {
        foreach my $fh (@ready) {
            if (fileno($fh) == fileno($IN)) {
                my $buf_size = 1024 * 1024;
                my $block = $fh->sysread(my $buf, $buf_size);
                if($block){
                    if ($buf =~ s/^\n*([^\n].*?)\n\n//s){
                        my $headers = $1;
                        for my $line (split /\n/,  $headers){
                            say STDOUT "< $line" if $arg_verbose || $arg_debug;
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
                        } elsif ($buf =~ s/^(.*?)\000\n*//s ){
                            $frame{body} = $1;
                        }
                    }
                }
                # $selector->remove($fh) if eof($fh);
            }
        }
    }
    return \%frame;
}

# Extract de differents parts from an URL
# return a hashref or undef if it fails
sub parse_url {
    my $given = shift;
    unless( $given =~ qr{
        (?<SCHEME> [\w]+ ) (?: :// )
        (?: (?<AUTH> (?&UNRESERVED)+ ( : [^@]+ )? ) @ )?
        (?<HOST> [^-] (?&UNRESERVED)+ )
        (?: \: (?<PORT> \d+ ))?
        (?<PATH> (?&PCHAR)+ )?
        (?: \? (?<PARAMS> (?&PCHAR)* ))?
      
        (?(DEFINE) #from here, define some sub-parts
          (?<PCHAR> (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL) | : | @ )
          (?<PCTENCODED> % (?&HEXDIG) (?&HEXDIG) )
          (?<HEXDIG> [0-9A-Za-z] )
          (?<UNRESERVED> [A-Za-z0-9._~-] )
          (?<SUBDEL> [/!\$'&()\*\+,\.=] )
        )
            }x ){
        return undef;
    }
    my $url = {};
    $url->{url} = $given;
    $url->{scheme} = $+{SCHEME};
    $url->{auth} = $+{AUTH} || '';
    $url->{host} = $+{HOST} || '';
    $url->{port} = $arg_port || $+{PORT};
    unless ($url->{port}){
        if ($url->{scheme} eq 'http'){
            $url->{port} = 80;
        } elsif ($url->{scheme} eq 'https'){
            $url->{port} = 443;
        } elsif ($url->{scheme} eq 'stomp'){
            $url->{port} = 61613;
        } else {
            say STDERR "Default port unknown for scheme '$url->{scheme}://'...";
            return undef;
        }
    }
    $url->{path} = $+{PATH} || '/';
    $url->{params} = $+{PARAMS} || '';
    if ($arg_debug){
        say STDERR "* Parsed URL '$given'";
        say(STDERR "*  $_ = $url->{$_}") for(sort(keys %$url));
    }
    return $url;
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

sub connect_direct_socket {
    my ($host, $port) = @_;
    my $sock = new IO::Socket::INET(PeerAddr => $host,
                                    PeerPort => $port,
                                    Proto    => 'tcp') or die "Can't connect to $host:$port\n";
    $sock->autoflush(1);
    say STDERR "* connected to $host:$port" if $arg_verbose || $arg_debug;
    
    return $sock, $sock, undef;
}

sub connect_ssl_tunnel {
    my ($dest, $proxy) = @_;
    my ($host, $port, $phost, $pport);
    $host = $dest->{host};
    $port = $dest->{port};
    if ($proxy){
        $phost = $proxy->{host};
        $pport = $proxy->{port};
    }
    my $cmd = "openssl s_client -connect ${host}:${port} -servername ${host} -quiet";# -quiet -verify_quiet -partial_chain';
    $cmd .= " -proxy ${phost}:${pport}" if $phost;
    $tunnel_pid = open3(*CMD_IN, *CMD_OUT, *CMD_ERR, $cmd);
    say STDERR "* connected via OpenSSL to $host:$port" if $arg_verbose || $arg_debug;
    say STDERR "* command = $cmd" if $arg_debug;

    $SIG{CHLD} = sub {
        print STDERR "* REAPER: status $? on ${tunnel_pid}\n" if waitpid($tunnel_pid, 0) > 0 && $arg_debug;
    };
    return *CMD_IN, *CMD_OUT, *CMD_ERR;
}

# poor man's hex dumper :)
sub hexdump {
    my $data = shift;
    my $data_len = shift || 16;
    my $hex_len = $data_len * 3;
    my $addr = 0;
    my @out;
    for my $s (unpack("(a${data_len})*", $data)){
        last unless $s;
        my $h = join' ', unpack('(H2)*', $s);
        $s =~ s/[\x00-\x1f]/./g;
        push @out, sprintf("%06x  %-${hex_len}s %s", $addr, $h, $s);
        $addr += length($s);
    }
    return @out;
}


__END__

=head1 NAME

pCurl - A minimalist cURL in Perl.

=head1 VERSION

v0.6

=head1 SYNOPSIS

pcurl.pl [options] [url]

=head1 DESCRIPTION

pCurl is a vanilla Perl tool that mimics cURL without external dependancies but OpenSSL in the case of a SSL connection. It is intented to provide a subset of cURL when cURL is not available. It is designed to work with a fresh installation of Perl without the need for additional CPAN packages.

=head1 OPTIONS

=over 4

=item -a, --agent <ua string>

Specify a string for User-Agent. If not specified the default User-Agent is 'pcurl v$VERSION'.

=item --basic <user:password>

Use basic http authentication. Sepcified in the form user:password it is passed to the server in Base64 encoding.

=item -b, --cookie <string or file>

Activate cookie support and read cookie from a string like 'NAME=Value' or a file. The file is either in 'HTTP headers format' or in 'Netscape cookie format'. See the L<Unofficial cookie FAQ|http://www.cookiecentral.com/faq/#3.5>. The file is never modified. If you want to save cookies, see --cookie-jar.

=item -c, --cookie-jar <file or dash>

Save cookies into a 'Netscape cookie format' file, or if the given file is '-', output the cookies into STDOUT.

=item --d, --data, --data-ascii <data>

Define some data that will be POSTed to the server. If data starts with '@', the rest of the string will be taken as a file name whose content will be send as request body. If using '-' as file name, the data will be read from standard input (so you can pipe it from another command). Note that CR+LF characters will be discarded from the output. See --data-binary if you need to send unaltered data.

=item --data-binary <data>

Similar to --data, but do not discard CR+LF characters. When reading from a file, perform binary read.

=item --data-raw <data>

Similar to --data, but do not interpret an initial '@' character.

=item --data-urlencode <data>

Similar to --data-raw, but the data will be url-encoded.

=item -I, --head

Show the document headers only. The shorthand notation for -X HEAD.

=item -H, --header <header_spec>

Send an additional header, or change / discard a default one. Usual syntax is -H 'header_name: value', e.g. -H 'X-my-header: some text'. To send several custom headers, repeat the -H parameter. If you pass only 'header_name:' (without value) the header will not be transmitted. If you need to send an empty header, use 'header_name;' (use semicolon).

=item -h, --help

Display a short help.

=item --http09, --http10, --http11

Specify the version of HTTP we want to use. In HTTP/0.9 the only method is GET <url> (without version) and the answer does not return headers, only the body of returned resource. In HTTP/1.0 we can use Host:, Connection: and additional headers. IN HTTP/1.1 the Host: is mandatory and if you do not specify Connection: it is kept open by default. We send automatically a Connection: close by default.

=item --junk-session-cookies

When using -b, --cookie and loading cookies from file, purge the session cookies (those with no expire date).

=item -L, --location

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

=item --port <port>

Specify explicitly the port. If not used, we use the port from the url (if specified), or we will try well-known port 80 for HTTP and 443 for HTTPS, depending on the url scheme.

=item -x, --proxy <proxy_url>

Set the url of the HTTP/1.1 proxy to use.

=item --proxy10 <proxy_url>

Set the url of the HTTP/1.0 proxy to use.

=item -U, --proxy-user <user:passwd>

Set the proxy authentication. Only Basic Auth is supported.

=item -e, --referer <referer url>

Specify a string for the referer. If followed by ";auto", when following redirections, reuse the previous url as referer. ";auto" can also be used alone with redirections.

=item -X, --request <method>

Specify the method for the request. Common methods are GET, HEAD, POST, PUT, TRACE, OPTIONS and DELETE, but you can specify a custom method. If not specified, we send a GET. 

=item --stompmsg <message>

Content of the message for the STOMP message broker. Use with a stomp://server:port/queuename url. 

=item --url <url>

Specify explicitly the url. If that parameter is not used, we try to get the url as the remaining text after the parameters.

=item -v, --verbose

Show both headers during the communication.

=back

=cut

# Local Variables: 
# coding: utf-8-unix
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 sts=4 et :
