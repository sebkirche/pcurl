#!/usr/bin/perl
use warnings;
use strict;
use feature 'say';
use utf8;
use Getopt::Long;
use Socket;
use MIME::Base64 'encode_base64';
use Data::Dumper;
use Pod::Usage;
use IPC::Open3;
use IO::Socket::INET;
use IO::Select;
# use Carp::Always;

our $VERSION = 0.1;
$|++; # auto flush messages
$Data::Dumper::Sortkeys = 1;

BEGIN{                          # automagic breakpoint for warnings when script is run by perl -d
    $SIG{__WARN__} = sub {
        my $msg = shift;
        chomp $msg;
        say "Warning: '$msg'";
        no warnings 'once';     # avoid « Warning: 'Name "DB::single" used only once: possible typo »
        $DB::single = 1;        # we stop execution if a warning occurs during run
    };
}

my $max_redirs = 20;
my ($url, $cli_url, $auth_basic, $uagent, $http_vers, $tunnel_pid);

my ($arg_hlp, $arg_man, $arg_debug, $arg_verbose,
    $arg_basic, $arg_url, $arg_port, $arg_agent,
    $arg_httpv09, $arg_httpv10, $arg_httpv11,
    $arg_method, $arg_info, $arg_follow, $arg_maxredirs,
    $arg_proxy, $arg_proxy10, $arg_proxyuser, $arg_noproxy,
    $arg_stompdest, $arg_stompmsg) = ();

GetOptions(
    'help|h|?'       => \$arg_hlp,
    'man'            => \$arg_man,
    'debug|d'        => \$arg_debug,
    'verbose|v'      => \$arg_verbose,
    'basic=s'        => \$arg_basic,
    'url=s'          => \$arg_url,
    'port|p=i'       => \$arg_port,
    'agent|a=s'      => \$arg_agent,
    'http09'         => \$arg_httpv09,
    'http10'         => \$arg_httpv10,
    'http11'         => \$arg_httpv11,
    'request|X=s'    => \$arg_method,
    'head|I'         => \$arg_info,
    'location|L'     => \$arg_follow,
    'max-redirs=i'   => \$arg_maxredirs,
    'proxy|x=s'      => \$arg_proxy,
    'proxy10=s'      => \$arg_proxy10,
    'proxy-user|U=s' => \$arg_proxyuser,
    'noproxy=s'      => \$arg_noproxy,
    # 'stompdest=s'    => \$arg_stompdest,
    'stompmsg=s'     => \$arg_stompmsg,
    ) or pod2usage(2);
pod2usage(1) if $arg_hlp;
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
        # send anyway ?
        # die "$arg_method: unknown method\n";
    }
}

#say STDERR "Url = $url->{url}\nScheme = $url->{scheme}\nAuth = $url->{auth}\nHost = $url->{host}\nPort = $url->{port}\nPath = $url->{path}\nParams = $url->{params}";

if ($url->{scheme} =~ /^http/){
    my $method = $arg_info ? 'HEAD' : $arg_method || 'GET';
    #$url->{path} = '*' if $method eq 'OPTIONS';    
    process_http($method, $url);
} elsif ($url->{scheme} =~ /^stomp/){
    unless ($url->{path} && $arg_stompmsg){
        say STDERR "Message sending with --stompmsg <message> is supported for now.";
        exit 1;
    }
    process_stomp($url);
}

sub process_http {
    my $method = shift;
    my $url_final = shift;

    my ($IN, $OUT, $ERR, $host, $port, $resp);

    my $url_proxy = get_proxy_settings($url_final);
    my $pheaders = make_proxy_request($url_proxy, $url_final) if ($url_final->{scheme} eq 'https') ;
    
    my $redirs = $arg_maxredirs || $max_redirs;
    do {
        my $headers = make_request($method, $url_final, $url_proxy);

        if ($url_proxy){
            # FIXME when using OpenSSL and Proxy, we should connect the input/outputs of each other...
            ($OUT, $IN, $ERR) = connect_direct_socket($url_proxy->{host}, $url_proxy->{port}) if $url_proxy->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_proxy->{host}, $url_proxy->{port}) if $url_proxy->{scheme} eq 'https';
            $url_final->{proxified} = 1;
            if ($pheaders && @$pheaders){
                send_http_request($IN, $OUT, $ERR, $pheaders);
                $resp = process_http_response($IN, $ERR);
                say STDERR sprintf('Proxy returned a code %d: %s', $resp->{code}, $resp->{message}) if $arg_verbose || $arg_debug;
                exit 1 unless $resp->{code} == 200;
                $url_final->{tunneled} = 1;
            }
        } else {
            ($OUT, $IN, $ERR) = connect_direct_socket($url_final->{host}, $url_final->{port}) if $url_final->{scheme} eq 'http';
            ($OUT, $IN, $ERR) = connect_ssl_tunnel($url_final->{host}, $url_final->{port}) if $url_final->{scheme} eq 'https';
        }

        send_http_request($IN, $OUT, $ERR, $headers);
        $resp = process_http_response($IN, $ERR);
        my $code = $resp->{status}{code};
        if ($arg_follow && (300 <= $code) && ($code <= 399)){
            unless($redirs){
                say STDERR sprintf("Too many redirections (>%d).", $arg_maxredirs || $max_redirs);
                exit 1;
            }
            $url_final = parse_url($resp->{headers}{location});
            say STDERR sprintf("Redirecting #%d to %s", ($arg_maxredirs || $max_redirs) -  $redirs,  $url_final->{url}) if $arg_verbose || $arg_debug;
            $redirs--;
        } else {
            goto BREAK;         # weird, 'last' is throwing a warning "Exiting subroutine via last"
        }
    } while ($url_final && $redirs >= 0);
  BREAK:
    
    close $IN;
    close $OUT;
    close $ERR if $ERR;
}

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
    
    while (my @ready = $selector->can_read(0.5)) {
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
sub send_http_request {
    my ($IN, $OUT, $ERR, $headers) = @_;
    if ($arg_verbose){
        say STDOUT "> $_" for @$headers;
    }
    my $request = join( "\r\n", @$headers ) . "\r\n\r\n";
    print $OUT $request;
    $OUT->flush;
}

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
    say STDERR "Using proxy $proxy->{url}" if $arg_verbose;
    return $proxy;
}

sub make_request {
    my $method = shift;
    my $u = shift;
    my $p = shift;
    my $headers = [];

    if (HTTP09()){
        push @$headers, "${method} $u->{path}", ''; # This is the minimal request (in 0.9)
    } else {
        if ($u->{proxified}){
            push @$headers, "${method} $u->{url} HTTP/${http_vers}";
        } else {
            # a proxy tunnel uses CONNECT
            my $path = $u->{path} . ($u->{params} ? "?$u->{params}" : '');
            push @$headers, "${method} ${path} HTTP/${http_vers}";
        }
        push @$headers, "Host: $u->{host}";        
        push @$headers, "User-Agent: ${uagent}";
        push @$headers, 'Accept: */*';
        push @$headers, 'Connection: close';
        my $pauth = $arg_proxyuser || $p->{auth};
        push @$headers, 'Proxy-Authorization: Basic ' . encode_base64($pauth) if $pauth;
        my $auth = $arg_basic || $u->{auth};
        push @$headers, 'Authorization: Basic ' . encode_base64($auth) if $auth;

    }
    return $headers;
}

sub make_proxy_request {
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
    push @$headers, "Host: $u->{host}:$u->{port}";
    push @$headers, "User-Agent: ${uagent}";
    my $auth = $arg_proxyuser || $p->{auth};
    push @$headers, 'Proxy-Authorization: Basic ' . encode_base64($auth) if $auth;
    if (HTTP11()){
        # push @$headers, 'Proxy-Connection: close';
    }
    return $headers;
}

sub process_http_response {
    my $IN = shift;
    my $ERR = shift;
    my $headers_done = 0;
    my $status_done = 0;
    my $content_length = 0;
    my $next_chunk_size = undef;
    my $received = 0;
    my %headers;
    my %resp;
    
    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    while (my @ready = $selector->can_read(1)) {
        foreach my $fh (@ready) {
            if ($ERR && (fileno($fh) == fileno($ERR))) {
                while(my $line = <$fh>){
                    print STDERR "STDERR: $line" if $arg_debug;
                }
            }
            if (fileno($fh) == fileno($IN)) {
                if (! $headers_done && !HTTP09()){ # there is no header in HTTP/0.9
                    local $/ = "\r\n";
                  HEAD: while(my $line = <$IN>){
                      # $line =~ s/[\r\n]+$//;
                      print STDOUT '< ' if $arg_verbose;
                      print STDOUT $line if $arg_verbose || $arg_info;
                      if ($line =~ s/^[\r\n]+$//){
                          $headers_done++;
                          last HEAD;
                      }
                      if (!$status_done && $line =~ m{^([^\s]+) (\d+) (.*)$}){
                          $resp{status}{proto} = $1;
                          $resp{status}{code} = $2;
                          $resp{status}{message} = $3;
                          $status_done++;
                      }
                      if ($line =~ /^([A-Za-z0-9-]+): (.*)$/){
                          $resp{headers}{lc $1} = $2;
                      }                            
                  }
                }
                # my $rfd;
                # vec($rfd,fileno($fh),1) = 1;
                # if (select($rfd, undef, undef, 0) >= 0){
                my $is_redirect = $resp{status}{code} =~ /^3/;
                say "Ignoring the response-body" if $is_redirect;
                unless ($fh->eof){
                    $content_length = $headers{'content-length'};
                    $next_chunk_size = $content_length unless $next_chunk_size;
                    my $buf_size = 2 * 1024 * 1024;
                    my $block = $fh->read(my $buf, $buf_size);
                    if ($block){
                        say STDERR "Read $block bytes" if $arg_debug;
                        $received += $block;
                        print STDOUT $buf unless $is_redirect;
                    }
                    # say STDERR 'Done?' , eof($fh), $received ;
                }
                # there may have additional info
            };
            # print STDOUT $_ for <$fh>;
            # warn "Extra data for fh $fh ?" unless eof($fh) ;
            $selector->remove($fh) if eof($fh);
        }
    }
    return \%resp;
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
        say STDERR $given;
        say(STDERR "$_ = $url->{$_}") for(sort(keys %$url));
    }
    return $url;
}

sub HTTP09 {
    return ($http_vers && $http_vers eq '0.9') ? 1 : undef;
}
sub HTTP10 {
    return ($http_vers && $http_vers eq '1.0') ? 1 : undef;
}
sub HTTP11 {
    return ($http_vers && $http_vers eq '1.1') ? 1 : undef;
}

sub connect_direct_socket {
    my ($host, $port) = @_;
    # my $iaddr = inet_aton($host);
    # my $paddr = sockaddr_in( $port, $iaddr );
    # my $proto = getprotobyname('tcp');
    # my $sock;
    # unless ( socket( $sock, PF_INET, SOCK_STREAM, $proto ) ) {
    #     die "ERROR : init socket: $!";
    # }
    # unless ( connect( $sock, $paddr ) ) { die "no connect: $!\n"; }
    my $sock = new IO::Socket::INET(PeerAddr => $host,
                                    PeerPort => $port,
                                    Proto    => 'tcp') or die "Can't connect to $host:$port\n";
    $sock->autoflush(1);
    
    return $sock, $sock, undef;
}

sub connect_ssl_tunnel {
    my ($host, $port) = @_;
    my $cmd = "openssl s_client -connect ${host}:${port} -quiet";# -verify_quiet -partial_chain';
    $tunnel_pid = open3(*CMD_IN, *CMD_OUT, *CMD_ERR, $cmd);

    $SIG{CHLD} = sub {
        print STDERR "REAPER: status $? on ${tunnel_pid}\n" if waitpid($tunnel_pid, 0) > 0 && $arg_debug;
    };
    return *CMD_IN, *CMD_OUT, *CMD_ERR;
}

__END__

=head1 NAME

pCurl - A minimalist cURL in Perl.

=head1 VERSION

v0.1

=head1 SYNOPSIS

pcurl.pl [options] [url]

=head1 DESCRIPTION

pCurl is a vanilla Perl tool that mimics cURL without external dependancies but OpenSSL in the case of a SSL connection. It is intented to provide a subset of cURL when cURL is not available. It is designed to work with a fresh installation of Perl without the need for additional CPAN packages.

=head1 OPTIONS

=over 4

=item B<-h --help>

Display a short help.

=item B<--man>

Display the full manual.

=item B<-v --verbose>

Show both headers during the communication.

=item B<--basic <user:password>>

Use basic http authentication. Sepcified in the form user:password it is passed to the server in Base64 encoding.

=item B<--url <url>>

Specify explicitly the url. If that parameter is not used, we try to get the url as the remaining text after the parameters.

=item B<--port <port>>

Specify explicitly the port. If not used, we use the port from the url (if specified), or we will try well-known port 80 for HTTP and 443 for HTTPS, depending on the url scheme.

=item B<-a --agent <ua string>>

Specify a string for User-Agent. If not specified the default User-Agent is 'pcurl v$VERSION'.

=item B<--http09 --http10 --http11>

Specify the version of HTTP we want to use. In HTTP/0.9 the only method is GET <url> (without version) and the answer does not return headers, only the body of returned resource. In HTTP/1.0 we can use Host:, Connection: and additional headers. IN HTTP/1.1 the Host: is mandatory and if you do not specify Connection: it is kept open by default. We send automatically a Connection: close by default.

=item B<-X --request <method>>

Specify the method for the request. Common methods are GET, HEAD, POST, PUT, TRACE, OPTIONS and DELETE, but you can specify a custom method. If not specified, we send a GET. 

=item B<-I --head>

Show the document headers only. The shorthand notation for -X HEAD.

=item B<-L --location>

Follow HTTP redirects.

=item B<--max-redirs <nb>>

Specify the maximum number of redirects to follow. Default is 20.

=item B<-x --proxy <proxy_url>>

Set the url of the HTTP/1.1 proxy to use.

=item B<-proxy10 <proxy_url>>

Set the url of the HTTP/1.0 proxy to use.

=item B<-U --proxy-user <user:passwd>>

Set the proxy authentication. Only Basic Auth is supported.

=item B<--noproxy <domain_list>>

Define a coma-separated list of domains that ignore the proxy. 

=item B<--stompmsg <message>>

Content of the message for the STOMP message broker. Use with a stomp://server:port/queuename url. 

=back

=cut

# Local Variables: 
# coding: utf-8-unix
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 sts=4 et :
