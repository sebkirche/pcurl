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

my ($url, $cli_url, $auth_basic, $uagent, $http_vers, $tunnel_pid);

my ($arg_hlp, $arg_man, $arg_debug, $arg_verbose, $arg_basic, $arg_url, $arg_port, $arg_agent, $arg_httpv09, $arg_httpv10, $arg_httpv11, $arg_method, $arg_info) = (0,0,0,0);
GetOptions(
    'help|h|?'    => \$arg_hlp,
    'man'         => \$arg_man,
    'debug|d'     => \$arg_debug,
    'verbose|v'   => \$arg_verbose,
    'basic=s'     => \$arg_basic,
    'url=s'       => \$arg_url,
    'port|p=i'    => \$arg_port,
    'agent|a=s'   => \$arg_agent,
    'http09'      => \$arg_httpv09,
    'http10'      => \$arg_httpv10,
    'http11'      => \$arg_httpv11,
    'request|X=s' => \$arg_method,
    'head|I'      => \$arg_info,
    
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

if ($arg_method){
    if ($arg_method =~ /^(GET|HEAD|POST|PUT|TRACE|OPTIONS|DELETE)$/i){
        $arg_method = uc $arg_method;
        die "HTTP/0.9 only supports GET method.\n" if $arg_method ne 'GET' and HTTP09();
    } else {
        # send anyway ?
        # die "$arg_method: unknown method\n";
    }
}

# FIXME: manage proxy settings
# get http[s]_proxy
# respect no_proxy or --noproxy
# manual proxy or --proxy

#say STDERR "Url = $url->{url}\nScheme = $url->{scheme}\nAuth = $url->{auth}\nHost = $url->{host}\nPort = $url->{port}\nPath = $url->{path}\nParams = $url->{params}";

if ($url->{scheme} =~ /^http/){
    my $method = $arg_info ? 'HEAD' : $arg_method || 'GET';
    #$url->{path} = '*' if $method eq 'OPTIONS';
    process_http($method, $url);
}

sub process_http {
    my $method = shift;
    my $url = shift;

    my $headers = make_request_headers($method, $url);
    
    my ($IN, $OUT, $ERR);
    ($OUT, $IN, $ERR) = connect_direct_socket($url->{host}, $url->{port}) if $url->{scheme} eq 'http';
    ($OUT, $IN, $ERR) = connect_ssl_tunnel($url->{host}, $url->{port}) if $url->{scheme} eq 'https';

    if ($arg_verbose){
        say STDOUT "> $_" for @$headers;
    }
    my $request = join( "\r\n", @$headers ) . "\r\n\r\n";
    # $OUT->print($request);
    print $OUT $request;

    process_http_response($IN, $ERR);
    
    close $IN;
    close $OUT;
    close $ERR if $ERR;
}

sub make_request_headers {
    my $method = shift;
    my $url = shift;
    my $h = [];

    if (HTTP09()){
        push @$h, "${method} $url->{path}", ''; # This is the minimal request (in 0.9)
    } else {
        push @$h, "${method} $url->{path} HTTP/${http_vers}";
        push @$h, "Host: $url->{host}";        
        push @$h, "User-Agent: ${uagent}";
        push @$h, 'Accept: */*';
        push @$h, 'Connection: close';
        my $auth = $arg_basic || $url->{auth};
        push @$h, 'Authorization: Basic ' . encode_base64($auth) if $auth;

    }
    
    return $h;
}

sub process_http_response {
    my $IN = shift;
    my $ERR = shift;
    my $headers_done = 0;
    my $content_length = 0;
    my $next_chunk_size = undef;
    my $received = 0;
    my %headers;
    
    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    while (my @ready = $selector->can_read) {
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
                      #chomp $line;
                      print STDOUT '< ' if $arg_verbose;
                      print STDOUT $line if $arg_verbose || $arg_info;
                      if ($line =~ /^[\r\n]+$/){
                          $headers_done = 1;
                          last HEAD;
                      }
                      if ($line =~ /^([a-z0-9-]): (.*)$/){
                          $headers{lc $1} = $2;
                      }                            
                  }
                }
                unless (eof($fh)){
                    $content_length = $headers{'content-length'};
                    $next_chunk_size = $content_length unless $next_chunk_size;
                    my $buf_size = 2 * 1024 * 1024;
                    my $block = $IN->read(my $buf, $buf_size);
                    if ($block){
                        say STDERR "Read $block bytes" if $arg_verbose;
                        $received += $block;
                        print STDOUT $buf;
                    }
                    # say STDERR 'Done?' , eof($fh), $received ;
                }
                # there may have additional info
            };
            # print STDOUT $_ for <$fh>;
            warn "Extra data for fh $fh ?" unless eof($fh);
            $selector->remove($fh) if eof($fh);
        }
    }

}

# Extract de differents parts from an URL
# return a hashref or undef if it fails
sub parse_url {
    my $given = shift;
    unless( $given =~ qr{
        (?<SCHEME> [\w]+ ) (?: :// )
        (?: (?<AUTH> (?&UNRESERVED)+ ( : [^@]+ )? ) @ )?
        (?<HOST> [^-] (?&UNRESERVED)+ ) \:?
        (?<PORT> \d+ )?
        (?<PATH> (?&PCHAR)+ ) 
        (?<PARAMS> \? (?&PCHAR)* )?
      
        (?(DEFINE) #from here, define some sub-parts
          (?<PCHAR> (?&UNRESERVED) | (?&PCTENCODED) | (?&SUBDEL) | : | @ )
          (?<PCTENCODED> % (?&HEXDIG) (?&HEXDIG) )
          (?<HEXDIG> [0-9A-Za-z] )
          (?<UNRESERVED> [A-Za-z0-9._~-] )
          (?<SUBDEL> [/!\$'&()\*\+,.=] )
        )
            }x ){
        return undef;
    }
    my $url = {};
    $url->{url} = $given;
    $url->{scheme} = $+{SCHEME};
    $url->{auth} = $+{AUTH} || '';
    $url->{host} = $+{HOST};
    $url->{port} = $arg_port || $+{PORT};
    unless ($url->{port}){
        if ($url->{scheme} eq 'http'){
            $url->{port} = 80;
        } elsif ($url->{scheme} eq 'https'){
            $url->{port} = 443;
        } else {
            say STDERR "Default port unknown for scheme '$url->{scheme}://'...";
            return undef;
        }
    }
    $url->{path} = $+{PATH};
    $url->{params} = $+{PARAMS} || '';
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

=back

=cut

# Local Variables: 
# coding: utf-8-unix
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 sts=4 et :
