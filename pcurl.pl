#!/usr/bin/perl
use warnings;
use strict;
use feature 'say';
use utf8;
use Getopt::Long;
use Socket;
use MIME::Base64;
use Data::Dumper;
use Pod::Usage;
use IPC::Open3;
use IO::Socket::INET;
use IO::Select;
use Carp::Always;

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
    $http_vers = '09';
} elsif ($arg_httpv10){
    $http_vers = '10';
} elsif ($arg_httpv11){
    $http_vers = '11';
} elsif ($url->{scheme} =~ /^http/){
    $http_vers = '10';
}


if ($arg_method){
    if ($arg_method =~ /^(GET|HEAD|POST|PUT|TRACE|OPTIONS|DELETE)$/i){
        $arg_method = uc $arg_method;
        die "HTTP/0.9 only supports GET method.\n" if $arg_method ne 'GET' and HTTP09();
    } else {
        die "$arg_method: unknown method\n";
    }
}

# FIXME: manage proxy settings
# get http[s]_proxy
# respect no_proxy or --noproxy
# manual proxy or --proxy

say STDERR "Url = $url->{url}\nScheme = $url->{scheme}\nAuth = $url->{auth}\nHost = $url->{host}\nPort = $url->{port}\nPath = $url->{path}\nParams = $url->{params}";

if ($url->{scheme} =~ /^http/){
    my $method = $arg_method || 'GET';
    process_http($method, $url);
}

sub process_http {
    my $method = shift;
    my $url = shift;
    my ($IN, $OUT, $ERR);
    ($OUT, $IN, $ERR) = connect_direct_socket($url->{host}, $url->{port}) if $url->{scheme} eq 'http';
    ($OUT, $IN, $ERR) = connect_ssl_tunnel($url->{host}, $url->{port}) if $url->{scheme} eq 'https';
    
    my @head = (
        "${method} $url->{path} HTTP/1.0",
        "User-Agent: ${uagent}",
        "",
        "",
        );
    my $request = join( "\r\n", @head );
    # select $OUT;
    # $| = 1;
    # binmode $OUT;
    print $OUT $request;
    # $OUT->flush;
    shutdown $OUT, 1;

    # my @data = (<$IN>);
    # print STDOUT "result >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n@data\n---EOT---\n";

    my $selector = IO::Select->new();
    $selector->add($ERR) if $ERR;
    $selector->add($IN);

    while (my @ready = $selector->can_read) {
        foreach my $fh (@ready) {
            if ($ERR && fileno($fh) == fileno($ERR)) {print STDERR "STDERR: ", scalar <$fh>};
            if (fileno($fh) == fileno($IN)) {print "$_" for <$fh>};
            # print STDOUT $_ for <$fh>;
            $selector->remove($fh) if eof($fh);
        }
    }

    
    close $IN;
    close $OUT;
    close $ERR if $ERR;
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
            $url->port = 443;
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
    return ($http_vers && $http_vers eq '09') ? 1 : undef;
}
sub HTTP10 {
    return ($http_vers && $http_vers eq '10') ? 1 : undef;
}
sub HTTP11 {
    return ($http_vers && $http_vers eq '11') ? 1 : undef;
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
        print STDERR "REAPER: status $? on ${tunnel_pid}\n" if waitpid($tunnel_pid, 0) > 0
    };
    return *CMD_IN, *CMD_OUT, *CMD_ERR;
}

__END__

=head1 NAME

pcurl.pl - A minimalist curl in Perl.

=head1 VERSION

v0.1

=head1 SYNOPSIS

pcurl.pl [options] [url]

=head1 DESCRIPTION

pcurl.pl is a vanilla Perl tool that mimics curl without external dependancies but OpenSSL in the case of a SSL connection.

=head1 OPTIONS

=over 4

=item B<-h --help>

Display a short help.

=item B<--man>

Display the full manual.

=back

=cut

# Local Variables: 
# coding: utf-8-unix
# mode: perl
# tab-width: 4
# indent-tabs-mode: nil
# End:
# ex: ts=4 sw=4 sts=4 et :
