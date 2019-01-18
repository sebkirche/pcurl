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

our $VERSION = 0.1;
$|++; # auto flush messages
$Data::Dumper::Sortkeys = 1;

my ($url, $cli_url, $url_scheme, $url_auth, $url_host, $url_port, $url_path, $url_params, $auth_basic, $uagent, $http_vers);

my ($arg_hlp, $arg_man, $arg_debug, $arg_verbose, $arg_basic, $arg_url, $arg_port, $arg_agent, $arg_httpv09, $arg_httpv10, $arg_httpv11,) = (0,0,0,0);
GetOptions(
    'help|h|?'  => \$arg_hlp,
    'man'       => \$arg_man,
    'debug|d'   => \$arg_debug,
    'verbose|v' => \$arg_verbose,
    'basic=s'   => \$arg_basic,
    'url=s'     => \$arg_url,
    'port|p=i'  => \$arg_port,
    'agent|a=s' => \$arg_agent,
    'http09'    => \$arg_httpv09,
    'http10'    => \$arg_httpv10,
    'http11'    => \$arg_httpv11,
    ) or pod2usage(2);
pod2usage(1) if $arg_hlp;
pod2usage(-exitval => 0, -verbose => 2) if $arg_man;

$cli_url = $arg_url || $ARGV[0];
unless ($cli_url){
    say "No url provided...";
    pod2usage(1);
}
unless ($url = parse_url($cli_url)){
    say "It's strange to me that `$url` does not look as an url...";
    exit 1;
}

$uagent = $arg_agent || "pcurl v$VERSION";

if ($arg_httpv11){
    $http_vers = '09';
} elsif ($arg_httpv10){
    $http_vers = '10';
} elsif ($arg_httpv11){
    $http_vers = '11';
} elsif ($url->{scheme} =~ /^http/){
    $http_vers = '10';
}

# FIXME: manage proxy settings
# get http[s]_proxy
# respect no_proxy or --noproxy
# manual proxy or --proxy


say "Url = $url->{url}\nScheme = $url->{scheme}\nAuth = $url->{auth}\nHost = $url->{host}\nPort = $url->{port}\nPath = $url->{path}\nParams = $url->{params}";

if ($url->{scheme} =~ /^http/){
    
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
    (?<PCHAR> (?&UNRESERVED) 
        | (?&PCTENCODED) 
        | (?&SUBDEL) 
        | : 
        | @
    )
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
    unless ($url_port){
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
    $url->{params} = $+{PARAMS};
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
