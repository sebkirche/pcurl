#!/usr/bin/env perl
#
# Regression test suite for pcurl.
#
# pcurl is a single-file Perl program that also behaves as a loadable module
# (package Pcurl). When required, it does NOT run cli() because caller() is set,
# and it returns a true value (42). This lets us unit-test its internal
# functions directly.
#
# Run with:   prove -v t/pcurl.t
#      or:    perl t/pcurl.t
#
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use File::Temp qw(tempfile tempdir);

# Locate the pcurl script (one level up from t/)
my $PCURL = "$Bin/../pcurl";
ok(-r $PCURL, "pcurl script is readable at $PCURL") or BAIL_OUT("cannot find pcurl at $PCURL");

# Load pcurl as a module. It returns 42 when used as a package.
require $PCURL;

# Convenience: most helpers live in package Pcurl.
# Seed the module's internal %args via its own helper so lexical %args is set.
Pcurl::simulate_cli_settings(
    'header'           => [],
    'data'             => [],
    'data-binary'      => [],
    'data-raw'         => [],
    'data-urlencode'   => [],
    'user-agent'       => 'pCurl-test',
    'json-pp-indent'   => 2,
    'xml-pp-indent'    => 2,
    'xml-root-element' => 'root',
);

# ---------------------------------------------------------------------------
subtest 'parse_uri - basic http url' => sub {
    my $u = Pcurl::parse_uri('http://example.com/path/to/page?x=1#frag');
    ok($u, 'parsed a basic url');
    is($u->{scheme},   'http',            'scheme');
    is($u->{host},     'example.com',     'host');
    is($u->{path},     '/path/to/page',   'path');
    is($u->{query},    'x=1',             'query');
    is($u->{fragment}, 'frag',            'fragment');
};

subtest 'parse_uri - userinfo, port' => sub {
    my $u = Pcurl::parse_uri('https://alice:secret@sub.example.com:8443/res');
    ok($u, 'parsed url with userinfo and port');
    is($u->{scheme}, 'https',           'scheme');
    is($u->{host},   'sub.example.com', 'host');
    is($u->{port},   8443,              'port');
    is($u->{auth}{user},     'alice',   'auth user');
    is($u->{auth}{password}, 'secret',  'auth password');
};

subtest 'parse_uri - invalid input returns undef' => sub {
    my $u = Pcurl::parse_uri('not a url with spaces');
    ok(!defined $u, 'invalid uri returns undef');
};

subtest 'parse_uri - scheme variations' => sub {
    my $f = Pcurl::parse_uri('file:///etc/hosts');
    ok($f, 'parsed file url');
    is($f->{scheme}, 'file', 'file scheme');

    my $s = Pcurl::parse_uri('stomp://mq.example.com:61613/queue/test');
    ok($s, 'parsed stomp url');
    is($s->{scheme}, 'stomp',           'stomp scheme');
    is($s->{host},   'mq.example.com',  'stomp host');
    is($s->{port},   61613,             'stomp port');
};

# ---------------------------------------------------------------------------
subtest 'complete_url_default_values - default ports' => sub {
    my $u = Pcurl::parse_uri('http://example.com/');
    Pcurl::complete_url_default_values($u);
    is($u->{port}, 80, 'http default port 80');

    my $h = Pcurl::parse_uri('https://example.com/');
    Pcurl::complete_url_default_values($h);
    is($h->{port}, 443, 'https default port 443');
};

# ---------------------------------------------------------------------------
subtest 'urlencode / urldecode roundtrip' => sub {
    is(Pcurl::urlencode('a b'),       'a+b',          'space -> +');
    is(Pcurl::urlencode('a/b?c=d'),   'a%2Fb%3Fc%3Dd','reserved chars encoded');
    is(Pcurl::urldecode('a+b'),       'a b',          '+ -> space');
    is(Pcurl::urldecode('a%2Fb'),     'a/b',          '%2F -> /');

    for my $s ('hello world', 'x=1&y=2', 'path/seg') {
        is(Pcurl::urldecode(Pcurl::urlencode($s)), $s, "roundtrip: '$s'");
    }
};

# ---------------------------------------------------------------------------
subtest 'canonicalize - single argument (absolute path)' => sub {
    is(Pcurl::canonicalize('/a/b/c'),          '/a/b/c',  'plain absolute');
    is(Pcurl::canonicalize('/a/b/../c'),       '/a/c',    'parent segment');
    is(Pcurl::canonicalize('/a/./b'),          '/a/b',    'current segment');
    is(Pcurl::canonicalize('/a/b/'),           '/a/b/',   'trailing slash kept');
    is(Pcurl::canonicalize('/a/b/../../c'),    '/c',      'multiple dotdot');
    is(Pcurl::canonicalize('/'),               '/',       'root stays root');
};

subtest 'canonicalize - two arguments (relative to base)' => sub {
    # base without leading slash
    is(Pcurl::canonicalize('b/c', 'a'),        '/a/b/c',  'relative to bare base');
    # base with leading slash must NOT produce a doubled slash (bug fix)
    is(Pcurl::canonicalize('b/c', '/a'),       '/a/b/c',  'relative to absolute base');
    is(Pcurl::canonicalize('../x', '/a/b'),    '/a/x',    'dotdot against absolute base');
    is(Pcurl::canonicalize('./y', '/a/b'),     '/a/b/y',  'dot against absolute base');
    # an absolute path ignores the base entirely
    is(Pcurl::canonicalize('/abs', '/a/b'),    '/abs',    'absolute path ignores base');
};

# ---------------------------------------------------------------------------
subtest 'is_descendant_or_equal' => sub {
    ok( Pcurl::is_descendant_or_equal('/a/b/c', '/a/b'),  'child is descendant');
    ok( Pcurl::is_descendant_or_equal('/a/b',   '/a/b'),  'equal is descendant');
    ok(!Pcurl::is_descendant_or_equal('/a',     '/a/b'),  'parent is not descendant');
    ok( Pcurl::is_descendant_or_equal('/x/y',   '/'),     'anything descends from root');
    ok(!Pcurl::is_descendant_or_equal('/a/x',   '/a/b'),  'sibling is not descendant');
};

# ---------------------------------------------------------------------------
subtest 'humanize_bytes' => sub {
    is(Pcurl::humanize_bytes(512),        512,        'bytes unchanged under 1KiB');
    is(Pcurl::humanize_bytes(1024),       '1.0 KiB',  'KiB');
    is(Pcurl::humanize_bytes(1048576),    '1.0 MiB',  'MiB');
    is(Pcurl::humanize_bytes(1073741824), '1.0 GiB',  'GiB');
};

# ---------------------------------------------------------------------------
subtest 'str2epoch - Last-Modified parsing' => sub {
    my $e = Pcurl::str2epoch('Wed, 21 Oct 2015 07:28:00 GMT');
    is($e, 1445412480, 'known GMT timestamp -> epoch');

    my $bad = Pcurl::str2epoch('not a date');
    is($bad, -1, 'unparseable timestamp returns -1');
};

# ---------------------------------------------------------------------------
subtest 'JSON parser - from_json basic types' => sub {
    my $o = Pcurl::from_json('{"s":"hi","n":42,"f":-1.5e2,"t":true,"fa":false,"nil":null}');
    ok($o, 'parsed object');
    is($o->{s},  'hi', 'string value');
    is($o->{n},  42,   'integer value');
    is($o->{f},  -150, 'float with exponent');
    is($o->{t},  1,    'true -> 1');
    is($o->{fa}, 0,    'false -> 0');
    ok(!defined $o->{nil}, 'null -> undef');
};

subtest 'JSON parser - arrays and nesting' => sub {
    my $o = Pcurl::from_json('{"list":[1,2,3],"obj":{"a":{"b":"c"}}}');
    is_deeply($o->{list}, [1,2,3], 'array parsed');
    is($o->{obj}{a}{b}, 'c', 'nested object');

    my $arr = Pcurl::from_json('[10,20,30]');
    is_deeply($arr, [10,20,30], 'top-level array');
};

subtest 'JSON parser - string escapes and unicode' => sub {
    my $o = Pcurl::from_json('{"k":"line1\nline2\ttab","u":"\u0041\u00e9"}');
    is($o->{k}, "line1\nline2\ttab", 'escape sequences decoded');
    is($o->{u}, "A\x{e9}",           'unicode escapes decoded');
};

subtest 'JSON parser - no code execution (security regression)' => sub {
    my $o = Pcurl::from_json('{"key":"test`echo pwned`test"}');
    is($o->{key}, 'test`echo pwned`test',
       'backticks in JSON string are literal, not executed');
};

subtest 'JSON parser - invalid json returns undef' => sub {
    my $o = Pcurl::from_json('{ this is not json ]');
    ok(!defined $o, 'invalid json returns undef');
};

# ---------------------------------------------------------------------------
subtest 'JSON serializer - to_json' => sub {
    # scalars
    is(Pcurl::to_json(undef), 'null', 'undef -> null');
    is(Pcurl::to_json(42),    42,     'number preserved');

    # roundtrip of a structure (key order not guaranteed, so reparse)
    my $data = { name => 'bob', nums => [1,2,3], nested => { ok => 1 } };
    my $json = Pcurl::to_json($data);
    my $back = Pcurl::from_json($json);
    is_deeply($back, $data, 'to_json -> from_json roundtrip');
};

subtest 'JSON string escaping in to_json' => sub {
    my $json = Pcurl::to_json({ q => 'he said "hi"', nl => "a\nb" });
    my $back = Pcurl::from_json($json);
    is($back->{q},  'he said "hi"', 'quotes roundtrip');
    is($back->{nl}, "a\nb",         'newline roundtrip');
};

# ---------------------------------------------------------------------------
subtest 'get_jpath - navigation' => sub {
    my $data = Pcurl::from_json(
        '{"users":[{"name":"alice"},{"name":"bob"}],"meta":{"count":2}}'
    );
    is(Pcurl::get_jpath($data, '/meta/count'),      2,       'scalar via path');
    is(Pcurl::get_jpath($data, '/users/[0]/name'),  'alice', 'array index navigation');
    is(Pcurl::get_jpath($data, '/users/[1]/name'),  'bob',   'second array element');
};

subtest 'get_jpath - length pseudo-function' => sub {
    my $data = Pcurl::from_json('{"list":[1,2,3,4]}');
    is(Pcurl::get_jpath($data, '/list/length()'), 4, 'length() on array');
};

# ---------------------------------------------------------------------------
subtest 'parse_process_action' => sub {
    my $a = Pcurl::parse_process_action('header:Content-Type');
    is($a->{what},  'header',       'action type header');
    is($a->{value}, 'Content-Type', 'action value');

    my $j = Pcurl::parse_process_action('json:/a/b');
    is($j->{what},  'json', 'action type json');
    is($j->{value}, '/a/b', 'json path value');
};

# ---------------------------------------------------------------------------
subtest 'build_http_request_headers - basics' => sub {
    my $u = Pcurl::parse_uri('http://example.com/path');
    Pcurl::complete_url_default_values($u);
    my $h = Pcurl::build_http_request_headers('GET', $u, undef, undef);

    ok((grep { /^GET \/path HTTP\/1\.1$/ } @$h), 'request line present');
    ok((grep { /^Host: example\.com$/ } @$h),    'Host header present');
    ok((grep { /^User-Agent: pCurl-test$/ } @$h),'User-Agent header present');
};

subtest 'build_http_request_headers - CRLF injection rejected (security regression)' => sub {
    Pcurl::simulate_cli_settings( 'header' => [ "X-Evil: a\r\nX-Injected: yes" ] );
    my $u = Pcurl::parse_uri('http://example.com/');
    Pcurl::complete_url_default_values($u);
    my $h = Pcurl::build_http_request_headers('GET', $u, undef, undef);
    ok(!(grep { /X-Injected/ } @$h), 'header with CRLF is rejected, no injection');
    # reset headers
    Pcurl::simulate_cli_settings( 'header' => [] );
};

subtest 'build_http_request_headers - auth stripped on host change (security regression)' => sub {
    Pcurl::simulate_cli_settings( 'basic' => 'alice:secret', 'location-trusted' => 0 );

    my $trusted = { scheme=>'http', host=>'a.example.com', port=>80, path=>'/', trust_basic_auth=>1 };
    my $h1 = Pcurl::build_http_request_headers('GET', $trusted, undef, undef);
    ok((grep { /^Authorization:/ } @$h1), 'auth sent to trusted (same) host');

    my $untrusted = { scheme=>'http', host=>'evil.example.net', port=>80, path=>'/', trust_basic_auth=>0 };
    my $h2 = Pcurl::build_http_request_headers('GET', $untrusted, undef, undef);
    ok(!(grep { /^Authorization:/ } @$h2), 'auth NOT sent after host change');

    # URL userinfo credentials always follow the URL
    my $userinfo = { scheme=>'http', host=>'c.example.com', port=>80, path=>'/',
                     trust_basic_auth=>0, auth=>{ user=>'bob', password=>'pw' } };
    my $h3 = Pcurl::build_http_request_headers('GET', $userinfo, undef, undef);
    ok((grep { /^Authorization:/ } @$h3), 'URL userinfo auth still sent');

    Pcurl::simulate_cli_settings( 'basic' => undef );
};

# ---------------------------------------------------------------------------
subtest 'cookie matching - regex metachars are literal (security regression)' => sub {
    # A malicious path containing regex metacharacters must not match arbitrary paths
    my $cookies = [
        { name=>'sid', value=>'abc', domain=>'example.com', path=>'/.*', secure=>0 },
    ];
    my $url = { scheme=>'http', host=>'example.com', path=>'/unrelated', port=>80 };
    my $head = Pcurl::get_matching_cookies($url, $cookies);
    ok(!defined $head || $head !~ /sid=abc/,
       'cookie with regex-metachar path does not leak to unrelated path');

    # A legitimate matching path should still work
    my $cookies2 = [
        { name=>'sid', value=>'abc', domain=>'example.com', path=>'/app', secure=>0 },
    ];
    my $url2 = { scheme=>'http', host=>'example.com', path=>'/app/page', port=>80 };
    my $head2 = Pcurl::get_matching_cookies($url2, $cookies2);
    like($head2, qr/sid=abc/, 'legitimate cookie path still matches');
};

subtest 'parse_cookie_header - basic Set-Cookie parsing' => sub {
    my $url = { host => 'example.com', path => '/' };
    my @c = Pcurl::parse_cookie_header('foo=bar; Path=/; HttpOnly', $url);
    ok(@c, 'parsed at least one cookie');
    is($c[0]{name},  'foo', 'cookie name');
    is($c[0]{value}, 'bar', 'cookie value');
};

# ---------------------------------------------------------------------------
subtest 'load_commandline_cookies' => sub {
    my $jar = Pcurl::load_commandline_cookies('a=1; b=2');
    is(scalar @$jar, 2, 'parsed two cookies');
    is($jar->[0]{name},  'a', 'first cookie name');
    is($jar->[0]{value}, '1', 'first cookie value');
};

subtest 'cookie jar save/load roundtrip (Netscape format)' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my $file = "$dir/cookies.txt";
    my $cookies = [
        { domain=>'example.com', tailmatch=>1, path=>'/', secure=>0,
          expires=>2000000000, name=>'sid', value=>'xyz' },
    ];
    Pcurl::save_cookie_jar($file, $cookies);
    ok(-f $file, 'cookie jar file written');

    my $loaded = Pcurl::load_cookie_jar($file);
    is(scalar @$loaded, 1, 'one cookie loaded back');
    is($loaded->[0]{name},   'sid', 'cookie name roundtrip');
    is($loaded->[0]{value},  'xyz', 'cookie value roundtrip');
    is($loaded->[0]{domain}, 'example.com', 'domain roundtrip');
};

# ---------------------------------------------------------------------------
subtest 'get_redirected_url - relative Location resolved' => sub {
    my $u = Pcurl::parse_uri('http://example.com/dir/page');
    Pcurl::complete_url_default_values($u);
    my $r = Pcurl::get_redirected_url($u, '/other/place');
    is($r->{host},   'example.com',  'host preserved on relative redirect');
    is($r->{scheme}, 'http',         'scheme preserved');
    is($r->{path},   '/other/place', 'path updated');
};

subtest 'get_redirected_url - absolute Location' => sub {
    my $u = Pcurl::parse_uri('http://example.com/page');
    Pcurl::complete_url_default_values($u);
    my $r = Pcurl::get_redirected_url($u, 'https://other.example.org/x');
    is($r->{host},   'other.example.org', 'host changed');
    is($r->{scheme}, 'https',             'scheme changed');
};

# ---------------------------------------------------------------------------
subtest 'hexdump - produces offset + hex + ascii' => sub {
    my @out = Pcurl::hexdump('AB');
    ok(@out, 'hexdump returns output');
    like($out[0], qr/^000000\s+41 42\s+AB/, 'hexdump formats bytes correctly');
};

# ---------------------------------------------------------------------------
subtest 'path_escapes_base - traversal detection (security)' => sub {
    # safe paths stay within the base
    ok(!Pcurl::path_escapes_base('a/b/c'),           'plain relative path is safe');
    ok(!Pcurl::path_escapes_base('host/dir/file.html'), 'nested relative path is safe');
    ok(!Pcurl::path_escapes_base('a/../b'),          'descend then back to base is safe');
    ok(!Pcurl::path_escapes_base('./a/b'),           'leading dot is safe');

    # traversal attempts are rejected
    ok(Pcurl::path_escapes_base('../etc/passwd'),          'leading .. escapes');
    ok(Pcurl::path_escapes_base('a/../../etc/passwd'),     'net upward traversal escapes');
    ok(Pcurl::path_escapes_base('../../../../etc/cron.d/evil'), 'deep traversal escapes');
    ok(Pcurl::path_escapes_base('/etc/passwd'),            'absolute path escapes');
    ok(Pcurl::path_escapes_base('a/b/../../..'),           'trailing traversal below base escapes');
};

# ---------------------------------------------------------------------------
subtest 'redact_header_line - masks credentials by default (security)' => sub {
    Pcurl::simulate_cli_settings( 'no-auth-redact' => 0 );
    is(Pcurl::redact_header_line('Authorization: Basic YWxpY2U6c2VjcmV0'),
       'Authorization: Basic ***REDACTED***',
       'Basic auth value masked');
    is(Pcurl::redact_header_line('Authorization: Bearer abc.def.ghi'),
       'Authorization: Bearer ***REDACTED***',
       'Bearer token masked');
    is(Pcurl::redact_header_line('Proxy-Authorization: Basic Zm9vOmJhcg=='),
       'Proxy-Authorization: Basic ***REDACTED***',
       'Proxy-Authorization value masked');
    is(Pcurl::redact_header_line('Host: example.com'),
       'Host: example.com',
       'non-sensitive header untouched');
};

subtest 'redact_header_line - --no-auth-redact shows raw value' => sub {
    Pcurl::simulate_cli_settings( 'no-auth-redact' => 1 );
    is(Pcurl::redact_header_line('Authorization: Basic YWxpY2U6c2VjcmV0'),
       'Authorization: Basic YWxpY2U6c2VjcmV0',
       'raw value shown when redaction disabled');
    Pcurl::simulate_cli_settings( 'no-auth-redact' => 0 );
};

# ---------------------------------------------------------------------------
subtest 'auth_string' => sub {
    my $u = { 'auth:user' => 'bob', 'auth:password' => 'pw' };
    is(Pcurl::auth_string($u), 'bob:pw@', 'user:password@ formatting');

    my $n = { };
    is(Pcurl::auth_string($n), '', 'no auth -> empty string');
};

done_testing();
