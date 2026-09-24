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

subtest 'parse_uri - percent-encoded and unicode paths' => sub {
    # standard percent-encoding (hex letters) must be accepted
    my $p = Pcurl::parse_uri('http://example.com/a%2Fb%3Dc');
    ok($p, 'parsed url with %XX hex escapes');
    is($p->{path}, '/a%2Fb%3Dc', 'percent-encoded path preserved');

    # non-standard %uXXXX form must be accepted in the path
    my $u = Pcurl::parse_uri('http://example.com/path/%u00e9dir/file');
    ok($u, 'parsed url with %uXXXX escape');
    is($u->{path}, '/path/%u00e9dir/file', '%uXXXX path preserved');

    # raw UTF-8 bytes in the path must be accepted (byte-oriented input)
    no utf8;
    my $r = Pcurl::parse_uri("http://example.com/caf\xC3\xA9/x");
    ok($r, 'parsed url with raw UTF-8 bytes in path');

    # a query with a percent-encoded value still parses
    my $q = Pcurl::parse_uri('http://example.com/s?q=%25BACKUP%25');
    ok($q, 'parsed url with percent-encoded query');
    is($q->{query}, 'q=%25BACKUP%25', 'query preserved');
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

subtest 'urldecode - hex escapes with letters (regression: not just digits)' => sub {
    # Historical bug guard: %XX must decode hex letters A-F, not only digits.
    is(Pcurl::urldecode('a%2Fb'),   'a/b',  '%2F (letter F) decodes to /');
    is(Pcurl::urldecode('x%3Dy'),   'x=y',  '%3D decodes to =');
    is(Pcurl::urldecode('%2C'),     ',',    '%2C decodes to ,');
    is(Pcurl::urldecode('%20'),     ' ',    '%20 decodes to space');
};

subtest 'urldecode - UTF-8 percent-encoding' => sub {
    is(Pcurl::urldecode('caf%C3%A9'),  "caf\x{e9}", 'UTF-8 2-byte (é) decodes to a character');
    is(Pcurl::urldecode('%E2%82%AC'),  "\x{20ac}",  'UTF-8 3-byte (€) decodes to a character');
    # invalid UTF-8 must not crash: falls back to the raw byte string
    my $bad = Pcurl::urldecode('%FF%FE');
    ok(defined $bad, 'invalid UTF-8 sequence does not die');
};

subtest 'urldecode - non-standard %uXXXX form' => sub {
    is(Pcurl::urldecode('%u00e9'),        "\x{e9}",   '%u00e9 -> é');
    is(Pcurl::urldecode('%u20AC'),        "\x{20ac}", '%u20AC -> € (uppercase hex)');
    is(Pcurl::urldecode('a%u0041b'),      'aAb',      '%uXXXX embedded in ASCII');
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
    # segment-wise, so prefix look-alikes are not descendants
    ok(!Pcurl::is_descendant_or_equal('/dirty/x', '/dir'), 'prefix look-alike is not descendant');
};

subtest 'no_parent_boundary - directory vs file heuristic (M1)' => sub {
    # trailing slash: kept as-is
    is(Pcurl::no_parent_boundary('/dir/'),        '/dir/',  'trailing-slash path kept');
    # slash-less directory-looking path: treated as a directory (bug fix -
    # previously collapsed to "/", making --no-parent a no-op)
    is(Pcurl::no_parent_boundary('/dir'),         '/dir/',  'slash-less dir path becomes /dir/');
    # file-looking last segment (has a dot): boundary is the parent directory
    is(Pcurl::no_parent_boundary('/dir/page.html'), '/dir/', 'file path -> parent directory');
    is(Pcurl::no_parent_boundary('/a/b.html'),    '/a/',    'nested file -> parent directory');
    # root
    is(Pcurl::no_parent_boundary('/'),            '/',      'root stays root');
};

subtest 'no-parent boundary + descendant check (M1 end-to-end)' => sub {
    my $check = sub {
        my ($page, $link) = @_;
        my $b = Pcurl::no_parent_boundary($page);
        return Pcurl::is_descendant_or_equal(Pcurl::canonicalize($link), $b) ? 1 : 0;
    };
    # the regression: a slash-less directory page must still constrain siblings
    is($check->('/dir', '/dir/x'), 1, 'child allowed under slash-less dir page');
    is($check->('/dir', '/other'), 0, 'sibling BLOCKED under slash-less dir page (was the bug)');
    # unchanged good behavior
    is($check->('/dir/page.html', '/dir/other'), 1, 'sibling file allowed');
    is($check->('/dir/page.html', '/x.html'),    0, 'parent blocked');
    is($check->('/dir/', '/dirty/x'),            0, 'prefix look-alike blocked');
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

subtest 'JSON parser - tolerates a leading UTF-8 BOM' => sub {
    # A raw (octet) UTF-8 BOM prefixing the body must not break parsing.
    my $bom = "\xEF\xBB\xBF";
    my $o = Pcurl::from_json("$bom\[{\"a\":1},{\"b\":2}]");
    is_deeply($o, [ { a => 1 }, { b => 2 } ], 'BOM-prefixed array parses correctly');

    my $obj = Pcurl::from_json("$bom\{\"k\":\"v\"}");
    is_deeply($obj, { k => 'v' }, 'BOM-prefixed object parses correctly');

    # And normal (no-BOM) JSON still works.
    is_deeply(Pcurl::from_json('[1,2,3]'), [1,2,3], 'no-BOM array still parses');
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

subtest 'to_json - strings containing true/false stay quoted (regression A)' => sub {
    # A substring "true"/"false" must NOT become a bare JSON literal.
    is(Pcurl::to_json('construe'),        '"construe"',        'string containing "true" is quoted');
    is(Pcurl::to_json('falsely'),         '"falsely"',         'string containing "false" is quoted');
    is(Pcurl::to_json('untrue statement'),'"untrue statement"','embedded "true" is quoted');
    # exact 'true'/'false' remain JSON boolean literals
    is(Pcurl::to_json('true'),            'true',              'exact true is a literal');
    is(Pcurl::to_json('false'),           'false',             'exact false is a literal');
};

subtest 'to_json - numeric-looking strings are not mangled by eval (regression B)' => sub {
    # Valid JSON numbers are emitted bare.
    is(Pcurl::to_json(42),        42,        'integer stays bare');
    is(Pcurl::to_json(-7),        -7,        'negative integer stays bare');
    is(Pcurl::to_json('0'),       '0',       'zero stays bare');
    is(Pcurl::to_json('3.14'),    '3.14',    'float stays bare');
    is(Pcurl::to_json('-1.5e3'),  '-1.5e3',  'exponent stays bare');
    # Leading-zero forms are NOT valid JSON numbers: must be quoted, not eval'd to 7.
    is(Pcurl::to_json('007'),     '"007"',   'leading-zero string is quoted, not renormalized');
    is(Pcurl::to_json('0755'),    '"0755"',  'octal-looking string is quoted');
    # The resulting document must be valid JSON (reparses).
    my $doc = Pcurl::to_json({ zip => '007', n => 42 });
    ok(defined Pcurl::from_json($doc), 'output with quoted 007 reparses as valid JSON');
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
subtest 'reset_state - clears session accumulators between runs' => sub {
    # Seed some args and run something that populates accumulator state.
    Pcurl::simulate_cli_settings( 'header' => [], 'user-agent' => 'pCurl-test' );

    # A broken URL populates %broken_url via process_loop (no network needed
    # because validate_uri fails first and recursive mode continues).
    Pcurl::simulate_cli_settings( 'recursive' => 1 );
    Pcurl::process_loop([ 'this is not a uri' ], 0);
    # After a run there should be some recorded state; reset must clear it.

    Pcurl::reset_state();

    # reset_state does not clear %args by default, so user-agent survives.
    my $u = { scheme=>'http', host=>'example.com', port=>80, path=>'/' };
    my $h = Pcurl::build_http_request_headers('GET', $u, undef, undef);
    ok((grep { /^User-Agent: pCurl-test$/ } @$h),
       'reset_state() preserves %args by default');

    # reset_state(1) restores %args defaults (user-agent back to pCurl/<version>)
    Pcurl::reset_state(1);
    my $h2 = Pcurl::build_http_request_headers('GET', $u, undef, undef);
    ok((grep { m{^User-Agent: pCurl/} } @$h2),
       'reset_state(1) restores default %args');

    # restore test defaults for subsequent subtests, clearing the recursive flag
    Pcurl::simulate_cli_settings( 'header' => [], 'user-agent' => 'pCurl-test', 'recursive' => 0 );
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
subtest 'local_path_for - local file path derivation' => sub {
    my $mk = sub {
        my $u = Pcurl::parse_uri($_[0]);
        Pcurl::complete_url_default_values($u);
        return $u;
    };

    # --output takes precedence
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings('output'=>'out.bin', 'recursive'=>0, 'remote-name'=>0, header=>[]);
    is(Pcurl::local_path_for($mk->('http://example.com/a/b.html')), 'out.bin',
       '--output wins');

    # remote-name style: filename from url path
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings('output'=>undef, 'recursive'=>0, 'remote-name'=>1, header=>[]);
    is(Pcurl::local_path_for($mk->('http://example.com/dir/file.txt')), 'file.txt',
       'filename derived from url path');

    # recursive with host directories
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings('output'=>undef, 'recursive'=>1, 'no-host-directories'=>0, header=>[]);
    is(Pcurl::local_path_for($mk->('http://example.com/dir/file.txt')),
       'example.com/dir/file.txt',
       'recursive keeps host dir + full path');

    # recursive, no host directories
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings('output'=>undef, 'recursive'=>1, 'no-host-directories'=>1, header=>[]);
    is(Pcurl::local_path_for($mk->('http://example.com/dir/file.txt')),
       'dir/file.txt',
       '--no-host-directories drops the host dir');

    Pcurl::reset_state();
    Pcurl::simulate_cli_settings(header=>[], 'user-agent'=>'pCurl-test');
};

subtest 'is_up_to_date - timestamping freshness predicate' => sub {
    # RFC 1123 date helper -> the format str2epoch understands
    my @dow = qw(Sun Mon Tue Wed Thu Fri Sat);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $httpdate = sub {
        my @t = gmtime($_[0]);
        sprintf('%s, %02d %s %04d %02d:%02d:%02d GMT',
                $dow[$t[6]], $t[3], $mon[$t[4]], $t[5]+1900, $t[2], $t[1], $t[0]);
    };

    my ($fh, $path) = tempfile(UNLINK => 1);
    print $fh 'hello';           # 5 bytes
    close $fh;
    my $mtime = 1_000_000_000;   # fixed local mtime
    utime($mtime, $mtime, $path);
    my $local_size = (stat $path)[7];

    # server not newer, size unknown -> up to date (skip)
    ok( Pcurl::is_up_to_date($path, { 'last-modified' => $httpdate->($mtime) }),
        'not-newer + no size => up to date');

    # server not newer, size equal -> up to date
    ok( Pcurl::is_up_to_date($path, { 'last-modified' => $httpdate->($mtime - 10),
                                      'content-length' => $local_size }),
        'older + matching size => up to date');

    # server not newer, size differs -> must fetch
    ok(!Pcurl::is_up_to_date($path, { 'last-modified' => $httpdate->($mtime),
                                      'content-length' => $local_size + 1 }),
        'same mtime but different size => fetch');

    # server newer -> must fetch
    ok(!Pcurl::is_up_to_date($path, { 'last-modified' => $httpdate->($mtime + 60) }),
        'server newer => fetch');

    # missing Last-Modified -> fetch (fail open)
    ok(!Pcurl::is_up_to_date($path, { 'content-length' => $local_size }),
        'missing Last-Modified => fetch');

    # unparseable Last-Modified -> fetch
    ok(!Pcurl::is_up_to_date($path, { 'last-modified' => 'not a date' }),
        'unparseable Last-Modified => fetch');

    # non-integer / multi-valued Content-Length is ignored (decide on mtime)
    ok( Pcurl::is_up_to_date($path, { 'last-modified' => $httpdate->($mtime),
                                      'content-length' => "$local_size, $local_size" }),
        'duplicated content-length ignored => decide on timestamp (skip)');

    # missing local file -> fetch
    ok(!Pcurl::is_up_to_date('/no/such/file/here', { 'last-modified' => $httpdate->($mtime) }),
        'missing local file => fetch');
};

subtest 'discover_links - --page-requisites exempts parent-dir requisites (M4)' => sub {
    # page in /dir/sub/; references parent-dir requisites (one relative, one as a
    # same-host absolute URL that gets rewritten) plus a plain parent <a> link.
    my $html = join('',
        '<img src="../logo.png">',                          # requisite (relative)
        '<link href="http://example.com/dir/style.css">',   # requisite (absolute url -> rewritten)
        '<a href="../other.html">up</a>',                   # plain link, parent dir
    );
    my $mk = sub {
        my $u = Pcurl::parse_uri('http://example.com/dir/sub/page.html');
        Pcurl::complete_url_default_values($u);
        return $u;
    };

    # explicitly set every crawler flag this test depends on, since reset_state()
    # does not clear %args and earlier subtests may have left flags set
    my @crawl_flags = ('relative'=>0, 'span-hosts'=>0, 'no-parent'=>1, 'header'=>[]);

    # --no-parent, no --page-requisites: everything above the dir is blocked
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings(@crawl_flags, 'page-requisites'=>0);
    my @blocked = Pcurl::discover_links({captured=>\$html}, $mk->(), undef, undef, 1);
    is(scalar @blocked, 0, 'without --page-requisites, parent items are blocked by --no-parent');

    # --no-parent + --page-requisites: the two requisites survive (incl. the
    # rewritten absolute-URL one), the plain link stays blocked
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings(@crawl_flags, 'page-requisites'=>1);
    my @kept_unsorted = Pcurl::discover_links({captured=>\$html}, $mk->(), undef, undef, 1);
    my @kept = sort @kept_unsorted;
    is_deeply(\@kept,
              [ 'http://example.com/dir/logo.png', 'http://example.com/dir/style.css' ],
              'requisites in parent dir kept (incl. rewritten absolute URL); plain link blocked');

    Pcurl::reset_state();
    Pcurl::simulate_cli_settings('no-parent'=>0, 'page-requisites'=>0, 'header'=>[], 'user-agent'=>'pCurl-test');
};

subtest 'discover_links - --relative keeps only relative links (M2)' => sub {
    my $html = join('',
        '<a href="sub/rel.html">rel</a>',
        '<a href="../up.html">rel-dotdot</a>',
        '<a href="/abs/path.html">abs-path</a>',
        '<a href="http://example.com/other.html">abs-url-samehost</a>',
        '<a href="http://other.example.org/x.html">abs-url-offhost</a>',
    );
    my $mk_url = sub {
        my $u = Pcurl::parse_uri('http://example.com/dir/page.html');
        Pcurl::complete_url_default_values($u);
        return $u;
    };

    for my $keep_tree (0, 1){
        Pcurl::reset_state();
        Pcurl::simulate_cli_settings(
            'relative' => 1, 'span-hosts' => 1, 'no-parent' => 0, 'header' => [] );
        my $resp = { captured => \$html };
        my @rel = Pcurl::discover_links($resp, $mk_url->(), undef, undef, $keep_tree);
        my @rel_sorted = sort @rel;
        is_deeply(\@rel_sorted,
                  [ 'http://example.com/dir/sub/rel.html', 'http://example.com/up.html' ],
                  "keep_tree=$keep_tree: only the two relative links kept");
    }

    # sanity: without --relative all five are discovered
    Pcurl::reset_state();
    Pcurl::simulate_cli_settings(
        'relative' => 0, 'span-hosts' => 1, 'no-parent' => 0, 'header' => [] );
    my $resp = { captured => \$html };
    my @all = Pcurl::discover_links($resp, $mk_url->(), undef, undef, 1);
    is(scalar @all, 5, 'without --relative, all links (incl. absolute) discovered');

    Pcurl::reset_state();
    Pcurl::simulate_cli_settings( 'relative' => 0, 'span-hosts' => 0, 'header' => [], 'user-agent' => 'pCurl-test' );
};

subtest 'canonical_url - equivalent URLs map to one dedup key (H3)' => sub {
    my $key = sub {
        my $u = Pcurl::parse_uri($_[0]);
        Pcurl::complete_url_default_values($u);
        return Pcurl::canonical_url($u);
    };
    # default port present/absent collapse
    is($key->('http://example.com/a/b'), $key->('http://example.com:80/a/b'),
       'http default port 80 is normalized away');
    is($key->('https://example.com/x'), $key->('https://example.com:443/x'),
       'https default port 443 is normalized away');
    # dot-segments collapse
    is($key->('http://example.com/a/./b'), $key->('http://example.com/a/b'),
       'single-dot segment normalized');
    is($key->('http://example.com/a/../c'), $key->('http://example.com/c'),
       'double-dot segment normalized');
    # a non-default port is preserved and distinguishes the key
    isnt($key->('http://example.com:8080/a'), $key->('http://example.com/a'),
       'non-default port kept distinct');
    # userinfo is included in the canonical form
    like($key->('http://alice:secret@example.com/p'), qr{alice:secret\@example\.com},
       'userinfo preserved in canonical url');

    # path override (as used by discover_links for a discovered link)
    my $u = Pcurl::parse_uri('http://example.com/dir/page');
    Pcurl::complete_url_default_values($u);
    is(Pcurl::canonical_url($u, '/other/res'), 'http://example.com/other/res',
       'path override builds the discovered-link url');
};

subtest 'auth_string' => sub {
    # uses the nested {auth}{user}/{password} shape produced by parse_uri
    my $u = { auth => { user => 'bob', password => 'pw' } };
    is(Pcurl::auth_string($u), 'bob:pw@', 'user:password@ formatting');

    my $user_only = { auth => { user => 'bob' } };
    is(Pcurl::auth_string($user_only), 'bob@', 'user-only -> user@');

    my $n = { };
    is(Pcurl::auth_string($n), '', 'no auth -> empty string');

    # regression: must read from a real parse_uri result, not flat keys
    my $parsed = Pcurl::parse_uri('http://alice:secret@example.com/p');
    is(Pcurl::auth_string($parsed), 'alice:secret@', 'works on a parse_uri() result (H1 regression)');
};

done_testing();
