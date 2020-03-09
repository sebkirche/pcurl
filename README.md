pCurl - a cURL-like implemented in Perl
=======================================

When possible, pCurl supports cURL command line arguments.

Usage
-----
    pcurl.pl [options] [url]

Options
-------
    --accept <mime type>
        Specify an accepted MIME type. This is simply a shortcut for -H
        'Accept: your/type'. Default is */*.

    --action <spec>
        Perform an action on the response. It can be the display of a value
        (from header, regex on body, json path)

    --basic <user:password>
        Use basic http authentication. Sepcified in the form user:password
        it is passed to the server in Base64 encoding.

    -b, --cookie <string or file>
        Activate cookie support and read cookie from a string like
        'NAME=Value' or a file. The file is either in 'HTTP headers format'
        or in 'Netscape cookie format'. See the Unofficial cookie FAQ
        <http://www.cookiecentral.com/faq/#3.5>. The file is never modified.
        If you want to save cookies, see --cookie-jar.

    -c, --cookie-jar <file or dash>
        Save cookies into a 'Netscape cookie format' file, or if the given
        file is '-', output the cookies into STDOUT.

    --d, --data, --data-ascii <data>
        Define some data that will be POSTed to the server. If data starts
        with '@', the rest of the string will be taken as a file name whose
        content will be send as request body. If using '-' as file name, the
        data will be read from standard input (so you can pipe it from
        another command). Note that CR+LF characters will be discarded from
        the output. See --data-binary if you need to send unaltered data.

    --data-binary <data>
        Similar to --data, but do not discard CR+LF characters. When reading
        from a file, perform binary read.

    --data-raw <data>
        Similar to --data, but do not interpret an initial '@' character.

    --data-urlencode <data>
        Similar to --data-raw, but the data will be url-encoded.

    -I, --head
        Show the document headers only. The shorthand notation for -X HEAD.

    -H, --header <header_spec>
        Send an additional header, or change / discard a default one. Usual
        syntax is -H 'header_name: value', e.g. -H 'X-my-header: some text'.
        To send several custom headers, repeat the -H parameter. If you pass
        only 'header_name:' (without value) the header will not be
        transmitted. If you need to send an empty header, use 'header_name;'
        (use semicolon).

    -h, --help
        Display a short help.

    --http09, --http10, --http11
        Specify the version of HTTP we want to use. In HTTP/0.9 the only
        method is GET <url> (without version) and the answer does not return
        headers, only the body of returned resource. In HTTP/1.0 we can use
        Host:, Connection: and additional headers. IN HTTP/1.1 the Host: is
        mandatory and if you do not specify Connection: it is kept open by
        default. We send automatically a Connection: close by default.

    -i, --include, --include-response
        Include the response headers in the output.

    --include-request
        Include the request headers in the output.

    --junk-session-cookies
        When using -b, --cookie and loading cookies from file, purge the
        session cookies (those with no expire date).

    -L, --location
        Follow HTTP redirects.

    --man
        Display the full manual.

    --max-wait <seconds>
        Specify the timeout in seconds when waiting for a response. Default
        is 10s.

    --max-redirs <number>
        Specify the maximum number of redirects to follow. Default is 50.

    --noproxy <domain_list>
        Define a coma-separated list of domains that ignore the proxy.

    -o, --output <file>
        Write to file instead of stdout.

    --port <port>
        Specify explicitly the port. If not used, we use the port from the
        url (if specified), or we will try well-known port 80 for HTTP and
        443 for HTTPS, depending on the url scheme.

    -x, --proxy <proxy_url>
        Set the url of the HTTP/1.1 proxy to use.

    --proxy10 <proxy_url>
        Set the url of the HTTP/1.0 proxy to use.

    -U, --proxy-user <user:passwd>
        Set the proxy authentication. Only Basic Auth is supported.

    -e, --referer <referer url>
        Specify a string for the referer. If followed by ";auto", when
        following redirections, reuse the previous url as referer. ";auto"
        can also be used alone with redirections.

    -X, --request <method>
        Specify the method for the request. Common methods are GET, HEAD,
        POST, PUT, TRACE, OPTIONS and DELETE, but you can specify a custom
        method. If not specified, we send a GET.

    --stompmsg <message>
        Content of the message for the STOMP message broker. Use with a
        stomp://server:port/queuename url.

    --url <url>
        Specify explicitly the url. If that parameter is not used, we try to
        get the url as the remaining text after the parameters.

    -A, --user-agent <ua string>
        Specify a string for User-Agent. If not specified the default
        User-Agent is 'pcurl v$VERSION'.

    -v, --verbose
        Show both headers during the communication.
