
pCurl - a cURL-like implemented in Perl
=======================================

pCurl goal is to provide a self-contain Perl curl-like tool capable of making http(s) requests, doing some recursive web hovering (similar to `wget --recursive`) and parse JSON and XML results without the need for additional tools or Perl packages (I am cheating for https by calling `openSSL s_client` for tunnelling).

I support the following protocols:
* `http:` and `https:` with all GET, HEAD, POST, PUT, TRACE, OPTIONS, DELETE or other custom actions
* http will try to honor 0.9, 1.0 and 1.1 versions if required (default is 1.0)
* `file:`
* `stomp:` pseudo protocol: we can make limited STOMP SENDs, initial intent was to push notifications to ApacheMQ

pCurl has its own recursive descent (extended regex based) JSON parser and an embedded XML::TreePP parser, and can returned processed outputs (called result actions, see below) based on:
* regular expression on the data returned
* values of the response headers
* single values or subsets of a JSON response (with builtin jsonification); parsing of a local file is supported with `file:` protocol
* basic web crawling feature

I am planning to implement a limited set of decision structures (`if`, `case`) capable to define a return value based on a header or a JSON value, or to perform polling until a defined failure or success condition.

Perl limited dependencies are:

* Data::Dumper
* Getopt::Long
* IO::Select, IO::Socket::INET and Socket
* IPC::Open3 (to call openSSL and pipe its IO on our STDIN and STDOUT)
* MIME::Base64
* Pod::Usage
* Time::Local
* locally system available openSSL

pCurl tries to supports (a small subset of) cURL command line parameters, cookies, additional parameters as shortcuts to standard curl parameters like 

* `--content foo` as synonym for `-H "Content-Type: foo"`
* `--accept bar` as synonym for `-H "Accept: bar"`

and some of wget parameters for recursive crawling like `--recursive`, `--page-requisite`, `--level`, `--cut-dirs`, `--no-parent`, `--no-host-dirs`... I am doing casual web page archiving and I found convenient to add my most used features of wget im my tool.

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

    --action-nullable-values
        If set an action can return null values, else it fails if the result
        cannot find a value.

    --action-res-delimiter
        Set the delimiter for action results. Default is ','.

    --basic <user:password>
    --user  <user:password>
        Use basic http authentication. Specified in the form user:password
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

    --http09 | --http0.9, --http10 | --http1.0 | -0, --http11 | --http1.1
        Specify the version of HTTP we want to use. In HTTP/0.9 the only
        method is GET <url> (without version) and the answer does not return
        headers, only the body of returned resource. In HTTP/1.0 we can use
        Host:, Connection: and additional headers. IN HTTP/1.1 the Host: is
        mandatory and if you do not specify Connection: it is kept open by
        default. We send automatically a Connection: close by default.
        Default is HTTP/1.1

        Note that pcurl supports curl parameters --http0.9, --http1.0 and
        http1.1 if only you have Getopt::Long >= 2.39

    -i, --include, --include-response
        Include the response headers in the output.

    --include-request
        Include the request headers in the output.

    -k, --insecure
        Accept insecure https connections (mostly curl option compatibility)

    --json <data>
        Shortcut to POST the specified json data and automatically set the
        Content-Type: and Accept: headers. This is equivalent to

            --request POST  (implicit with --data)
            --data <arg>
            --header "Content-Type: application/json"  or --content application/json
            --header "Accept: application/json"        or --accept application/json

    --json-pp
        When using a json action (see --action), pretty-print the json.

    --json-pp-indent
        When using --json-pp-indent, number of space characters to use for
        each level of indentation (default = 2).

    --json-stringify-null
        When parsing json, replace null values by the string 'null'

    --junk-session-cookies
        When using -b, --cookie and loading cookies from file, purge the
        session cookies (those with no expire date).

    -L, --location, --follow
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

    --octet-stream
        Shortcut for "--content octet-stream", will result in a
        "Content-Type: octet-stream" header.

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

    -J, --remote-header-name
        With -O --remote-name, use the name provided by Content-disposition:
        filename instead of URL.

    -O, --remote-name
        Write output to a file named as the remote file (that name is
        extracted from the URL).

    -R, --remote-time
        Set the remote file's time on the local output, if provided by
        Last-Modified response header.

    -X, --request <method>
        Specify the method for the request. Common methods are GET, HEAD,
        POST, PUT, TRACE, OPTIONS and DELETE, but you can specify a custom
        method. If not specified, we send a GET.

    -s, --silent
        Silent mode - argument compatibility w/ curl, pcurl is silent by default

    -3, --sslv3
        Force the usage of SSL v3 for openSSL tunneling

    --stompmsg <message>
        Content of the message for the STOMP message broker. Use with a
        stomp://server:port/queuename url.

    --tcp-nodelay, --notcp-nodelay
        Disable the Nagle's algorithm for TCP communication (do not wait for
        a previous ACK before sending data if small amount of data)

    -1, --tlsv1_0, --tlsv1
        Force the usage of TLS v1.0 for openSSL tunneling

    --tlsv1_1
        Force the usage of TLS v1.1 for openSSL tunneling

    --tlsv1_2
        Force the usage of TLS v1.2 for openSSL tunneling

    --tlsv1_3
        Force the usage of TLS v1.3 for openSSL tunneling

    -T, --upload-file <filename>
        Allow to upload a file using the PUT method.

    --url <url>
        Specify explicitly the url. If that parameter is not used, we try to
        get the url as the remaining text after the parameters.

    -A, --user-agent <ua string>
        Specify a string for User-Agent. If not specified the default
        User-Agent is 'pcurl v$VERSION'.

    -v, --verbose
        Show both headers during the communication.

    -V, --version
        Show version number and quit.

    --xml-pp
        When using an xml action (see --action), pretty-print the xml.
        Default is not indented.

    --xml-pp-indent <number_of_spaces>
        Number of space characters for each indentation level. Default is 2

    --xml-root-element <name>
        Use the given name for the root element of XML.

Web crawling features:

    In web-crawling mode, a first resource is retrieved then in a recursive
    way, all related resources (linked html, pictures, css) are also
    retrieved.

    By default a number of 5 successive jumps from initial url are
    processed. All the files are stored under a common directory named after
    the host.

    --accept-list <coma-separated list>
        Specify a list of accepted file extensions

    --accept-regex <pattern>
        Specify a pattern that will be validated to accept urls

    --cut-dirs <number of levels>
        Specify a number of path levels to remove from all links.

    --directory-prefix <common path>
        Specify a path to prepend for all retrieved resources.

    --default-page <file name>
        Specify the name of the index file when directory browsing is
        allowed by the server. Default is 'index.html'

    -l, --level <number>
        Specify the maximum number of jump to explore from initial url.
        Default is 5. 0 is equivalent to 'get all site'.

    --no-host-directories
        Allow to disable the creation of a common ancestor named after the
        host name for all retrieved resources.

    --np, --no-parent
        Prevent the crawling to go back to the parent of the given url.

    --page-requisites
        Will help to get linked resources (pictures, css) even if stored in
        a higher directory than resource.

    -r, --recursive
        Use the web-crawling mode: get as many linked resources as possible.

    --recursive-flat
        Disable the creation of directories, all related resources will be
        stored in the same directory.

    --relative
        Tell that you want to take into account only relative links.

    --reject-list <coma-separated list>
        Specify a list of ignored file extensions

    --reject-regex <pattern>
        Specify a pattern that will be validated to ignore urls

    --span-hosts
        Allow to process resources from external web sites. Beware if you
        set also --level 0: you will download the whole Internet! ;o)

    --summary
        Ask for a final list of retrieved resources, if you do not want to
        see other details.

  Examples:
    parse an URI to show its components
            pcurl https://mylogin:mypwd@subdomain.domain.com:1234/some/path/to/resource --parse-only

    list linked resources on a page
            pcurl https://domain.org/some/path/to/page.html --action listlinks:

    Get a page and all its direct linked resources (without going up to
    parent)
            pcurl -ORL --recursive --no-parent --page-requisites --no-host-directories --level 1 --recursive-flat --cut-dirs 2  --progression https://path

Actions
-------

To simplify some post-processing on the retrieved resources, you can specify an action to be performed on the result.
Action can be of type:

* print: display a response header value (multiple values supported, separated by comas), a json or xml response attribute
    * you can specify a pseudo path similar to xpath
    * there is a limited set of functions that you can use as the last element of path:
        * `length()` returns the number of element of an array, or the number of keys for a an object
        * `to_json()` converts the result to JSON
        * `to_xml()` converts the result to XML
    * `pcurl --action=header:server http://free.fr` => `nginx`
    * `pcurl https://jsonplaceholder.typicode.com/users/1 --action='json:id'` => `1`
    * `pcurl http://jsonplaceholder.typicode.com/users --action='json:[3]/address/geo'` => `{"lng":-164.299,"lat":29.4572}`
    * `pcurl http://jsonplaceholder.typicode.com/users --action='json:[3]/address/geo/lat'` => `29.4572`
    * `pcurl https://www.w3schools.com/xml/simple.xml --action 'xml:breakfast_menu/food/length()'` => `5`
    * note: 
        * for arrays:
            * `foo/[42]` is equivalent to `foo[42]`
            * `foo[]` is equivalent to `foo[*]`
            * you can access a single array element `[42]`, a range `[2..12]` or an index list `[1,3,19]`
        * for objects:
            * you can access a single key with `/key`
            * or construct a new object from a list of existing object key `/attrX,attrY,attrZ`
            example: `pcurl https://jsonplaceholder.typicode.com/users/ --action='json:[]/id,username' --json-pp`
    

* regex: display the match of a regex on the response body
    * `pcurl http://jsonplaceholder.typicode.com/ --action='bodyrx:Free.*\.'` => `Free fake API for testing and prototyping.`

* spider: show some useful infos when grabbing page contents
    * `pcurl http://some.host.com/some/path/ --action 'listlinks:\.pdf$'`
    * `pcurl http://some.host.com/some/path/ --action 'getlinked:^[^?].*[^/]$'` => get all linked files but directories and sort links
    * `pcurl http://some.host.com/some/path/ --action 'getlinked-tree:^[^?].*[^/]$' -R` => get all linked files but directories and sort links, keep the directory structure and file times
    * see also the `--recursive` parameter
    
Return codes
------------

*  0 : No error.
*  1 : no URL / wrong URL (does not parse the URL syntax).
*  2 : unknown option.
*  3 : url stomp:// without --stompmsg or --stompread parameter.
*  4 : no URL / wrong URL for proxy (does not parse the URL syntax).
*  5 : HTTP CONNECT failed for tunnel.
*  6 : cannot access the file via file: protocol.
*  7 : cannot get remote file name from url.
*  8 : cannot parse result as JSON for action.
*  9 : cannot parse result as XML for action.
* 10 : Write error. Cannot write output.
* 11 : http returned a temporary failure 4xx.
* 12 : http returned a permanent failure 5xx.
* 13 : STOMP issue.
* 14 : unknown scheme

