
# Helper functions stolen from linux package bash-completion

# This function quotes the argument in a way so that readline dequoting
# results in the original argument.  This is necessary for at least
# `compgen' which requires its arguments quoted/escaped:
#
#     $ ls "a'b/"
#     c
#     $ compgen -f "a'b/"       # Wrong, doesn't return output
#     $ compgen -f "a\'b/"      # Good
#     a\'b/c
#
# See also:
# - https://lists.gnu.org/archive/html/bug-bash/2009-03/msg00155.html
# - https://www.mail-archive.com/bash-completion-devel@lists.alioth.debian.org/msg01944.html
# @param $1  Argument to quote
# @param $2  Name of variable to return result to
_pcurl_quote_readline_by_ref()
{
    if [[ $1 == \'* ]]; then
        # Leave out first character
        printf -v $2 %s "${1:1}"
    else
        printf -v $2 %q "$1"
    fi

    # If result becomes quoted like this: $'string', re-evaluate in order to
    # drop the additional quoting.  See also:
    # https://www.mail-archive.com/bash-completion-devel@lists.alioth.debian.org/msg01942.html
    [[ ${!2} == \$* ]] && eval $2=${!2}
} # _pcurl_quote_readline_by_ref()

# This function shell-quotes the argument
_pcurl_quote()
{
    local quoted=${1//\'/\'\\\'\'}
    printf "'%s'" "$quoted"
}

# @see _quote_readline_by_ref()
_pcurl_quote_readline()
{
    local ret
    _pcurl_quote_readline_by_ref "$1" ret
    printf %s "$ret"
} # quote_readline()

# This function shell-dequotes the argument
_pcurl_dequote()
{
    eval printf %s "$1" 2>/dev/null
}

_pcurl_parse_options_pcurl() { :; }

_pcurl_parse_usage() { :; }

_pcurl_parse_help() {
    eval local cmd="$(_pcurl_quote "$1")"
    local line
    {
        case $cmd in
            -) cat ;;
            *) LC_ALL=C "$(_pcurl_dequote "$cmd")" ${2:---help} 2>&1 ;;
        esac
    } |
        while read -r line; do

            [[ $line == *([[:blank:]])-* ]] || continue
            # transform "-f FOO, --foo=FOO" to "-f , --foo=FOO" etc
            while [[ $line =~ \
                ((^|[^-])-[A-Za-z0-9?][[:space:]]+)\[?[A-Z0-9]+([,_-]+[A-Z0-9]+)?(\.\.+)?\]? ]]; do
                line=${line/"${BASH_REMATCH[0]}"/"${BASH_REMATCH[1]}"}
            done
            __parse_options "${line// or /, }"

        done
}

_pcurl_completion() {

    # MIME types
    # action
    
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local opt_alias="--user --data-ascii --include-response --follow --notcp-nodelay"

    case "$prev" in
        --basic | --user | --proxy-user)
            COMPREPLY=($(compgen -W 'login:password' -- "$cur"))
            return
            ;;
        --action)
            COMPREPLY=( $( compgen -W "header: bodyrx: listlinks: getlinked: getlinked-tree: json: xml: help:" -- $cur) )
            return 0
            ;;
        --accept | --content)
            # https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
            local types='text/css text/csv application/msword application/vnd.openxmlformats-officedocument.wordprocessingml.document application/epub+zip application/gzip image/gif text/html application/java-archive image/jpeg text/javascript application/json audio/mpeg video/mp4 video/mpeg application/vnd.oasis.opendocument.presentation application/vnd.oasis.opendocument.spreadsheet application/vnd.oasis.opendocument.text audio/ogg video/ogg font/otf image/png application/pdf application/x-httpd-php application/vnd.ms-powerpoint application/vnd.openxmlformats-officedocument.presentationml.presentation application/vnd.rar application/x-sh image/svg+xml application/x-tar image/tiff font/ttf text/plain audio/wav image/webp application/xhtml+xml application/vnd.ms-excel application/vnd.openxmlformats-officedocument.spreadsheetml.sheet application/xml text/xml application/zip application/x-7z-compressed'
            COMPREPLY=( $( compgen -W "$types" -- $cur) )
            return 0
            ;;
        --user-agent)
            local agents=("\"Wget/1.15 (linux-gnu)\"" "\"curl/7.35.0\"" "\"Lynx/2.8.8pre.4 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.12.23\"" "\"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\"" "\"Mozilla/5.0 (X11; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0\"" "\"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\"" "\"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0\"")
            # COMPREPLY=( $( compgen -W "$agents" -- $cur) )
            for iter in "${agents[@]}"; do
                if [[ $iter =~ ^$cur ]]; then
                    COMPREPLY+=( "$iter" )
                fi
            done
            return 0
            ;;
        --default-page)
            COMPREPLY=($(compgen -W 'index.html' -- "$cur"))
            return 0
            ;;

    esac

    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W '$opt_alias $(_pcurl_parse_help "$1")' -- ${cur}) )
        return 0 
    fi

    
} && complete -F _pcurl_completion pcurl
