# -*- coding: utf-8 -*-
"""
    pygments.lexers.haproxy
    ~~~~~~~~~~~~~~~~~~~~~~~

    Lexer for HAProxy configuration files

    :copyright: Copyright 2020 by the HAProxy Technologies team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.lexer import RegexLexer, bygroups, using, words
from pygments.token import *

from pygments.lexers import _haproxy_builtins

__all__ = ['HAProxyLexer']

class HAProxyLexer(RegexLexer):
    name = 'HAProxy'
    aliases = ['haproxy', 'hapee-lb']
    filenames = ['haproxy*.cfg', 'hapee-lb*.cfg']

    tokens = {
        'root': [
            # HAProxy configuration parsing basics.
            # - A typical file is split into sections.
            # - To declare a section you need to use its keyword at the start of
            #   the line.
            # - Only sections and comments are allowed at the start of the line.
            # - Configuration keywords always start with indentation either by
            #   space or tabs or a mix of the two.

            # Based on the latest HAProxy Enterprise Configuration manual
            # https://www.haproxy.com/documentation/hapee/latest/onepage/

            # Comment that starts at the beginning of the line
            # Regex:
            # Start at the start of the line
            # Look for a #
            # Grab everything till the end of line
            (r'^#.*$', Comment.Singleline),

            # Inline comment
            # Regex:
            # Look for whitespace followed by #
            # Grab everything till the end of line
            (r'(?<=\s)#.*$', Comment.Singleline),

            # Path
            (r'(\s)(\/\S+)', bygroups(Text, String)),
            # Path at the end of the line
            (r'(\s)(\/\S+)$', bygroups(Text, String)),

            # Urls
            (r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', String),

            # Quoted strings
            (r'(\".*?\")', bygroups(String.Double)),

            # dashed options
            (r'(?<=\s)(-)(m|i)(?=\s)', bygroups(Text, Name.Attribute)),

            # Main Sections
            # RegEx:
            # Start at the start of the line
            # Look for any of the keywords (Group 1)
            # Look for whitespace - matches 0 or more (Group 2)
            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Name.Namespace, Text, Name.Variable, Text, Number, Number, Text)),
            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Name.Namespace, Text, Name.Variable, Text, Number, Number, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)([0-9]+(?:\.[0-9]+){3}|\*)(:[0-9]+)?([\t ]?)$'), bygroups(Name.Namespace, Text, Number, Number, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]+)(\S+)([\t ]?)$'), bygroups(Name.Namespace, Text, Name.Variable, Text)),

            (words(_haproxy_builtins.sections, prefix=r'^', suffix='([\t ]?)$'), bygroups(Name.Namespace, Text)),

            # Start at the start of the line
            # Look for any of the keywords (Group 1)
            # Look for whitespace - matches 0 or more (Group 2)
            # Grab everything else (Group 3)
            # (r'^(dynamic-update|fcgi-app|backend|cache|defaults|frontend|global|listen|mailers|peers|program|resolvers|ruleset|userlist|aggregations|director)(\s?)(.*)$', bygroups(Name.Namespace, Text, Name.Variable)),

            # manual fixes (order of proccessing)
            (r'^([\t ]+)(log-stderr|docroot|index)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),

            (r'^([\t ]+)(log-stderr|log)([\t ]+)(global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Keywords that take a second keyword/option
            # no option
            (words(_haproxy_builtins.no_option_keywords, prefix=r'^([\t ]+)(no)([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Keyword.Reserved, Text, Name.Attribute)),

            # option
            (words(_haproxy_builtins.option_keywords, prefix=r'^([\t ]+)(option)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # http-response
            (words(_haproxy_builtins.http_response, prefix=r'^([\t ]+)(http-response)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # http-request
            (words(_haproxy_builtins.http_request, prefix=r'^([\t ]+)(http-request)([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # tcp-check
            (r'^([\t ]+)(tcp-check)([\t ]+)(send-binary|expect|send|comment|connect)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # mailers
            (r'^([\t ]+)(mailer)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Variable)),
            (r'^([\t ]+)(mailer)', bygroups(Text, Keyword.Reserved)),
            (r'^([\t ]+)(email-alert)([\t ]+)(mailers|level|from|to)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # compression
            (r'^([\t ]+)(compression)([\t ]+)(algo|offload|type)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # stats
            (r'^([\t ]+)(stats)([\t ]+)(admin|auth|enable|hide-version|http-request|realm|refresh|scope|show-desc|show-legends|show-node|uri|socket|bind-process|timeout)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # mode
            (r'^([\t ]+)(mode)([\t ]+)(http|tcp|health)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # hold
            (r'^([\t ]+)(hold)([\t ]+)(other|refused|nx|timeout|valid|obsolete)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # timeout
            (r'^([\t ]+)(timeout)([\t ]+)(check|client-fin|client|connect|http-keep-alive|http-request|queue|server-fin|server|tarpit|tunnel)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # timeout Resolvers
            (r'^([\t ]+)(timeout)([\t ]+)(resolve|retry)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # balance
            (r'^([\t ]+)(balance)([\t ]+)(roundrobin|static-rr|leastconn|first|source|uri|queue|server-fin|server|tarpit|tunnel)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            # log
            (r'^([\t ]+)(log)([\t ]+)(stdout|stderr|global)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Literal)),
            (r'^([\t ]+)(default-server)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # max-mind
            (r'^([\t ]+)(maxmind-update)([\t ]+)(url|cache|update|show|status|force-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),
            (r'^([\t ]+)(maxmind-cache-size|maxmind-debug|maxmind-load|maxmind-update)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # net aquity
            (r'^([\t ]+)(netacuity-cache-size|netacuity-debug|netacuity-property-separator|netacuity-load|netacuity-update|netacuity-test-ipv4)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),
            # command
            (r'^([\t ]+)(command)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved)),

            #stick
            (r'^([\t ]+)(stick)([\t ]+)(match|on|store-request|store-response)(?=[\t \n\r])', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),




            # Rules for user in userlists
            # user <username> [password|insecure-password <password>] [groups <group>,<group>,(...)]

            (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s+)(groups)(\s+)(\S+)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text, Name.Attribute, Text, String )),

            (r'^([\t ]+)(user)(\s+)(\S+)(\s+)(password|insecure-password)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            # Rules for group in userlists
            # group <groupname> [users <user>,<user>,(...)]

            (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            (r'^([\t ]+)(group)(\s+)(\S+)(\s+)(users)(\s+)(\S+)(\s?)$', bygroups( Text, Keyword.Reserved, Text, String, Text, Name.Attribute, Text, String, Text )),

            # Rules for capture
            (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)([\t ]+)(len)(\s)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String, Text, Name.Function)),
            (r'^([\t ]+)(capture)([\t ]+)(cookie)([\t ]+)(\S+)', bygroups(Text, Keyword.Reserved, Text,  Name.Attribute, Text, String)),
            (r'^([\t ]+)(capture)([\t ]+)(cookie)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            (r'^([\t ]+)(capture)([\t ]+)(response|request)([\t ]+)(header)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute, Text, Name.Attribute)),

            # Rules for tcp-request
            (r'^([\t ]+)(tcp-request)([\t ]+)(connection|content|inspect-delay|session)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Rules for tcp-response
            (r'^([\t ]+)(tcp-response)([\t ]+)(content|inspect-delay)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),

            # Rules for http-check
            (r'^([\t ]+)(http-check)([\t ]+)(disable-on-404|expect|send-state|send)', bygroups(Text, Keyword.Reserved, Text, Name.Attribute)),


            # Keywords that declare a variable
            # acl, use_backend, server, default_backend, table
            # Syntax: acl <acl-name>
            (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)([a-zA-Z0-9\_\-\.\:]+)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved, Text, Name.Variable)),
            (r'^([\t ]+)(acl|use_backend|server|default_backend|table)([\t ]+)(\S+)', bygroups( Text, Keyword.Reserved, Text, Error)),

            # Keywords that take a single value typically displayed as string
            # username        user
            # groupname       group
            # path            ca-base, chroot, crt-base, deviceatlas-json-file,h1-case-adjust-file, 51degrees-data-file, wurfl-data-file
            # name            deviceatlas-properties-cookie, group, localpeer, node
            # file            lua-load, pidfile
            # dir             server-state-base
            # file            server-state-file, ssl-dh-param-file
            # text            description
            # name            mailer peer table
            # id              nameserver
            # prefix          server-template
            # name            cookie
            # name            use-fcgi-app
            (r'^([\t ]+)(user|group|ca-base|chroot|cookie|crt-base|deviceatlas-json-file|h1-case-adjust-file|51degrees-data-file|wurfl-data-file|deviceatlas-properties-cookie|group|localpeer|node|lua-load|pidfile|server-state-base|server-state-file|ssl-dh-param-file|description|mailer|peer|table|nameserver|server-template|use-fcgi-app)([\t ]+)(\S+)', bygroups( Text, Keyword.Reserved, Text, String)),

            # userlist keywords
            (r'([\t ])(groups|users)', bygroups(Text, Name.Attribute)),


            # Global Parameters
            # RegEx:
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for global keywords (Group 2)
            (words(_haproxy_builtins.global_parameters, prefix=r'^([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved)),

            # Proxies
            # List of all proxy keywords from the one page documentation
            # Regex:
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for global keywords (Group 2)
            (words(_haproxy_builtins.proxy_keywords, prefix=r'^([\t ]+)', suffix='(?=[\t \n\r])'), bygroups(Text, Keyword.Reserved)),

            # Bind options
            # Regex:
            # Look for whitespace (Group 1)
            # Look for bind option (Group 2)
            (words(_haproxy_builtins.bind_options, prefix=r'([\t ])', suffix='(?=[\t \n\r])'), bygroups(Text, Name.Attribute)),

            # Server & Default Server options
            # Regex:
            # Look for whitespace (Group 1)
            # Look for server and default server option (Group 2)
            (words(_haproxy_builtins.server_options, prefix=r'([\t ])', suffix='(?=[\t \n\r])'), bygroups(Text, Name.Attribute)),


            #manual fix
            (r'([\t ])(track-sc0|track-sc1|track-sc2)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),


            # Resolvers keywords
            # Start at the start of the line
            # Look for whitespace - matches at least 1 char or more (Group 1)
            # Look for resolvers keywords (Group 2)
            (r'^([\t ]+)(accepted_payload_size|nameserver|parse-resolv-conf|hold|resolve_retries|timeout)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),
            # Cache keywords
            (r'^([\t ]+)(total-max-size|max-object-size|max-age)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),
            # ACL
            # ACL Matches
            # ACL Converters
            # ACL Fetches
            # ACL Predefined
            # Filters
            # Fast CGI
            (r'^([\t ]+)(path-info)(?=[\t \n\r])', bygroups( Text, Keyword.Reserved)),

            # functions
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(\S+)(\s+)(})', bygroups(Text, Name.Function, Text, String, Text, Text)),
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(\s+)(.+)$', bygroups(Text, Name.Function, Text, String)),
            (r'([\t ])(path_beg|path_dir|path_dom|path_end|path_len|path_reg|path_sub|path)(?=[\t \n\r])', bygroups(Text, Name.Function)),
            (r'([\t ])(addr)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'([\t ])(verify|none|crt|tfo|check-ssl|check|alpn)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'([\t ])(accept-netscaler-cip|accept-proxy|allow-0rtt|alpn|backlog|ca-file|ca-ignore-err|ca-sign-file|ca-sign-pass|ciphers|ciphersuites|crl-file|crt|crt-ignore-err|crt-list|curves|defer-accept|ecdhe|expose-fd listeners|force-sslv3|force-tlsv10|force-tlsv11|force-tlsv12|force-tlsv13|generate-certificates|gid|group|id|interface|level|maxconn|mode|mss|namespace|name|nice|no-ca-names|no-sslv3|no-tls-tickets|no-tlsv10|no-tlsv11|no-tlsv12|no-tlsv13|npn|prefer-client-ciphers|process|proto|severity-output|ssl-max-ver|ssl-min-ver|ssl_fc|ssl|strict-sni|tcp-ut|tfo|tls-ticket-keys|transparent|uid|user|v4v6|v6only|verify)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'(\s)(location|scheme|prefix|random)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),
            (r'(\,|[\t ])(type|string|size|store|http_req_rate|http_req_cnt)(?=[\t \n\r])', bygroups(Text, Name.Function)),

            (r'([\t ])(SSLv3|TLSv1.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)(?=[\t \n\r])', bygroups(Text, Literal)),
            (r'([\t ])(conn-failure|empty-response|junk-response|response-timeout|0rtt-rejected|except|nbsrv)(?=[\t \n\r])', bygroups(Text, Name.Attribute)),

            # stick table functions
            (r'(\,|[\t ])(gpc0|gpc1|conn_cnt|conn_cur|sess_cnt|http_req_cnt|http_err_cnt|bytes_in_cnt|bytes_out_cnt)(?=[\t \n\r])', bygroups(Text, Name.Function)),
            (r'(\,|[\t ])(gpc0_rate|gpc1_rate|conn_rate|sess_rate|http_req_rate|http_err_rate|bytes_in_rate|bytes_out_rate)([\(|\s])', bygroups(Text, Name.Function, Text)),

            # Converter functions
            (words(_haproxy_builtins.converter_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Converters
            (words(_haproxy_builtins.converters, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetches internal states functions
            (words(_haproxy_builtins.internal_states_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetches internal states
            (words(_haproxy_builtins.internal_states_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 4 functions
            (words(_haproxy_builtins.l4_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetching samples at Layer 4
            (words(_haproxy_builtins.l4_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples at Layer 5 functions
            (words(_haproxy_builtins.l5_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetching samples at Layer 5
            (words(_haproxy_builtins.l5_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples from buffer contents (Layer 6) functions
            (words(_haproxy_builtins.l6_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetching samples from buffer contents (Layer 6)
            (words(_haproxy_builtins.l6_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching HTTP samples (Layer 7) functions
            (words(_haproxy_builtins.l7_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetching HTTP samples (Layer 7)
            (words(_haproxy_builtins.l7_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # Fetching samples for developers Functions
            (words(_haproxy_builtins.dev_samples_fetch_functions, prefix=r'(\,|[\t ])', suffix='([\(|\s])'), bygroups(Text, Name.Function, Text)),

            # Fetching samples for developers
            (words(_haproxy_builtins.dev_samples_fetches, prefix=r'(\,|[\t ])', suffix='(?=[\t \n\r]|\,)'), bygroups(Text, Name.Function)),

            # ACL Predefined functions
            (r'(\,|[\t ])(FALSE|HTTP_1\.0|HTTP_1\.1|HTTP_CONTENT|HTTP_URL_ABS|HTTP_URL_SLASH|HTTP_URL_STAR|HTTP|LOCALHOST|METH_CONNECT|METH_DELETE|METH_GET|METH_HEAD|METH_OPTIONS|METH_POST|METH_PUT|METH_TRACE|RDP_COOKIE|REQ_CONTENT|TRUE|WAIT_END)(?=[\t \n\r]|\,)', bygroups(Text, Name.Attribute)),

            # ACL conditionals
            (r'(\s)(if|unless)(\s+)([a-zA-Z0-9_-]+|!\s?[a-zA-Z0-9_-]+)', bygroups(Text, Operator.Word, Text, Name.Variable)),
            (r'\b(if|unless)\b', Operator.Word),
            # Logical operators
            (r'(\s+)(lt|gt|or|\|\||!)', bygroups(Text, Operator.Word)),

            # Numbers
            # also optional letter supported, like '100s'
            (r'(\s)([0-9]+)(?=[\t \n])', bygroups(Text, Number)),
            (r'(\s)([0-9]+)(ms|s|m|h|w|y)', bygroups(Text, Number, Number)),
            # IP address/subnet
            # ([\t ]|,)[0-9]+(?:\.[0-9]+){3}(\/[0-9]+)?
            (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(\/[0-9]+)?', bygroups(Text, Number, Number)),
            # IP address:port
            (r'([\t ]|,)([0-9]+(?:\.[0-9]+){3})(:[0-9]+)?', bygroups(Text, Number, Number)),

            # Ports only
            (r'([\.:][0-9]+)', Number),
            # Remaining text
            (r'.', Text)
        ]
    }
