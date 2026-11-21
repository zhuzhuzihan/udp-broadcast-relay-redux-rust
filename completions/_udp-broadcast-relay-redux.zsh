#compdef udp-broadcast-relay-redux
# zsh completion for udp-broadcast-relay-redux
_udp_broadcast_relay-redux() {
    _arguments -S \
        '(-d)'{-d}'[enable debugging output]' \
        '(-f)'{-f}'[fork to background]' \
        '(-s)'{-s+}'[set source IP of forwarded packets]:ip:' \
        '(-t)'{-t+}'[set destination IP of forwarded packets]:ip:' \
        '--id[instance id (1-99)]:id:' \
        '--port[UDP port to listen on]:port:' \
        '--dev[interface to manage (repeatable)]:interface:_net_interfaces' \
        '--multicast[multicast group to join (repeatable)]:group:' \
        '--lang[user-facing message language]:language:(en zh)' \
        '--log[error/log channel]:target:(stderr syslog)' \
        '--ipv6[also relay IPv6 multicast]' \
        '--list-interfaces[enumerate interfaces and exit]' \
        '(-h --help)'{-h,--help}'[show help and exit]' \
        '--version[show version and exit]'
}
_udp_broadcast_relay-redux "$@"
