# bash completion for udp-broadcast-relay-redux
_udp_broadcast_relay-redux_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    case "$prev" in
        --lang) COMPREPLY=( $(compgen -W "en zh" -- "$cur") ); return ;;
        --log) COMPREPLY=( $(compgen -W "stderr syslog file=" -- "$cur") ); return ;;
        --dev) COMPREPLY=( $(compgen -S '' -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ); return ;;
        --multicast) COMPREPLY=(); return ;;
        -s|-t) COMPREPLY=(); return ;;
        --id|--port) COMPREPLY=(); return ;;
    esac
    case "$cur" in
        -*) COMPREPLY=( $(compgen -W "-d -f -s -t --id --port --dev --multicast --lang --log --ipv6 --list-interfaces -h --help --version" -- "$cur") ) ;;
        *) COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ) ;;
    esac
}
complete -F _udp_broadcast_relay-redux_completions udp-broadcast-relay-redux
