_trace_cmd_complete()
{
    local sub_cmd_list
    sub_cmd_list=$(trace-cmd --help 2>/dev/null | \
                          grep " - " | sed 's/^ *//; s/ -.*//')
    COMPREPLY=()
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cur="${COMP_WORDS[COMP_CWORD]}"
    if [[ "$prev" == "trace-cmd" ]]; then
        COMPREPLY=( $(compgen -W "${sub_cmd_list}" -- ${cur} ))
    fi
}
complete -F _trace_cmd_complete trace-cmd
