_trace_cmd_complete()
{
    local cur=""
    local prev=""

    # Not to use COMP_WORDS to avoid buggy behavior of Bash when
    # handling with words including ":", like:
    #
    # prev="${COMP_WORDS[COMP_CWORD-1]}"
    # cur="${COMP_WORDS[COMP_CWORD]}"
    #
    # Instead, we use _get_comp_words_by_ref() magic.
    _get_comp_words_by_ref -n : cur prev

    case "$prev" in
        trace-cmd)
            local cmds=$(trace-cmd --help 2>/dev/null | \
                                grep " - " | sed 's/^ *//; s/ -.*//')
            COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
            ;;
        -e)
            local events=$(trace-cmd list -e)
            local prefix=${cur%%:*}

            COMPREPLY=( $(compgen -W "${events}" -- "${cur}") )

            # This is still to handle the "*:*" special case
            if [[ -n "$prefix" ]]; then
                local reply_n=${#COMPREPLY[*]}
                for (( i = 0; i < $reply_n; i++)); do
                    COMPREPLY[$i]=${COMPREPLY[i]##${prefix}:}
                done
            fi
            ;;
        -p)
            local plugins=$(trace-cmd list -p)
            COMPREPLY=( $(compgen -W "${plugins}" -- "${cur}") )
            ;;
        -l|-n|-g)
            # This is extremely slow still (may take >1sec).
            local funcs=$(trace-cmd list -f | sed 's/ .*//')
            COMPREPLY=( $(compgen -W "${funcs}" -- "${cur}") )
            ;;
        *)
            # By default, we list files
            local files=$(ls --color=never)
            COMPREPLY=( $(compgen -W "${files}" -- "$cur") )
            ;;
    esac
}
complete -F _trace_cmd_complete trace-cmd
