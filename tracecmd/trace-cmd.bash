make_small() {
    local w=$1

    echo $w | tr A-Z a-z
}

show_instances()
{
   local cur="$1"
   local bufs=$(trace-cmd list -B)
   if [ "$bufs" == "No buffer instances defined" ]; then
	return 0
   fi
   COMPREPLY=( $(compgen -W "${bufs}" -- "${cur}") )
   return 0
}

show_virt()
{
    local cur="$1"
    if ! which virsh &>/dev/null; then
	return 1
    fi
    local virt=`virsh list | awk '/^ *[0-9]/ { print $2 }'`
    COMPREPLY=( $(compgen -W "${virt}" -- "${cur}") )
    return 0
}

show_options()
{
   local cur="$1"
   local options=$(trace-cmd list -o | sed -e 's/^\(no\)*\(.*\)/\2 no\2/')
   COMPREPLY=( $(compgen -W "${options}" -- "${cur}") )
   return 0
}

__show_files()
{
    COMPREPLY=( $(compgen -f -- "$cur") )
    if [ ${#COMPREPLY[@]} -gt 1 ]; then
	    return 0;
    fi
    # directories get '/' instead of space
    DIRS=( $(compgen -d -- "$cur"))
    if [ ${#DIRS[@]} -eq 1 ]; then
	compopt -o nospace
	COMPREPLY="$DIRS/"
	return 0;
    fi
    return 0
}

cmd_options()
{
    local type="$1"
    local cur="$2"
    local extra="$3"
    local cmds=$(trace-cmd $type -h 2>/dev/null|grep "^ *-" | \
				 sed -e 's/ *\(-[^ ]*\).*/\1/')
    COMPREPLY=( $(compgen -W "${cmds} ${extra}" -- "${cur}") )
}

cmd_options_files()
{
    cmd_options "$1" "$2" "$3"
    if [ ${#COMPREPLY[@]} -eq 0 ]; then
	__show_files "${cur}"
    fi
}

plugin_options()
{
    local cur="$1"

    local opts=$(trace-cmd list -O | sed -ne 's/option://p')
    COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
}

compression_param()
{
    local opts=$(trace-cmd list -c | grep -v 'Supported' | cut -d "," -f1)
    opts+=" any none "
    COMPREPLY=( $(compgen -W "${opts}") )
}

list_events() {
    local cur=$1

    local list=$(trace-cmd list -e "$cur")
    local prefix=${cur%%:*}
    if [ -z "$cur" -o  "$cur" != "$prefix" ]; then
	echo "${list}"
    else
	local events=$(for e in $list; do echo ${e/*:/}; done | sort -u)
	local systems=$(for s in $list; do echo ${s/:*/:}; done | sort -u)

	echo "${events} ${systems}"
    fi
}

__trace_cmd_list_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	list)
	    local cmds=$(trace-cmd list -h |egrep "^ {10}-" | \
				 sed -e 's/.*\(-.\).*/\1/')
	    COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
	    ;;
	-e)
	    local list=`list_events "$cur"`
	    COMPREPLY=( $(compgen -W "all $list" -- "${cur}") )
	    ;;
	*)
	    size=${#words[@]}
	    if [ $size -gt 3 ]; then
		if [ "$cur" == "-" ]; then
		    let size=$size-3
		else
		    let size=$size-2
		fi
		local w="${words[$size]}"
		if [ "$w" == "-e" ]; then
		    local cmds=$(trace-cmd list -h |egrep "^ {12}-" | \
				 sed -e 's/.*\(-.\).*/\1/')
		    COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
		fi
	    fi
	    ;;
    esac
}

__trace_cmd_show_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	-B)
	    show_instances "$cur"
	    ;;
	*)
	    cmd_options show "$cur"
	    ;;
    esac
}

__trace_cmd_extract_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	extract)
	    cmd_options "$prev" "$cur"
	    ;;
	-B)
	    show_instances "$cur"
	    ;;
	*)
	    __show_files
	    ;;
    esac
}

__trace_cmd_record_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	-e)
	    local list=`list_events $cur`
	    COMPREPLY=( $(compgen -W "all ${list}" -- "${cur}") )

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
	    COMPREPLY=( $(compgen -W "${plugins}" -- "${cur}" ) )
            ;;
        -l|-n|-g)
            # This is extremely slow still (may take >1sec).
            local funcs=$(trace-cmd list -f | sed 's/ .*//')
            COMPREPLY=( $(compgen -W "${funcs}" -- "${cur}") )
            ;;
	-B)
	    show_instances "$cur"
	    ;;
	-O)
	    show_options "$cur"
	    ;;
	-A)
	    if ! show_virt "$cur"; then
		cmd_options_files record "$cur"
	    fi
	    ;;
	--compression)
	    compression_param
	    ;;
        *)
	    # stream start and profile do not show all options
	    cmd_options_files record "$cur"
	    ;;
    esac
}

__trace_cmd_report_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	-O)
	    plugin_options "$cur"
	    ;;
        *)
	    cmd_options report "$cur"
	    ;;
    esac
}

dynevent_options()
{
    local cur="$1"
    local opts=("kprobe" "kretprobe" "uprobe" "uretprobe" "eprobe" "synth" "all")
    COMPREPLY=( $(compgen -W "${opts[*]}" -- "${cur}") )
}

__trace_cmd_reset_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
        -B)
            show_instances "$cur"
            ;;
        -k)
            dynevent_options "$cur"
            ;;
        *)
            cmd_options reset "$cur"
            ;;
    esac
}

__trace_cmd_dump_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	-i)
	    __show_files
	    ;;
	*)
	    cmd_options dump "$cur"
	    ;;
    esac
}

__trace_cmd_convert_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    case "$prev" in
	-i)
	    __show_files
	    ;;
	-o)
	    __show_files
	    ;;
	--compression)
	    compression_param
	    ;;
	*)
	    cmd_options convert "$cur"
	    ;;
    esac
}

##### SQLHIST COMMANDS #####

prev_keyword() {
    local i=$1
    shift
    local words=("$@")

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=`make_small ${words[$i]}`

	case $w in
	    select)
		      echo "select"
		      return
		      ;;
		  from)
		      echo "from"
		      return
		      ;;
		  as)
		      echo "as"
		      return
		      ;;
		  on)
		      echo "on"
		      return
		      ;;
		  join)
		      echo "join"
		      return
		      ;;
		  where)
		      echo "where"
		      return
		      ;;
		  *)
		      if [ "$w" != "${w%%,}" ]; then
			  echo ","
			  return
		      fi
		      if [ "$w" != "${w%%=}" ]; then
			  echo "="
			  return
		      fi
		      ;;
	    esac
	done
	    echo ""
}

prev_command() {
    local i=$1
    shift
    local words=("$@")

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=`make_small ${words[$i]}`

	case $w in
	    select)
		      echo "select"
		      return
		      ;;
		  from)
		      echo "from"
		      return
		      ;;
		  on)
		      echo "on"
		      return
		      ;;
		  join)
		      echo "join"
		      return
		      ;;
		  where)
		      echo "where"
		      return
		      ;;
	    esac
	done
	    echo ""
}

add_vars() {
    local words=("$@")

    local i=$COMP_CWORD

    let found_from=0

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=`make_small ${words[$i]}`

	case $w in
	    "from")
		let found_from=1
		;;
	    *)
		if [ $found_from ]; then
		    start=`echo $w | sed -e 's/\.[^\.]*$//'`
		    if [ "$start" != "$w" -a "$start" == "${start%%\.*}" ]; then
			echo -n "$start "
		    fi
		fi
		;;
	esac
    done
}

add_options() {
    local cur="$1"
    local list="$2"

    COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
}

print_fields() {
    local event=$1
    local var=$2
    local extra=$3

    local list=`trace-cmd list -e "^${event/\./:}\$" -F |  cut -d';' -f1 | sed -ne 's/\t.*:.* \(.*\)/\1/p' |sed -e 's/\[.*\]//'`

    for field in $list $extra; do
	echo "$event.$field"
	if [ ! -z "$var" ]; then
	    echo "$var.$field"
	fi
    done
}

select_options() {
    local cur=$1
    local extra=$2
    local list=`list_events "${cur/\./:}" | sed -e 's/:/./g'`
    local select_list=" TIMESTAMP_DELTA TIMESTAMP_DELTA_USECS $extra"
    local select_fields=" TIMESTAMP TIMESTAMP_USECS STACKTRACE"
    add_options "$cur" "$list $select_list"
    local cnt=${#COMPREPLY[@]}
    if [ $cnt -eq 1 ]; then
	local comp=${COMPREPLY[0]}
	local w=$(compgen -W "$select_list" -- "$comp" )
	if [ -z "$w" ]; then
	    COMPREPLY=("$comp.")
	    compopt -o nospace
	fi
    elif [ $cnt -eq 0 ]; then
	local w=`echo $cur | sed -e 's/\.[^\.]*$//'`
	list=`print_fields $w "" "$select_fields"`
	COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
    fi
}

check_as() {
    local words=("$@")

    last_key=`prev_keyword $COMP_CWORD ${words[@]}`
    if [ "$last_key" != "as" ]; then
	echo -n "AS"
    fi
}

on_list() {
    local type=$1
    shift
    local words=("$@")

    local i=$COMP_CWORD

    local var=""

    while [ $i -gt 0 ]; do
	let i=$i-1
	local w=`make_small ${words[$i]}`
	case $w in
	    "from"|"join")
		if [ $w == $type ]; then
		    print_fields ${words[$i+1]} "$var"
		    return
		fi
		var=""
		;;
	    as)
		var=${words[$i+1]}
		;;
	esac
    done
}

update_completion() {
    local cur=$1
    shift
    local words=("$@")

    if [ ${#COMPREPLY[@]} -gt 0 ]; then
	return
    fi

    for w in ${words[@]}; do
	if [ "$w" != "${w##$cur}" ]; then
	    COMPREPLY=("$w")
	    return
	fi
    done
}

__trace_cmd_sqlhist_complete()
{
    local prev=$1
    local cur=$2
    shift 2
    local words=("$@")

    if [ "$cur" != "${cur%%,}" ]; then
	COMPREPLY=("$cur")
	return
    fi

    local p=`make_small $prev`

    if [ "$p" != "${p%%,}" ]; then
	p=`prev_command $COMP_CWORD ${words[@]}`
    fi

    case "$p" in
	"sqlhist")
	    cmd_options sqlhist "$cur" "SELECT"
	    update_completion "$cur" select
	    ;;
	"select")
	    select_options "$cur"
	    ;;
	"on")
	    list=`on_list "from" ${words[@]}`
	    add_options "$cur" "$list"
	    ;;
	"as")
	    local last_cmd=`prev_command $COMP_CWORD ${words[@]}`
	    case $last_cmd in
		"from"|"join")
		    list=`add_vars ${words[@]}`
		    if [ ! -z "$list" ]; then
			add_options "$cur" "$list"
		    fi
		    ;;
	    esac
	    ;;
	"from"|"join")
	    local list=$(trace-cmd list -e "${cur/\./:}" | tr : .)
	    local prefix=${cur/\./}
	    if [ -z "$cur" -o  "$cur" != "$prefix" ]; then
		COMPREPLY=( $(compgen -W "${list}" -- "${cur}") )
	    else
		local events=$(for e in $list; do echo ${e/*\./}; done | sort -u)
	        local systems=$(for s in $list; do echo ${s/\.*/.}; done | sort -u)

		COMPREPLY=( $(compgen -W "all ${events} ${systems}" -- "${cur}") )
	    fi
	    ;;
	*)
	    local last_cmd=`prev_command $COMP_CWORD ${words[@]}`
	    local list=`check_as ${words[@]}`
	    local alist=""
	    if [ ! -z "$list" ]; then
		alist="as"
	    fi
	    case $last_cmd in
		"select")
		    if [ "$cur" != "${cur%%,}" ]; then
			select_options "$cur" "$list"
		    else
			add_options "$cur" "FROM , $list"
			update_completion "$cur" from $alist
		    fi
		    ;;
		"from")
		    add_options "$cur" "JOIN $list"
		    update_completion "$cur" join $alist
		    ;;
		"join")
		    add_options "$cur" "ON $list"
		    update_completion "$cur" on $alist
		    ;;
		"on")
		    if [ "$cur" != "${cur%%=}" ]; then
			COMPREPLY=("")
		    else
			last_key=`prev_keyword $COMP_CWORD ${words[@]}`
			if [ "$last_key" == "=" ]; then
			    if [ $prev == "=" ]; then
				list=`on_list "join" ${words[@]}`
				add_options "$cur" "$list"
			    else
				add_options "$cur" "WHERE"
				update_completion "$cur" where
			    fi
			else
			    add_options "$cur" "="
			fi
		    fi
		    ;;
		"where")
		    ;;
		*)
		    cmd_options sqlhist "$cur" "SELECT"
		    update_completion "$cur" select
		    ;;
	    esac
	    ;;
    esac
}

##### SQLHIST COMMANDS END #####

__show_command_options()
{
    local command="$1"
    local prev="$2"
    local cur="$3"
    local cmds=( $(trace-cmd --help 2>/dev/null | \
		    grep " - " | sed 's/^ *//; s/ -.*//') )

    for cmd in ${cmds[@]}; do
	if [ $cmd == "$command" ]; then
	    local opts=$(trace-cmd $cmd -h 2>/dev/null|grep "^ *-" | \
				 sed -e 's/ *\(-[^ ]*\).*/\1/')
	    if [ "$prev" == "-B" ]; then
		for opt in ${opts[@]}; do
		    if [ "$opt" == "-B" ]; then
			show_instances "$cur"
			return 0
		    fi
		done
	    fi
	    COMPREPLY=( $(compgen -W "${opts}" -- "$cur"))
	    break
	fi
    done
    if [ ${#COMPREPLY[@]} -eq 0 ]; then
	__show_files "${cur}"
    fi
}

_trace_cmd_complete()
{
    local cur=""
    local prev=""
    local words=()

    # Not to use COMP_WORDS to avoid buggy behavior of Bash when
    # handling with words including ":", like:
    #
    # prev="${COMP_WORDS[COMP_CWORD-1]}"
    # cur="${COMP_WORDS[COMP_CWORD]}"
    #
    # Instead, we use _get_comp_words_by_ref() magic.
    _get_comp_words_by_ref -n : cur prev words

    if [ "$prev" == "trace-cmd" ]; then
            local cmds=$(trace-cmd --help 2>/dev/null | \
                                grep " - " | sed 's/^ *//; s/ -.*//')
            COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
	    return;
    fi

    local w="${words[1]}"

    case "$w" in
	list)
	    __trace_cmd_list_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	show)
	    __trace_cmd_show_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	extract)
	    __trace_cmd_extract_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	record|stream|start|set|profile)
	    __trace_cmd_record_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	report)
	    __trace_cmd_report_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	reset)
	    __trace_cmd_reset_complete "${prev}" "${cur}" "${words[@]}"
	    return 0
	    ;;
	dump)
	    __trace_cmd_dump_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	convert)
	    __trace_cmd_convert_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
	sqlhist)
	    __trace_cmd_sqlhist_complete "${prev}" "${cur}" ${words[@]}
	    return 0
	    ;;
        *)
	    __show_command_options "$w" "${prev}" "${cur}"
            ;;
    esac
}
complete -F _trace_cmd_complete trace-cmd
