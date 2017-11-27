#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "trace-local.h"
#include "version.h"

struct usage_help {
	char *name;
	char *short_help;
	char *long_help;
};

static struct usage_help usage_help[] = {
	{
		"record",
		"record a trace into a trace.dat file",
		" %s record [-v][-e event [-f filter]][-p plugin][-F][-d][-D][-o file] \\\n"
		"           [-q][-s usecs][-O option ][-l func][-g func][-n func] \\\n"
		"           [-P pid][-N host:port][-t][-r prio][-b size][-B buf][command ...]\n"
		"           [-m max][-C clock]\n"
		"          -e run command with event enabled\n"
		"          -f filter for previous -e event\n"
		"          -R trigger for previous -e event\n"
		"          -p run command with plugin enabled\n"
		"          -F filter only on the given process\n"
		"          -P trace the given pid like -F for the command\n"
		"          -c also trace the childen of -F (or -P if kernel supports it)\n"
		"          -C set the trace clock\n"
		"          -T do a stacktrace on all events\n"
		"          -l filter function name\n"
		"          -g set graph function\n"
		"          -n do not trace function\n"
		"          -m max size per CPU in kilobytes\n"
		"          -M set CPU mask to trace\n"
		"          -v will negate all -e after it (disable those events)\n"
		"          -d disable function tracer when running\n"
		"          -D Full disable of function tracing (for all users)\n"
		"          -o data output file [default trace.dat]\n"
		"          -O option to enable (or disable)\n"
		"          -r real time priority to run the capture threads\n"
		"          -s sleep interval between recording (in usecs) [default: 1000]\n"
		"          -S used with --profile, to enable only events in command line\n"
		"          -N host:port to connect to (see listen)\n"
		"          -t used with -N, forces use of tcp in live trace\n"
		"          -b change kernel buffersize (in kilobytes per CPU)\n"
		"          -B create sub buffer and folling events will be enabled here\n"
		"          -k do not reset the buffers after tracing.\n"
		"          -i do not fail if an event is not found\n"
		"          -q print no output to the screen\n"
		"          --quiet print no output to the screen\n"
		"          --module filter module name\n"
		"          --by-comm used with --profile, merge events for related comms\n"
		"          --profile enable tracing options needed for report --profile\n"
		"          --func-stack perform a stack trace for function tracer\n"
		"             (use with caution)\n"
		"          --max-graph-depth limit function_graph depth\n"
	},
	{
		"start",
		"start tracing without recording into a file",
		" %s start [-e event][-p plugin][-d][-O option ][-P pid]\n"
		"          Uses same options as record, but does not run a command.\n"
		"          It only enables the tracing and exits\n"
	},
	{
		"extract",
		"extract a trace from the kernel",
		" %s extract [-p plugin][-O option][-o file][-B buf][-s][-a][-t]\n"
		"          Uses similar options as record, but only reads an existing trace.\n"
		"          -s : extract the snapshot instead of the main buffer\n"
		"          -B : extract a given buffer (more than one may be specified)\n"
		"          -a : extract all buffers (except top one)\n"
		"          -t : extract the top level buffer (useful with -B and -a)\n"
	},
	{
		"stop",
		"stop the kernel from recording trace data",
		" %s stop [-B buf [-B buf]..] [-a] [-t]\n"
		"          Stops the tracer from recording more data.\n"
		"          Used in conjunction with start\n"
		"          -B stop a given buffer (more than one may be specified)\n"
		"          -a stop all buffers (except top one)\n"
		"          -t stop the top level buffer (useful with -B or -a)\n"
	},
	{
		"restart",
		"restart the kernel trace data recording",
		" %s restart [-B buf [-B buf]..] [-a] [-t]\n"
		"          Restarts recording after a trace-cmd stop.\n"
		"          Used in conjunction with stop\n"
		"          -B restart a given buffer (more than one may be specified)\n"
		"          -a restart all buffers (except top one)\n"
		"          -t restart the top level buffer (useful with -B or -a)\n"
	},
	{
		"show",
		"show the contents of the kernel tracing buffer",
		" %s show [-p|-s][-c cpu][-B buf][options]\n"
		"          Basically, this is a cat of the trace file.\n"
		"          -p read the trace_pipe file instead\n"
		"          -s read the snapshot file instance\n"
		"           (Can't have both -p and -s)\n"
		"          -c just show the file associated with a given CPU\n"
		"          -B read from a tracing buffer instance.\n"
		"          -f display the file path that is being dumped\n"
		"          The following options shows the corresponding file name\n"
		"           and then exits.\n"
		"          --tracing_on\n"
		"          --current_tracer\n"
		"          --buffer_size (for buffer_size_kb)\n"
		"          --buffer_total_size (for buffer_total_size_kb)\n"
		"          --ftrace_filter (for set_ftrace_filter)\n"
		"          --ftrace_notrace (for set_ftrace_notrace)\n"
		"          --ftrace_pid (for set_ftrace_pid)\n"
		"          --graph_function (for set_graph_function)\n"
		"          --graph_notrace (for set_graph_notrace)\n"
		"          --cpumask (for tracing_cpumask)\n"
	},
	{
		"reset",
		"disable all kernel tracing and clear the trace buffers",
		" %s reset [-b size][-B buf][-a][-d][-t]\n"
		"          Disables the tracer (may reset trace file)\n"
		"          Used in conjunction with start\n"
		"          -b change the kernel buffer size (in kilobytes per CPU)\n"
		"          -d delete the previous specified instance\n"
		"          -B reset the given buffer instance (may specify multiple -B)\n"
		"          -a reset all instances (except top one)\n"
		"          -t reset the top level instance (useful with -B or -a)\n"
	},
	{
		"clear",
		"clear the trace buffers",
		" %s clear\n"
	},
	{
		"report",
		"read out the trace stored in a trace.dat file",
		" %s report [-i file] [--cpu cpu] [-e][-f][-l][-P][-L][-N][-R][-E]\\\n"
		"           [-r events][-n events][-F filter][-v][-V][-T][-O option]\n"
		"           [-H [start_system:]start_event,start_match[,pid]/[end_system:]end_event,end_match[,flags]\n"
		"           [-G]\n"
		"          -i input file [default trace.dat]\n"
		"          -e show file endianess\n"
		"          -f show function list\n"
		"          -P show printk list\n"
		"          -E show event files stored\n"
		"          -F filter to filter output on\n"
		"          -I filter out events with the HARDIRQ flag set\n"
		"          -S filter out events with the SOFTIRQ flag set\n"
		"          -t print out full timestamp. Do not truncate to 6 places.\n"
		"          -R raw format: ignore print format and only show field data\n"
		"          -r raw format the events that match the option\n"
		"          -v will negate all -F after it (Not show matches)\n"
		"          -T print out the filter strings created and exit\n"
		"          -V verbose (shows plugins being loaded)\n"
		"          -L load only local (~/.trace-cmd/plugins) plugins\n"
		"          -N do not load any plugins\n"
		"          -n ignore plugin handlers for events that match the option\n"
		"          -w show wakeup latencies\n"
		"          -l show latency format (default with latency tracers)\n"
		"          -O plugin option -O [plugin:]var[=val]\n"
		"          --check-events return whether all event formats can be parsed\n"
		"          --stat - show the buffer stats that were reported at the end of the record.\n"
		"          --uname - show uname of the record, if it was saved\n"
		"          --profile report stats on where tasks are blocked and such\n"
		"          -G when profiling, set soft and hard irqs as global\n"
		"          -H Allows users to hook two events together for timings\n"
		"             (used with --profile)\n"
		"          --by-comm used with --profile, merge events for related comms\n"
		"          --ts-offset will add amount to timestamp of all events of the\n"
		"                     previous data file.\n"
		"          --ts2secs HZ, pass in the timestamp frequency (per second)\n"
		"                     to convert the displayed timestamps to seconds\n"
		"                     Affects the previous data file, unless there was no\n"
		"                     previous data file, in which case it becomes default\n"
		"           --ts-diff Show the delta timestamp between events.\n"
	},
	{
		"stream",
		"Start tracing and read the output directly",
		" %s stream [-e event][-p plugin][-d][-O option ][-P pid]\n"
		"          Uses same options as record but does not write to files or the network.\n"
	},
	{
		"profile",
		"Start profiling and read the output directly",
		" %s profile [-e event][-p plugin][-d][-O option ][-P pid][-G][-S][-o output]\n"
		"    [-H [start_system:]start_event,start_match[,pid]/[end_system:]end_event,end_match[,flags]\n\n"
		"          Uses same options as record --profile.\n"
		"          -H Allows users to hook two events together for timings\n"
	},
	{
		"hist",
		"show a historgram of the trace.dat information",
		" %s hist [-i file][-P] [file]"
		"          -P ignore pids (compact all functions)\n"
	},
	{
		"stat",
		"show the status of the running tracing (ftrace) system",
		" %s stat"
	},
	{
		"split",
		"parse a trace.dat file into smaller file(s)",
		" %s split [options] -o file [start [end]]\n"
		"          -o output file to write to (file.1, file.2, etc)\n"
		"          -s n  split file up by n seconds\n"
		"          -m n  split file up by n milliseconds\n"
		"          -u n  split file up by n microseconds\n"
		"          -e n  split file up by n events\n"
		"          -p n  split file up by n pages\n"
		"          -r    repeat from start to end\n"
		"          -c    per cpu, that is -p 2 will be 2 pages for each CPU\n"
		"          if option is specified, it will split the file\n"
		"           up starting at start, and ending at end\n"
		"          start - decimal start time in seconds (ex: 75678.923853)\n"
		"                  if left out, will start at beginning of file\n"
		"          end   - decimal end time in seconds\n"
	},
	{
		"options",
		"list the plugin options available for trace-cmd report",
		" %s options\n"
	},
	{
		"listen",
		"listen on a network socket for trace clients",
		" %s listen -p port[-D][-o file][-d dir][-l logfile]\n"
		"          Creates a socket to listen for clients.\n"
		"          -D create it in daemon mode.\n"
		"          -o file name to use for clients.\n"
		"          -d diretory to store client files.\n"
		"          -l logfile to write messages to.\n"
	},
	{
		"list",
		"list the available events, plugins or options",
		" %s list [-e [regex]][-t][-o][-f [regex]]\n"
		"          -e list available events\n"
		"            -F show event format\n"
		"            -R show event triggers\n"
		"            -l show event filters\n"
		"          -t list available tracers\n"
		"          -o list available options\n"
		"          -f [regex] list available functions to filter on\n"
		"          -P list loaded plugin files (by path)\n"
		"          -O list plugin options\n"
		"          -B list defined buffer instances\n"
		"          -C list the defined clocks (and active one)\n"
	},
	{
		"restore",
		"restore a crashed record",
		" %s restore [-c][-o file][-i file] cpu-file [cpu-file ...]\n"
		"          -c create a partial trace.dat file only\n"
		"          -o output file\n"
		"          -i parital trace.dat file for input\n"
	},
	{
		"snapshot",
		"take snapshot of running trace",
		" %s snapshot [-s][-r][-f][-B buf][-c cpu]\n"
		"          -s take a snapshot of the trace buffer\n"
		"          -r reset current snapshot\n"
		"          -f free the snapshot buffer\n"
		"            without the above three options, display snapshot\n"
		"          -c operate on the snapshot buffer for the given CPU\n"
		"          -B operate on the snapshot buffer for a tracing buffer instance.\n"
	},
	{
		"stack",
		"output, enable or disable kernel stack tracing",
		" %s stack [--start][--stop][--reset]\n"
		"          --start  enable the stack tracer\n"
		"          --stop   disable the stack tracer\n"
		"          --reset  reset the maximum stack found\n"
	},
	{
		"check-events",
		"parse trace event formats",
		" %s check-format [-N]\n"
		"          -N do not load any plugins\n"
	},
	{
		NULL, NULL, NULL
	}
};

static struct usage_help *find_help(char *cmd)
{
	struct usage_help *help;

	help = usage_help;
	while (help->name) {
		if (strcmp(cmd, help->name) == 0)
			return help;
		help++;
	}
	return NULL;
}

void usage(char **argv)
{
	struct usage_help *help = NULL;
	char *arg = argv[0];
	char *p;

	p = basename(arg);

	printf("\n"
	       "%s version %s\n\n"
	       "usage:\n", p, VERSION_STRING);

	if (argv[1])
		help = find_help(argv[1]);

	if (help) {
		printf(help->long_help, p);
		goto out;
	}

	printf("  %s [COMMAND] ...\n\n"
	       "  commands:\n", p);

	help = usage_help;
	while (help->name) {
		printf("     %s - %s\n", help->name, help->short_help);
		help++;
	}
 out:
	printf("\n");
	exit(-1);
}


void trace_usage(int argc, char **argv)
{
	usage(argv);
}
