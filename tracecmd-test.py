#!/usr/bin/env python

from ctracecmd import *

# Let's move the following into a new Trace object constructor
filename = "trace.dat"
trace_file = open(filename)
handle = tracecmd_open(trace_file.fileno())
tracecmd_read_headers(handle)
tracecmd_init_data(handle)

# These should be members, i.e. Trace.cpus
pe = tracecmd_get_pevent(handle)
cpus = tracecmd_cpus(handle)
print "Trace %s contains data for %d cpus" % (filename, cpus)

# FIXME: this doesn't print anything...
tracecmd_print_events(handle)

print "Cycling through the events for each CPU"
for cpu in range(0,cpus):
    print "CPU", cpu
    rec = tracecmd_read_data(handle, cpu)
    while True:
        if rec:
            # these should be members of a Record object
            pid = pevent_data_pid(pe, rec)
            comm = pevent_data_comm_from_pid(pe, pid)
            type = pevent_data_type(pe, rec)
            event = pevent_data_event_from_type(pe, type)
            print "\t%f %s: pid=%d comm=%s type=%d" % \
                  (record_ts_get(rec), event_name_get(event), pid, comm, type)

            rec = tracecmd_read_data(handle, cpu)
        else:
            break
