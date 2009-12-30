CC = gcc
AR = ar
EXT = -std=gnu99
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -ltracecmd -ldl

PACKAGES= gtk+-2.0

CONFIG_FLAGS = $(shell pkg-config --cflags $(PACKAGES)) \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

CFLAGS = -g -Wall $(CONFIG_FLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = libparsevent.a libtracecmd.a trace-cmd plugin_hrtimer.so plugin_mac80211.so \
	plugin_sched_switch.so trace-graph trace-view kernelshark

all: $(TARGETS)

LIB_FILE = libtracecmd.a

HEADERS = parse-events.h trace-cmd.h trace-local.h

trace-read.o::		$(HEADERS) 
trace-cmd.o::		$(HEADERS) $(LIB_FILE)
trace-util.o::		$(HEADERS)
trace-ftrace.o::	$(HEADERS)
trace-input.o::		$(HEADERS)
trace-view.o::		$(HEADERS) trace-view-store.h trace-view.h
trace-view-store.o::	$(HEADERS) trace-view-store.h trace-view.h
trace-view-main.o::	$(HEADERS) trace-view-store.h trace-view.h
trace-filter.o::	$(HEADERS)
trace-graph.o::		$(HEADERS) trace-graph.h
trace-graph-main.o::	$(HEADERS) trace-graph.h
kernel-shark.o::	$(HEADERS) kernel-shark.h

TRACE_VIEW_OBJS = trace-view.o trace-view-store.o trace-filter.o

trace-cmd:: trace-cmd.o trace-read.o
	$(CC) $^ -rdynamic -o $@ $(LIBS)

trace-view:: trace-view-main.o $(TRACE_VIEW_OBJS)
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS)

trace-graph:: trace-graph-main.o trace-graph.o trace-compat.o
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS)

kernelshark:: kernel-shark.o trace-compat.o $(TRACE_VIEW_OBJS) trace-graph.o
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS)

.PHONY: gtk_depends
view_depends:
	@pkg-config --cflags $(PACKAGES)

trace-view.o::		parse-events.h
trace-graph.o::		parse-events.h

parse-events.o: parse-events.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-seq.o: trace-seq.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-util.o:: trace-util.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-input.o:: trace-input.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-output.o:: trace-output.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-record.o:: trace-record.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-ftrace.o:: trace-ftrace.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

PEVENT_LIB_OBJS = parse-events.o trace-seq.o

libparsevent.so: $(PEVENT_LIB_OBJS)
	$(CC) --shared $^ -o $@

libparsevent.a: $(PEVENT_LIB_OBJS)
	$(RM) $@;  $(AR) rcs $@ $^

TCMD_LIB_OBJS = $(PEVENT_LIB_OBJS) trace-util.o trace-input.o trace-ftrace.o \
			trace-output.o trace-record.o

libtracecmd.so: $(TCMD_LIB_OBJS)
	$(CC) --shared $^ -o $@

libtracecmd.a: $(TCMD_LIB_OBJS)
	$(RM) $@;  $(AR) rcs $@ $^

plugin_hrtimer.o: plugin_hrtimer.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

plugin_hrtimer.so: plugin_hrtimer.o
	$(CC) -shared -nostartfiles -o $@ $<

plugin_sched_switch.o: plugin_sched_switch.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

plugin_sched_switch.so: plugin_sched_switch.o
	$(CC) -shared -nostartfiles -o $@ $<

plugin_mac80211.o: plugin_mac80211.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

plugin_mac80211.so: plugin_mac80211.o
	$(CC) -shared -nostartfiles -o $@ $<


.PHONY: python
python:	$(TCMD_LIB_OBJS)
	swig -Wall -python -noproxy ctracecmd.i
	#swig -Wall -python ctracecmd.i
	gcc -fpic -c  `python-config --includes` ctracecmd_wrap.c
	$(CC) --shared $^ ctracecmd_wrap.o -o ctracecmd.so
	#$(CC) --shared $^ ctracecmd_wrap.o -o _ctracecmd.so


.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c
