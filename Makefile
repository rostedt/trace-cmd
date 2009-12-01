CC = gcc
AR = ar
EXT = -std=gnu99
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -ltracecmd -ldl

PACKAGES= gtk+-2.0 libgnome-2.0 libgnomecanvas-2.0 libgnomeui-2.0 libxml-2.0

CONFIG_FLAGS = $(shell pkg-config --cflags $(PACKAGES))
CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

CFLAGS = -g -Wall $(CONFIG_FLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = libparsevent.a libtracecmd.a trace-cmd plugin_hrtimer.so plugin_mac80211.so \
	plugin_sched_switch.so

all: $(TARGETS)

LIB_FILE = libtracecmd.a

HEADERS = parse-events.h trace-cmd.h

trace-read.o::		$(HEADERS) 
trace-cmd.o::		$(HEADERS) $(LIB_FILE)
trace-util.o::		$(HEADERS)
trace-ftrace.o::	$(HEADERS)
trace-input.o::		$(HEADERS)

trace-cmd:: trace-cmd.o trace-read.o trace-view.o trace-view-store.o
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS)

.PHONY: view_depends
view_depends:
	@pkg-config --cflags $(PACKAGES)

trace-view.o::		parse-events.h view_depends

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
python:	$(TCMD_LIB_OBJS) trace-cmd.o trace-read.o
	swig -Wall -python -noproxy ctracecmd.i
	gcc -fpic -c  `python-config --includes` ctracecmd_wrap.c
	$(CC) --shared $^ ctracecmd_wrap.o -o ctracecmd.so


.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c
