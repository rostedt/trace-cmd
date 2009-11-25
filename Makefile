CC = gcc
AR = ar
EXT = -std=gnu99
CFLAGS = -g -Wall # -O2
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -ltracecmd -ldl

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = libparsevent.a libtracecmd.a trace-cmd plugin_hrtimer.so plugin_mac80211.so

all: $(TARGETS)

LIB_FILE = libtracecmd.a

trace-read.o::		parse-events.h
trace-cmd.o::		parse-events.h $(LIB_FILE)

trace-cmd:: trace-cmd.o trace-read.o
	$(CC) $^ $(LIBS) -rdynamic -o $@

parse-events.o: parse-events.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-seq.o: trace-seq.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

PEVENT_LIB_OBJS = parse-events.o trace-seq.o

libparsevent.so: $(PEVENT_LIB_OBJS)
	$(CC) --shared $^ -o $@

libparsevent.a: $(PEVENT_LIB_OBJS)
	$(RM) $@;  $(AR) rcs $@ $^

TCMD_LIB_OBJS = $(PEVENT_LIB_OBJS) trace-util.o

libtracecmd.a: $(TCMD_LIB_OBJS)
	$(RM) $@;  $(AR) rcs $@ $^

plugin_hrtimer.o: plugin_hrtimer.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

plugin_hrtimer.so: plugin_hrtimer.o
	$(CC) -shared -nostartfiles -o $@ $<

plugin_mac80211.o: plugin_mac80211.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

plugin_mac80211.so: plugin_mac80211.o
	$(CC) -shared -nostartfiles -o $@ $<

.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so
