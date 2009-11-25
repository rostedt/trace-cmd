CC = gcc
AR = ar
EXT = -std=gnu99
CFLAGS = -g -Wall # -O2
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -lparsevent -ldl

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = libparsevent.a trace-cmd test_plugin

all: $(TARGETS)

LIB_FILE = libparsevent.a

trace-read.o::		parse-events.h
trace-cmd.o::		parse-events.h $(LIB_FILE)

trace-cmd:: trace-cmd.o trace-read.o trace-util.o
	$(CC) $^ $(LIBS) -rdynamic -o $@

parse-events.o: parse-events.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-seq.o: trace-seq.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

LIB_OBJS = parse-events.o trace-seq.o

libparsevent.so: $(LIB_OBJS)
	$(CC) --shared $^ -o $@

libparsevent.a: $(LIB_OBJS)
	$(RM) $@;  $(AR) rcs $@ $^

test_plugin.o: test_plugin.c parse-events.h
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

test_plugin: test_plugin.o
	$(CC) -shared -nostartfiles -o $@ $<

.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so
