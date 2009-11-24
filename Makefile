CC = gcc
EXT = -std=gnu99
CFLAGS = -g -Wall # -O2
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -lparsevent

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = libparsevent.so trace-cmd

all: $(TARGETS)

trace-read.o::		parse-events.h
trace-cmd.o::		parse-events.h

trace-cmd:: trace-cmd.o trace-read.o
	$(CC) $^ -o $@ $(LIBS)

parse-events.o: parse-events.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

trace-seq.o: trace-seq.c parse-events.h
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

libparsevent.so: parse-events.o trace-seq.o
	$(CC) --shared $^ -o $@

.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS)
