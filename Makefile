CC = gcc
EXT = -std=gnu99
CFLAGS = -g -Wall # -O2
INCLUDES = -I. -I/usr/local/include

%.o: %.c
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

TARGETS = trace-cmd

all: $(TARGETS)

parse-events.o::	parse-events.h
trace-read.o::		parse-events.h
trace-cmd.o::		parse-events.h
trace-seq.o::		parse-events.h trace-seq.h

trace-cmd: trace-cmd.o trace-read.o parse-events.o trace-seq.o
	$(CC) $^ -o $@

.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS)
