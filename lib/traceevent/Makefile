

include $(src)/scripts/utils.mk

DEFAULT_TARGET = libtraceevent.a

OBJS =
OBJS += event-parse.o
OBJS += event-plugin.o
OBJS += kbuffer-parse.o
OBJS += trace-seq.o
OBJS += parse-filter.o
OBJS += parse-utils.o

# Additional util objects
OBJS += str_error_r.o

DEPS := $(OBJS:%.o=.%.d)

all: $(DEFAULT_TARGET)

libtraceevent.a: $(OBJS)
	$(Q)$(call do_build_static_lib)

libtraceevent.so: $(OBJS)
	$(Q)$(call do_compile_shared_library)

%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): .%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): %.o : .%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) *.a *.so *.o .*.d

.PHONY: clean
