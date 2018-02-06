

include $(src)/scripts/utils.mk

DEFAULT_TARGET = libtracecmd.a

OBJS =
OBJS += trace-hash.o
OBJS += trace-hooks.o
OBJS += trace-input.o
OBJS += trace-recorder.o
OBJS += trace-util.o

# Additional util objects
OBJS += trace-blk-hack.o
OBJS += trace-ftrace.o

DEPS := $(OBJS:%.o=.%.d)

all: $(DEFAULT_TARGET)

libtracecmd.a: $(OBJS)
	$(Q)$(call do_build_static_lib)

libtracecmd.so: $(OBJS)
	$(Q)$(call do_compile_shared_library)

%.o: %.c
	$(Q)$(call do_fpic_compile)

trace-util.o: $(obj)/plugins/trace_plugin_dir

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
