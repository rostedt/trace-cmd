

include $(src)/scripts/utils.mk

bdir:=$(obj)/lib/trace-cmd

DEFAULT_TARGET = $(bdir)/libtracecmd.a

OBJS =
OBJS += trace-hash.o
OBJS += trace-hooks.o
OBJS += trace-input.o
OBJS += trace-output.o
OBJS += trace-recorder.o
OBJS += trace-util.o
OBJS += trace-filter-hash.o
OBJS += trace-msg.o
OBJS += trace-plugin.o
ifeq ($(VSOCK_DEFINED), 1)
OBJS += trace-timesync.o
endif

# Additional util objects
OBJS += trace-blk-hack.o
OBJS += trace-ftrace.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

all: $(DEFAULT_TARGET)

$(bdir):
	@mkdir -p $(bdir)

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

$(bdir)/libtracecmd.a: $(OBJS)
	$(Q)$(call do_build_static_lib)

LIBS = -L$(obj)/lib/traceevent -ltraceevent

$(bdir)/libtracecmd.so: $(OBJS)
	$(Q)$(call do_compile_shared_library)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.o $(bdir)/.*.d

.PHONY: clean
