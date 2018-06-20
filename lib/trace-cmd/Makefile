

include $(src)/scripts/utils.mk

bdir:=$(obj)/lib/trace-cmd

DEFAULT_TARGET = $(bdir)/libtracecmd.a

OBJS =
OBJS += trace-hash.o
OBJS += trace-hooks.o
OBJS += trace-input.o
OBJS += trace-recorder.o
OBJS += trace-util.o
OBJS += trace-filter-hash.o

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

$(bdir)/libtracecmd.so: $(OBJS)
	$(Q)$(call do_compile_shared_library)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(bdir)/trace-util.o: $(obj)/plugins/trace_plugin_dir

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.o $(bdir)/.*.d

.PHONY: clean
