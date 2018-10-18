

include $(src)/scripts/utils.mk

bdir:=$(obj)/lib/traceevent

DEFAULT_TARGET = $(bdir)/libtraceevent.a

OBJS =
OBJS += event-parse.o
OBJS += event-plugin.o
OBJS += kbuffer-parse.o
OBJS += trace-seq.o
OBJS += parse-filter.o
OBJS += parse-utils.o
OBJS += event-parse-api.o
OBJS += tep_strerror.o

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

all: $(DEFAULT_TARGET)

$(bdir):
	@mkdir -p $(bdir)

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

$(bdir)/libtraceevent.a: $(OBJS)
	$(Q)$(call do_build_static_lib)

$(bdir)/libtraceevent.so: $(OBJS)
	$(Q)$(call do_compile_shared_library)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) -f $(bdir)/*.a $(bdir)/*.so $(bdir)/*.o $(bdir)/.*.d

.PHONY: clean
