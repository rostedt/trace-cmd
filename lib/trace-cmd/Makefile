# SPDX-License-Identifier: GPL-2.0

include $(src)/scripts/utils.mk

bdir:=$(obj)/lib/trace-cmd

DEFAULT_TARGET = $(LIBTRACECMD_STATIC)

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

$(LIBTRACECMD_STATIC): $(OBJS)
	$(Q)$(call do_build_static_lib)

LIBS = $(LIBTRACEEVENT_LDLAGS) $(LIBTRACEFS_LDLAGS)

$(LIBTRACECMD_SHARED_VERSION): $(LIBTRACECMD_SHARED)
	@ln -sf $(<F) $@

$(LIBTRACECMD_SHARED_SO): $(LIBTRACECMD_SHARED_VERSION)
	@ln -sf $(<F) $@

libtracecmd.so: force $(LIBTRACECMD_SHARED_SO)

$(LIBTRACECMD_SHARED): $(OBJS)
	$(Q)$(call do_compile_shared_library)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

install_libs:
	$(Q)$(call do_install,$(LIBTRACECMD_SHARED),$(libdir_SQ))
	cp -fpR $(LIBTRACECMD_SHARED_VERSION) $(DESTDIR)$(libdir_SQ)
	cp -fpR $(LIBTRACECMD_SHARED_SO) $(DESTDIR)$(libdir_SQ)
	$(Q)$(call do_install,$(src)/include/trace-cmd/trace-cmd.h,$(includedir_SQ)/trace-cmd)

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.so.* $(bdir)/*.o $(bdir)/.*.d

.PHONY: clean

PHONY += force
force:
