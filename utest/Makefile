# SPDX-License-Identifier: GPL-2.0

include $(src)/scripts/utils.mk

bdir:=$(obj)/utest

TARGETS = $(bdir)/trace-utest

OBJS =
OBJS += trace-utest.o
OBJS += tracecmd-utest.o

LIBS += $(LIBTRACECMD_STATIC) -lcunit $(LIBTRACEEVENT_LDLAGS) $(LIBTRACEFS_LDLAGS)

LIBS += $(ZLIB_LDLAGS) $(LIBZSTD_LDLAGS)

OBJS := $(OBJS:%.o=$(bdir)/%.o)
DEPS := $(OBJS:$(bdir)/%.o=$(bdir)/.%.d)

VALGRIND = $(shell which valgrind)

$(bdir):
	@mkdir -p $(bdir)

$(OBJS): | $(bdir)
$(DEPS): | $(bdir)

$(bdir)/trace-utest: $(OBJS) $(LIBTRACECMD_STATIC)
	$(Q)$(do_app_build)

$(bdir)/%.o: %.c
	$(Q)$(call do_fpic_compile)

$(DEPS): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@
	$(Q)$(CC) -M -MT $(bdir)/$*.o $(CPPFLAGS) $(CFLAGS) $< > $@

$(OBJS): $(bdir)/%.o : $(bdir)/.%.d

dep_includes := $(wildcard $(DEPS))

test: $(TARGETS)

test_mem: test
ifeq (, $(VALGRIND))
	$(error "No valgrind in $(PATH), cannot run memory test")
endif
ifneq ($(shell id -u), 0)
	$(error "The memory test should be run as root, as it reuqires full access to tracefs")
endif
	CK_FORK=no $(VALGRIND) \
		--show-leak-kinds=all --leak-resolution=high \
		--leak-check=full --show-possibly-lost=yes \
		--track-origins=yes -s \
		$(bdir)/trace-utest

clean:
	$(RM) $(TARGETS) $(bdir)/*.o $(bdir)/.*.d
