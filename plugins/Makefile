include $(src)/scripts/utils.mk

PLUGIN_OBJS =
PLUGIN_OBJS += plugin_jbd2.o
PLUGIN_OBJS += plugin_hrtimer.o
PLUGIN_OBJS += plugin_kmem.o
PLUGIN_OBJS += plugin_kvm.o
PLUGIN_OBJS += plugin_mac80211.o
PLUGIN_OBJS += plugin_sched_switch.o
PLUGIN_OBJS += plugin_function.o
PLUGIN_OBJS += plugin_xen.o
PLUGIN_OBJS += plugin_scsi.o
PLUGIN_OBJS += plugin_cfg80211.o
PLUGIN_OBJS += plugin_blk.o
PLUGIN_OBJS += plugin_tlb.o

PLUGINS := $(PLUGIN_OBJS:.o=.so)
DEPS := $(PLUGIN_OBJS:%.o=.%.d)

all: $(PLUGINS)

$(PLUGIN_OBJS): %.o : %.c
	$(Q)$(do_compile_plugin_obj)

$(PLUGINS): %.so: %.o
	$(Q)$(do_plugin_build)

$(DEPS): .%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(PLUGIN_OBJS): %.o : .%.d

CFLAGS_plugin_python.o += $(PYTHON_DIR_SQ)

plugin_python.o: %.o : %.c trace_python_dir
	$(Q)$(do_compile_python_plugin_obj)

plugin_python.so: %.so: %.o
	$(Q)$(do_python_plugin_build)

PLUGINS_INSTALL = $(subst .so,.install,$(PLUGINS)) $(subst .so,.install,$(PYTHON_PLUGINS))

$(PLUGINS_INSTALL): %.install : %.so force
	$(Q)$(call do_install_data,$<,$(plugin_dir_SQ))

install_plugins: $(PLUGINS_INSTALL)

# The following targets are necessary to trigger a rebuild when $(PLUGIN_DIR)
# and $(PYTHON_DIR) change. Without them, a full clean build would necessary
# in order to get the binaries updated.

trace_plugin_dir: force
	$(Q)$(N)$(call update_dir, 'PLUGIN_DIR=$(PLUGIN_DIR)')

trace_python_dir: force
	$(Q)$(N)$(call update_dir, 'PYTHON_DIR=$(PYTHON_DIR)')


dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) *.a *.so *.o .*.d trace_plugin_dir trace_python_dir

force:
.PHONY: clean force