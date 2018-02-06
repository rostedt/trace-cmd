# Kernel Shark version

VERSION		= 0
PATCHLEVEL	= 2
EXTRAVERSION	=
KERNELSHARK_VERSION = $(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)

BUILDGUI := 1
include $(src)/scripts/utils.mk


PACKAGES = gtk+-2.0 libxml-2.0 gthread-2.0

CONFIG_INCLUDES = $(shell pkg-config --cflags $(PACKAGES)) -I$(obj)

CONFIG_FLAGS = -DBUILDGUI \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

CONFIG_FLAGS += $(HELP_DIR_SQ)

KS_VERSION := $(obj)/kernel-shark/include/ks_version.h

GUI_TARGETS = $(KS_VERSION) trace-graph trace-view kernelshark

TRACE_GUI_OBJS = trace-filter.o trace-compat.o trace-filter-hash.o \
		 trace-dialog.o trace-xml.o
TRACE_VIEW_OBJS = trace-view.o trace-view-store.o
TRACE_GRAPH_OBJS = trace-graph.o trace-plot.o trace-plot-cpu.o trace-plot-task.o
TRACE_VIEW_MAIN_OBJS = trace-view-main.o $(TRACE_VIEW_OBJS) $(TRACE_GUI_OBJS)
TRACE_GRAPH_MAIN_OBJS = trace-graph-main.o $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS)
KERNEL_SHARK_OBJS = $(TRACE_VIEW_OBJS) $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS) \
	trace-capture.o kernel-shark.o

GUI_OBJS = $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_MAIN_OBJS) $(TRACE_GRAPH_MAIN_OBJS)

all_objs := $(sort $(GUI_OBJS))
all_deps := $(all_objs:%.o=.%.d)

# Temporary HACK!
# This hack is OK only until the non-gui builds do not have any config_includes
# nor config flags. In case they do, keeping this hack might be a problem.
override CFLAGS += $(CONFIG_INCLUDES) $(CONFIG_FLAGS)

LIBS += -L$(LIBTRACEEVENT_DIR) -L$(LIBTRACECMD_DIR)
LIBS += -ltracecmd -ltraceevent -ldl

all: $(GUI_TARGETS)

$(KS_VERSION): force
	$(Q)$(call update_version.h)

kernelshark: $(KERNEL_SHARK_OBJS)
	$(Q)$(do_app_build)

trace-view: $(TRACE_VIEW_MAIN_OBJS)
	$(Q)$(do_app_build)

trace-graph: $(TRACE_GRAPH_MAIN_OBJS)
	$(Q)$(do_app_build)

%.o: %.c
	$(Q)$(call do_compile)

$(all_deps): .%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(all_deps): $(KS_VERSION)

$(GUI_OBJS): %.o : .%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) *.a *.so *.o .*.d $(GUI_TARGETS)

force:
.PHONY: clean
