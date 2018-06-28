# Kernel Shark version

VERSION		= 0
PATCHLEVEL	= 2
EXTRAVERSION	=
KERNELSHARK_VERSION = $(VERSION).$(PATCHLEVEL).$(EXTRAVERSION)

bdir:=$(obj)/kernel-shark

BUILDGUI := 1
include $(src)/scripts/utils.mk


PACKAGES = gtk+-2.0 libxml-2.0 gthread-2.0

CONFIG_INCLUDES = $(shell pkg-config --cflags $(PACKAGES)) -I$(obj)

CONFIG_FLAGS = -DBUILDGUI \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

CONFIG_FLAGS += $(HELP_DIR_SQ)

KS_VERSION := $(bdir)/include/ks_version.h

GUI_TARGETS = $(KS_VERSION) $(bdir)/trace-graph $(bdir)/trace-view $(bdir)/kernelshark

TRACE_GUI_OBJS = trace-filter.o trace-compat.o \
		 trace-dialog.o trace-xml.o
TRACE_VIEW_OBJS = trace-view.o trace-view-store.o
TRACE_GRAPH_OBJS = trace-graph.o trace-plot.o trace-plot-cpu.o trace-plot-task.o
TRACE_VIEW_MAIN_OBJS = trace-view-main.o $(TRACE_VIEW_OBJS) $(TRACE_GUI_OBJS)
TRACE_GRAPH_MAIN_OBJS = trace-graph-main.o $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS)
KERNEL_SHARK_OBJS = $(TRACE_VIEW_OBJS) $(TRACE_GRAPH_OBJS) $(TRACE_GUI_OBJS) \
	trace-capture.o kernel-shark.o

KERNEL_SHARK_OBJS := $(KERNEL_SHARK_OBJS:%.o=$(bdir)/%.o)
TRACE_VIEW_MAIN_OBJS := $(TRACE_VIEW_MAIN_OBJS:%.o=$(bdir)/%.o)
TRACE_GRAPH_MAIN_OBJS := $(TRACE_GRAPH_MAIN_OBJS:%.o=$(bdir)/%.o)

ALL_OBJS = $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_MAIN_OBJS) $(TRACE_GRAPH_MAIN_OBJS)
PIC_OBJS = $(TRACE_VIEW_OBJS)

all_objs := $(sort $(ALL_OBJS))
pic_objs = $(sort $(PIC_OBJS))
all_deps := $(all_objs:$(bdir)/%.o=$(bdir)/.%.d)

override CFLAGS += $(CONFIG_INCLUDES) $(CONFIG_FLAGS)

LIBS += -L$(LIBTRACEEVENT_DIR) -L$(LIBTRACECMD_DIR)
LIBS += -ltracecmd -ltraceevent -ldl

all: $(GUI_TARGETS)

$(bdir):
	@mkdir -p $(bdir)

$(bdir)/include: | $(bdir)
	@mkdir -p $(bdir)/include

$(all_objs): | $(bdir)
$(all_deps): | $(bdir)

$(KS_VERSION): force | $(bdir)/include
	$(Q)$(call update_version.h)

$(bdir)/kernelshark: $(KERNEL_SHARK_OBJS) $(LIBTRACEEVENT_STATIC) $(LIBTRACECMD_STATIC)
	$(Q)$(do_app_build)

$(bdir)/trace-view: $(TRACE_VIEW_MAIN_OBJS) $(LIBTRACEEVENT_STATIC) $(LIBTRACECMD_STATIC)
	$(Q)$(do_app_build)

$(bdir)/trace-graph: $(TRACE_GRAPH_MAIN_OBJS) $(LIBTRACEEVENT_STATIC) $(LIBTRACECMD_STATIC)
	$(Q)$(do_app_build)

$(pic_objs): GENERATE_PIC := 1

$(bdir)/%.o: %.c
	$(Q)$(call do_compile)

$(all_deps): $(bdir)/.%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(all_deps): $(KS_VERSION)

$(all_objs): $(bdir)/%.o : $(bdir)/.%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) $(bdir)/*.a $(bdir)/*.so $(bdir)/*.o $(bdir)/.*.d $(GUI_TARGETS)

force:
.PHONY: clean
