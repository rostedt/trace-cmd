
VERSION := $(TC_VERSION)
PATCHLEVEL := $(TC_PATCHLEVEL)
EXTRAVERSION := $(TC_EXTRAVERSION)

TC_VERSION := $(obj)/tracecmd/include/tc_version.h
TARGETS = trace-cmd $(TC_VERSION)

BUILDGUI := 0
include $(src)/scripts/utils.mk

TRACE_CMD_OBJS =
TRACE_CMD_OBJS += trace-cmd.o
TRACE_CMD_OBJS += trace-record.o
TRACE_CMD_OBJS += trace-read.o
TRACE_CMD_OBJS += trace-split.o
TRACE_CMD_OBJS += trace-listen.o
TRACE_CMD_OBJS += trace-stack.o
TRACE_CMD_OBJS += trace-hist.o
TRACE_CMD_OBJS += trace-mem.o
TRACE_CMD_OBJS += trace-snapshot.o
TRACE_CMD_OBJS += trace-stat.o
TRACE_CMD_OBJS += trace-profile.o
TRACE_CMD_OBJS += trace-stream.o
TRACE_CMD_OBJS += trace-record.o
TRACE_CMD_OBJS += trace-restore.o
TRACE_CMD_OBJS += trace-check-events.o
TRACE_CMD_OBJS += trace-show.o
TRACE_CMD_OBJS += trace-list.o
TRACE_CMD_OBJS += trace-output.o
TRACE_CMD_OBJS += trace-usage.o
TRACE_CMD_OBJS += trace-msg.o

ALL_OBJS = $(TRACE_CMD_OBJS)

all_objs := $(sort $(ALL_OBJS))
all_deps := $(all_objs:%.o=.%.d)

CONFIG_INCLUDES =
CONFIG_LIBS	=
CONFIG_FLAGS	=

all: $(TARGETS)

$(TC_VERSION): force
	$(Q)$(call update_version.h)

trace-cmd: $(ALL_OBJS)
	$(Q)$(do_app_build)

trace-cmd: $(LIBTRACECMD_STATIC) $(LIBTRACEEVENT_STATIC)

%.o: %.c
	$(Q)$(call do_compile)

$(all_deps): .%.d: %.c
	$(Q)$(CC) -M $(CPPFLAGS) $(CFLAGS) $< > $@

$(all_deps): $(TC_VERSION)

$(all_objs): %.o : .%.d

dep_includes := $(wildcard $(DEPS))

ifneq ($(dep_includes),)
  include $(dep_includes)
endif

clean:
	$(RM) *.a *.so *.o .*.d $(TARGETS)

force:
.PHONY: clean
