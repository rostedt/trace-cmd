# trace-cmd version
TC_VERSION = 0
TC_PATCHLEVEL = 7
TC_EXTRAVERSION =

# Kernel Shark version
KS_VERSION = 0
KS_PATCHLEVEL = 2
KS_EXTRAVERSION =

# file format version
FILE_VERSION = 5

CC = gcc
AR = ar
EXT = -std=gnu99

MAKEFLAGS += --no-print-directory

LIBS = -L. -ltracecmd -ldl
LIB_FILE = libtracecmd.a

PACKAGES= gtk+-2.0

ifndef BUILDGUI
 BUILDGUI = 0
endif

ifeq ($(BUILDGUI), 1)

CONFIG_INCLUDES = $(shell pkg-config --cflags $(PACKAGES))

CONFIG_FLAGS = -DBUILDGUI \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

VERSION		= $(KS_VERSION)
PATCHLEVEL	= $(KS_PATCHLEVEL)
EXTRAVERSION	= $(KS_EXTRAVERSION)

GUI		= 'GUI '
GOBJ		= $@

REBUILD_GUI	= /bin/true
G		=
N 		= @/bin/true ||

else

CONFIG_INCLUDES = 
CONFIG_LIBS	=
CONFIG_FLAGS	=

VERSION		= $(TC_VERSION)
PATCHLEVEL	= $(TC_PATCHLEVEL)
EXTRAVERSION	= $(TC_EXTRAVERSION)

GUI		=
GOBJ		= "    "$@

REBUILD_GUI	= $(MAKE) BUILDGUI=1 $@
G		= $(REBUILD_GUI); /bin/true ||
N		=
endif

export Q VERBOSE

TRACECMD_VERSION = $(TC_VERSION).$(TC_PATCHLEVEL).$(TC_EXTRAVERSION)
KERNELSHARK_VERSION = $(KS_VERSION).$(KS_PATCHLEVEL).$(KS_EXTRAVERSION)

INCLUDES = -I. -I/usr/local/include $(CONFIG_INCLUDES)

CFLAGS = -g -Wall $(CONFIG_FLAGS) $(INCLUDES)

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

ifeq ($(VERBOSE),1)
  Q =
  print_compile =
  print_app_build =
  print_fpic_compile =
  print_shared_lib_compile =
  print_plugin_obj_compile =
  print_plugin_build =
else
  Q = @
  print_compile =		echo '  $(GUI)COMPILE            '$(GOBJ);
  print_app_build =		echo '  $(GUI)BUILD              '$(GOBJ);
  print_fpic_compile =		echo '  $(GUI)COMPILE FPIC       '$(GOBJ);
  print_shared_lib_compile =	echo '  $(GUI)COMPILE SHARED LIB '$(GOBJ);
  print_plugin_obj_compile =	echo '  $(GUI)COMPILE PLUGIN OBJ '$(GOBJ);
  print_plugin_build =		echo '  $(GUI)BUILD PLUGIN       '$(GOBJ);
  print_static_lib_build =	echo '  $(GUI)BUILD STATIC LIB   '$(GOBJ);
endif

do_fpic_compile =					\
	($(print_fpic_compile)				\
	$(CC) -c $(CFLAGS) $(EXT) -fPIC $< -o $@)

do_app_build =						\
	($(print_app_build)				\
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS))

do_compile_shared_library =			\
	($(print_shared_lib_compile)		\
	$(CC) --shared $^ -o $@)

do_compile_plugin_obj =				\
	($(print_plugin_obj_compile)		\
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<)

do_plugin_build =				\
	($(print_plugin_build)			\
	$(CC) -shared -nostartfiles -o $@ $<)

do_build_static_lib =				\
	($(print_static_lib_build)		\
	$(RM) $@;  $(AR) rcs $@ $^)


define check_gui
	if [ $(BUILDGUI) -ne 1 -a ! -z "$(filter $(gui_objs),$(@))" ];	then	\
		$(REBUILD_GUI);							\
	else									\
		$(print_compile)						\
		$(CC) -c $(CFLAGS) $(EXT) $< -o $@;				\
	fi;
endef

%.o: %.c
	$(Q)$(call check_gui)


TRACE_CMD_OBJS = trace-cmd.o trace-read.o trace-split.o
TRACE_VIEW_OBJS = trace-view.o trace-view-store.o trace-filter.o trace-compat.o \
	trace-hash.o
TRACE_GRAPH_OBJS = trace-graph.o trace-compat.o trace-hash.o trace-filter.o
TRACE_VIEW_MAIN_OBJS = trace-view-main.o $(TRACE_VIEW_OBJS)
TRACE_GRAPH_MAIN_OBJS = trace-graph-main.o $(TRACE_GRAPH_OBJS)
KERNEL_SHARK_OBJS = $(TRACE_VIEW_OBJS) $(TRACE_GRAPH_OBJS) kernel-shark.o

PEVENT_LIB_OBJS = parse-events.o trace-seq.o
TCMD_LIB_OBJS = $(PEVENT_LIB_OBJS) trace-util.o trace-input.o trace-ftrace.o \
			trace-output.o trace-record.o

PLUGIN_OBJS = plugin_hrtimer.o plugin_kmem.o plugin_sched_switch.o \
	plugin_mac80211.o

PLUGINS := $(PLUGIN_OBJS:.o=.so)

ALL_OBJS = $(TRACE_CMD_OBJS) $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_OBJS) $(TRACE_GRAPH_OBJS) \
	$(TCMD_LIB_OBJS) $(PLUGIN_OBJS)

CMD_TARGETS = tc_version.h libparsevent.a $(LIB_FILE) trace-cmd  $(PLUGINS)

GUI_TARGETS = ks_version.h trace-graph trace-view kernelshark

TARGETS = $(CMD_TARGETS) $(GUI_TARGETS)


#	cpp $(INCLUDES)

###
#    Default we just build trace-cmd
#
#    If you want kernelshark, then do:  make gui
###

all: $(CMD_TARGETS) show_gui_make

gui: $(CMD_TARGETS)
	$(Q)$(MAKE) BUILDGUI=1 all_gui

all_gui: $(GUI_TARGETS) show_gui_done

GUI_OBJS = $(KERNEL_SHARK_OBJS) $(TRACE_VIEW_MAIN_OBJS) $(TRACE_GRAPH_MAIN_OBJS)

gui_objs := $(sort $(GUI_OBJS))

trace-cmd: $(TRACE_CMD_OBJS)
	$(Q)$(do_app_build)

kernelshark: $(KERNEL_SHARK_OBJS)
	$(Q)$(G)$(do_app_build)

trace-view: $(TRACE_VIEW_MAIN_OBJS)
	$(Q)$(G)$(do_app_build)

trace-graph: $(TRACE_GRAPH_MAIN_OBJS)
	$(Q)$(G)$(do_app_build)

trace-cmd: libtracecmd.a
kernelshark: libtracecmd.a
trace-view: libtracecmd.a
trace-graph: libtracecmd.a

libparsevent.so: $(PEVENT_LIB_OBJS)
	$(Q)$(do_compile_shared_library)

libparsevent.a: $(PEVENT_LIB_OBJS)
	$(Q)$(do_build_static_lib)

$(TCMD_LIB_OBJS): %.o: %.c
	$(Q)$(do_fpic_compile)

libtracecmd.so: $(TCMD_LIB_OBJS)
	$(Q)$(do_compile_shared_library)

libtracecmd.a: $(TCMD_LIB_OBJS)
	$(Q)$(do_build_static_lib)

$(PLUGIN_OBJS): %.o : %.c
	$(Q)$(do_compile_plugin_obj)

$(PLUGINS): %.so: %.o
	$(Q)$(do_plugin_build)

define make_version.h
	(echo \#define VERSION_CODE $(shell						\
	expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
	echo '#define EXTRAVERSION ' $(EXTRAVERSION);					\
	echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL)$(EXTRAVERSION)'"';	\
	echo '#define FILE_VERSION '$(FILE_VERSION);					\
	) > $1
endef

define update_version.h
	($(call make_version.h, $@.tmp);		\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then		\
		rm -f $@.tmp;				\
	else						\
		echo '  UPDATE                 $@';	\
		mv -f $@.tmp $@;			\
	fi);
endef

ks_version.h: force
	$(Q)$(G)$(call update_version.h)

tc_version.h: force
	$(Q)$(N)$(call update_version.h)

## make deps

all_objs := $(sort $(ALL_OBJS))
all_deps := $(all_objs:%.o=.%.d)
gui_deps := $(gui_objs:%.o=.%.d)
non_gui_deps = $(filter-out $(gui_deps),$(all_deps))

define check_gui_deps
	if [ ! -z "$(filter $(gui_deps),$(@))" ];	then	\
		if [ $(BUILDGUI) -ne 1 ]; then			\
			$(REBUILD_GUI);				\
		else						\
			$(CC) -M $(CFLAGS) $< > $@;		\
		fi						\
	elif [ $(BUILDGUI) -eq 0 ]; then			\
		$(CC) -M $(CFLAGS) $< > $@;			\
	else							\
		echo SKIPPING $@;				\
	fi;
endef

$(gui_deps): ks_version.h
$(non_gui_deps): tc_version.h

$(all_deps): .%.d: %.c
	$(Q)$(call check_gui_deps)

$(all_objs) : %.o : .%.d

ifeq ($(BUILDGUI), 1)
dep_includes := $(wildcard $(gui_deps))
else
dep_includes := $(wildcard $(non_gui_deps))
endif

ifneq ($(dep_includes),)
 include $(dep_includes)
endif

show_gui_make:
	@echo "*** to build the gui, type \"make gui\" ***"

show_gui_done:
	@echo "*** gui build complete ***"

.PHONY: force show_gui_make
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c .*.d


##### PYTHON STUFF #####

PYTHON_INCLUDES = `python-config --includes`
PYGTK_CFLAGS = `pkg-config --cflags pygtk-2.0`

ctracecmd.so: $(TCMD_LIB_OBJS)
	swig -Wall -python -noproxy ctracecmd.i
	gcc -fpic -c $(PYTHON_INCLUDES)  ctracecmd_wrap.c
	$(CC) --shared $^ ctracecmd_wrap.o -o ctracecmd.so

ctracecmdgui.so: $(TRACE_VIEW_OBJS) $(LIB_FILE)
	swig -Wall -python -noproxy ctracecmdgui.i
	gcc -fpic -c  $(CFLAGS) $(INCLUDES) $(PYTHON_INCLUDES) $(PYGTK_CFLAGS) ctracecmdgui_wrap.c
	$(CC) --shared $^ $(LIBS) $(CONFIG_LIBS) ctracecmdgui_wrap.o -o ctracecmdgui.so

.PHONY: python
python: ctracecmd.so

.PHONY: python-gui
python-gui: ctracecmd.so ctracecmdgui.so 
