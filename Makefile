# trace-cmd version
TC_VERSION = 0
TC_PATCHLEVEL = 6
TC_EXTRAVERSION =

# Kernel Shark version
KS_VERSION = 0
KS_PATCHLEVEL = 1
KS_EXTRAVERSION =

# file format version
FILE_VERSION = 0

CC = gcc
AR = ar
EXT = -std=gnu99
INCLUDES = -I. -I/usr/local/include

LIBS = -L. -ltracecmd -ldl

PACKAGES= gtk+-2.0

ifeq ($(BUILDGUI), 1)
CONFIG_FLAGS = $(shell pkg-config --cflags $(PACKAGES)) -DBUILDGUI \
	-DGTK_VERSION=$(shell pkg-config --modversion gtk+-2.0 | \
	awk 'BEGIN{FS="."}{ a = ($$1 * (2^16)) + $$2 * (2^8) + $$3; printf ("%d", a);}')

CONFIG_LIBS = $(shell pkg-config --libs $(PACKAGES))

VERSION		= $(KS_VERSION)
PATCHLEVEL	= $(KS_PATCHLEVEL)
EXTRAVERSION	= $(KS_EXTRAVERSION)

GUI		= 'GUI '
GOBJ		= $@

else

CONFIG_LIBS	=
CONFIG_FLAGS	=

VERSION		= $(TC_VERSION)
PATCHLEVEL	= $(TC_PATCHLEVEL)
EXTRAVERSION	= $(TC_EXTRAVERSION)

GUI		=
GOBJ		= "    "$@

endif

TRACECMD_VERSION = $(TC_VERSION).$(TC_PATCHLEVEL).$(TC_EXTRAVERSION)
KERNELSHARK_VERSION = $(KS_VERSION).$(KS_PATCHLEVEL).$(KS_EXTRAVERSION)

CFLAGS = -g -Wall $(CONFIG_FLAGS)

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
else
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
  print_compile =		@echo '  $(GUI)COMPILE            '$(GOBJ);
  print_app_build =		@echo '  $(GUI)BUILD              '$(GOBJ);
  print_fpic_compile =		@echo '  $(GUI)COMPILE FPIC       '$(GOBJ);
  print_shared_lib_compile =	@echo '  $(GUI)COMPILE SHARED LIB '$(GOBJ);
  print_plugin_obj_compile =	@echo '  $(GUI)COMPILE PLUGIN OBJ '$(GOBJ);
  print_plugin_build =		@echo '  $(GUI)BUILD PLUGIN       '$(GOBJ);
  print_static_lib_build =	@echo '  $(GUI)BUILD STATIC LIB   '$(GOBJ);
endif

do_fpic_compile =							\
	$(Q)$(print_fpic_compile)					\
	$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) -fPIC $< -o $@

do_app_build =						\
	$(Q)$(print_app_build)				\
	$(CC) $^ -rdynamic -o $@ $(CONFIG_LIBS) $(LIBS)

do_compile_shared_library =			\
	$(Q)$(print_shared_lib_compile)		\
	$(CC) --shared $^ -o $@

do_compile_plugin_obj =				\
	$(Q)$(print_plugin_obj_compile)		\
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

do_plugin_build =				\
	$(Q)$(print_plugin_build)		\
	$(CC) -shared -nostartfiles -o $@ $<

do_build_static_lib =				\
	$(Q)$(print_static_lib_build)		\
	$(RM) $@;  $(AR) rcs $@ $^

%.o: %.c
	$(print_compile)
	$(Q)$(CC) -c $(CFLAGS) $(EXT) $(INCLUDES) $< -o $@

PLUGINS =  plugin_hrtimer.so plugin_mac80211.so plugin_sched_switch.so \
	plugin_kmem.so

CMD_TARGETS = tc_version.h libparsevent.a libtracecmd.a trace-cmd  $(PLUGINS)

GUI_TARGETS = ks_version.h trace-graph trace-view kernelshark

TARGETS = $(CMD_TARGETS) $(GUI_TARGETS)

###
#    Default we just build trace-cmd
#
#    If you want kernelshark, then do:  make gui
###

all: $(CMD_TARGETS)

gui:	$(CMD_TARGETS)
	$(Q)$(MAKE) BUILDGUI=1 all_gui

all_gui: $(GUI_TARGETS)

LIB_FILE = libtracecmd.a

HEADERS = parse-events.h trace-cmd.h trace-local.h trace-hash.h

trace-read.o::		$(HEADERS) 
trace-cmd.o::		$(HEADERS) $(LIB_FILE) tc_version.h
trace-util.o::		$(HEADERS)
trace-ftrace.o::	$(HEADERS)
trace-input.o::		$(HEADERS)
trace-view.o::		$(HEADERS) trace-view-store.h trace-view.h
trace-view-store.o::	$(HEADERS) trace-view-store.h trace-view.h
trace-view-main.o::	$(HEADERS) trace-view-store.h trace-view.h libtracecmd.a
trace-filter.o::	$(HEADERS)
trace-graph.o::		$(HEADERS) trace-graph.h
trace-graph-main.o::	$(HEADERS) trace-graph.h libtracecmd.a
kernel-shark.o::	$(HEADERS) kernel-shark.h libtracecmd.a ks_version.h

TRACE_VIEW_OBJS = trace-view.o trace-view-store.o trace-filter.o trace-compat.o \
	trace-hash.o

trace-cmd:: trace-cmd.o trace-read.o
	$(do_app_build)

trace-view:: trace-view-main.o $(TRACE_VIEW_OBJS)
	$(do_app_build)

trace-graph:: trace-graph-main.o trace-graph.o trace-compat.o trace-hash.o trace-filter.o
	$(do_app_build)

ifeq ($(BUILDGUI), 1)
kernelshark:: kernel-shark.o trace-compat.o $(TRACE_VIEW_OBJS) trace-graph.o \
		trace-hash.o
	$(do_app_build)
else
kernelshark: force
	@echo '**************************************'
	@echo '** To build kernel shark:  make gui **'
	@echo '**************************************'
endif

.PHONY: gtk_depends
view_depends:
	@pkg-config --cflags $(PACKAGES)

trace-view.o::		parse-events.h
trace-graph.o::		parse-events.h

parse-events.o: parse-events.c parse-events.h
	$(do_fpic_compile)

trace-seq.o: trace-seq.c parse-events.h
	$(do_fpic_compile)

trace-util.o:: trace-util.c
	$(do_fpic_compile)

trace-input.o:: trace-input.c
	$(do_fpic_compile)

trace-output.o:: trace-output.c
	$(do_fpic_compile)

trace-record.o:: trace-record.c
	$(do_fpic_compile)

trace-ftrace.o:: trace-ftrace.c
	$(do_fpic_compile)

PEVENT_LIB_OBJS = parse-events.o trace-seq.o

libparsevent.so: $(PEVENT_LIB_OBJS)
	$(do_compile_shared_library)

libparsevent.a: $(PEVENT_LIB_OBJS)
	$(do_build_static_lib)

TCMD_LIB_OBJS = $(PEVENT_LIB_OBJS) trace-util.o trace-input.o trace-ftrace.o \
			trace-output.o trace-record.o

libtracecmd.so: $(TCMD_LIB_OBJS)
	$(do_compile_shared_library)

libtracecmd.a: $(TCMD_LIB_OBJS)
	$(do_build_static_lib)

plugin_hrtimer.o: plugin_hrtimer.c parse-events.h trace-cmd.h
	$(do_compile_plugin_obj)

plugin_hrtimer.so: plugin_hrtimer.o
	$(do_plugin_build)

plugin_kmem.o: plugin_kmem.c parse-events.h trace-cmd.h
	$(do_compile_plugin_obj)

plugin_kmem.so: plugin_kmem.o
	$(do_plugin_build)

plugin_sched_switch.o: plugin_sched_switch.c parse-events.h trace-cmd.h
	$(do_compile_plugin_obj)

plugin_sched_switch.so: plugin_sched_switch.o
	$(do_plugin_build)

plugin_mac80211.o: plugin_mac80211.c parse-events.h trace-cmd.h
	$(do_compile_plugin_obj)

plugin_mac80211.so: plugin_mac80211.o
	$(do_plugin_build)

define make_version.h
	@(echo \#define VERSION_CODE $(shell						\
	expr $(VERSION) \* 256 + $(PATCHLEVEL));					\
	echo '#define EXTRAVERSION ' $(EXTRAVERSION);					\
	echo '#define VERSION_STRING "'$(VERSION).$(PATCHLEVEL)$(EXTRAVERSION)'"';	\
	echo '#define FILE_VERSION '$(FILE_VERSION);					\
	) > $1
endef

define update_version.h
	$(call make_version.h, $@.tmp);		\
	if [ -r $@ ] && cmp -s $@ $@.tmp; then	\
		rm -f $@.tmp;			\
	else					\
		echo '  UPD $@';		\
		mv -f $@.tmp $@;		\
	fi;
endef

ks_version.h: force
	$(call update_version.h)

tc_version.h: force
	$(call update_version.h)

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

.PHONY: force
force:

TAGS:	force
	find . -name '*.[ch]' | xargs etags

clean:
	$(RM) *.o *~ $(TARGETS) *.a *.so ctracecmd_wrap.c
