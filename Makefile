# SPDX-License-Identifier: GPL-2.0
# trace-cmd version
TC_VERSION = 2
TC_PATCHLEVEL = 8
TC_EXTRAVERSION = 3
TRACECMD_VERSION = $(TC_VERSION).$(TC_PATCHLEVEL).$(TC_EXTRAVERSION)

export TC_VERSION
export TC_PATCHLEVEL
export TC_EXTRAVERSION
export TRACECMD_VERSION

# file format version
FILE_VERSION = 6

MAKEFLAGS += --no-print-directory

# Makefiles suck: This macro sets a default value of $(2) for the
# variable named by $(1), unless the variable has been set by
# environment or command line. This is necessary for CC and AR
# because make sets default values, so the simpler ?= approach
# won't work as expected.
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

# Allow setting CC and AR, or setting CROSS_COMPILE as a prefix.
$(call allow-override,CC,$(CROSS_COMPILE)gcc)
$(call allow-override,AR,$(CROSS_COMPILE)ar)

EXT = -std=gnu99
INSTALL = install

# Use DESTDIR for installing into a different root directory.
# This is useful for building a package. The program will be
# installed in this directory as if it was the root directory.
# Then the build tool can move it later.
DESTDIR ?=
DESTDIR_SQ = '$(subst ','\'',$(DESTDIR))'

prefix ?= /usr/local
bindir_relative = bin
bindir = $(prefix)/$(bindir_relative)
man_dir = $(prefix)/share/man
man_dir_SQ = '$(subst ','\'',$(man_dir))'
html_install = $(prefix)/share/kernelshark/html
html_install_SQ = '$(subst ','\'',$(html_install))'
img_install = $(prefix)/share/kernelshark/html/images
img_install_SQ = '$(subst ','\'',$(img_install))'
libdir ?= $(prefix)/lib
libdir_SQ = '$(subst ','\'',$(libdir))'
includedir = $(prefix)/include/trace-cmd
includedir_SQ = '$(subst ','\'',$(includedir))'

export man_dir man_dir_SQ html_install html_install_SQ INSTALL
export img_install img_install_SQ
export DESTDIR DESTDIR_SQ

ifeq ($(prefix),$(HOME))
plugin_dir = $(HOME)/.trace-cmd/plugins
python_dir = $(HOME)/.trace-cmd/python
var_dir = $(HOME)/.trace-cmd/
else
plugin_dir = $(libdir)/trace-cmd/plugins
python_dir ?= $(libdir)/trace-cmd/python
PLUGIN_DIR = -DPLUGIN_DIR="$(plugin_dir)"
PYTHON_DIR = -DPYTHON_DIR="$(python_dir)"
PLUGIN_DIR_SQ = '$(subst ','\'',$(PLUGIN_DIR))'
PYTHON_DIR_SQ = '$(subst ','\'',$(PYTHON_DIR))'
var_dir = /var
endif

# Shell quotes
bindir_SQ = $(subst ','\'',$(bindir))
bindir_relative_SQ = $(subst ','\'',$(bindir_relative))
plugin_dir_SQ = $(subst ','\'',$(plugin_dir))
python_dir_SQ = $(subst ','\'',$(python_dir))

VAR_DIR = -DVAR_DIR="$(var_dir)"
VAR_DIR_SQ = '$(subst ','\'',$(VAR_DIR))'
var_dir_SQ = '$(subst ','\'',$(var_dir))'

HELP_DIR = -DHELP_DIR=$(html_install)
HELP_DIR_SQ = '$(subst ','\'',$(HELP_DIR))'
#' emacs highlighting gets confused by the above escaped quote.

BASH_COMPLETE_DIR ?= /etc/bash_completion.d

export PLUGIN_DIR
export PYTHON_DIR
export PYTHON_DIR_SQ
export plugin_dir_SQ
export python_dir_SQ
export var_dir

# copy a bit from Linux kbuild

ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif

SWIG_DEFINED := $(shell if command -v swig; then echo 1; else echo 0; fi)
ifeq ($(SWIG_DEFINED), 0)
BUILD_PYTHON := report_noswig
NO_PYTHON = 1
endif

ifndef NO_PYTHON
PYTHON		:= ctracecmd.so
PYTHON_GUI	:= ctracecmd.so ctracecmdgui.so

PYTHON_VERS ?= python

# Can build python?
ifeq ($(shell sh -c "pkg-config --cflags $(PYTHON_VERS) > /dev/null 2>&1 && echo y"), y)
	PYTHON_PLUGINS := plugin_python.so
	BUILD_PYTHON := $(PYTHON) $(PYTHON_PLUGINS)
	BUILD_PYTHON_WORKS := 1
else
	BUILD_PYTHON := report_nopythondev
	NO_PYTHON = 1
endif
endif # NO_PYTHON

export PYTHON_PLUGINS
export BUILD_PYTHON_WORKS
export NO_PYTHON

# $(call test-build, snippet, ret) -> ret if snippet compiles
#                                  -> empty otherwise
test-build = $(if $(shell sh -c 'echo "$(1)" | \
	$(CC) -o /dev/null -c -x c - > /dev/null 2>&1 && echo y'), $2)

UDIS86_AVAILABLE := $(call test-build,\#include <udis86.h>, y)
ifneq ($(strip $(UDIS86_AVAILABLE)), y)
NO_UDIS86 := 1
endif

ifndef NO_UDIS86
# have udis86 disassembler library?
udis86-flags := -DHAVE_UDIS86 -ludis86
udis86-ldflags := -ludis86
endif # NO_UDIS86

define BLK_TC_FLUSH_SOURCE
#include <linux/blktrace_api.h>
int main(void) { return BLK_TC_FLUSH; }
endef

# have flush/fua block layer instead of barriers?
blk-flags := $(call test-build,$(BLK_TC_FLUSH_SOURCE),-DHAVE_BLK_TC_FLUSH)

ifeq ("$(origin O)", "command line")

  saved-output := $(O)
  BUILD_OUTPUT := $(shell cd $(O) && /bin/pwd)
  $(if $(BUILD_OUTPUT),, \
    $(error output directory "$(saved-output)" does not exist))

else
  BUILD_OUTPUT = $(CURDIR)
endif

srctree		:= $(if $(BUILD_SRC),$(BUILD_SRC),$(CURDIR))
objtree		:= $(BUILD_OUTPUT)
src		:= $(srctree)
obj		:= $(objtree)

kshark-dir	= $(src)/kernel-shark

export prefix bindir src obj

LIBS = -ldl

LIBTRACEEVENT_DIR = $(obj)/lib/traceevent
LIBTRACEEVENT_STATIC = $(LIBTRACEEVENT_DIR)/libtraceevent.a
LIBTRACEEVENT_SHARED = $(LIBTRACEEVENT_DIR)/libtraceevent.so

LIBTRACECMD_DIR = $(obj)/lib/trace-cmd
LIBTRACECMD_STATIC = $(LIBTRACECMD_DIR)/libtracecmd.a
LIBTRACECMD_SHARED = $(LIBTRACECMD_DIR)/libtracecmd.so

TRACE_LIBS = -L$(LIBTRACECMD_DIR) -ltracecmd -L$(LIBTRACEEVENT_DIR) -ltraceevent

export LIBS TRACE_LIBS
export LIBTRACEEVENT_DIR LIBTRACECMD_DIR
export LIBTRACECMD_STATIC LIBTRACECMD_SHARED
export LIBTRACEEVENT_STATIC LIBTRACEEVENT_SHARED

export Q VERBOSE EXT

# Include the utils
include scripts/utils.mk

INCLUDES = -I$(src)/include -I$(src)/../../include
INCLUDES += -I$(src)/include/traceevent
INCLUDES += -I$(src)/include/trace-cmd
INCLUDES += -I$(src)/lib/traceevent/include
INCLUDES += -I$(src)/lib/trace-cmd/include
INCLUDES += -I$(src)/tracecmd/include
INCLUDES += -I$(obj)/tracecmd/include

include $(src)/features.mk

# Set compile option CFLAGS if not set elsewhere
CFLAGS ?= -g -Wall
CPPFLAGS ?=
LDFLAGS ?=

export CFLAGS
export INCLUDES

# Required CFLAGS
override CFLAGS += -D_GNU_SOURCE

ifndef NO_PTRACE
ifneq ($(call try-cc,$(SOURCE_PTRACE),),y)
	NO_PTRACE = 1
	override CFLAGS += -DWARN_NO_PTRACE
endif
endif

ifdef NO_PTRACE
override CFLAGS += -DNO_PTRACE
endif

ifndef NO_AUDIT
ifneq ($(call try-cc,$(SOURCE_AUDIT),-laudit),y)
	NO_AUDIT = 1
	override CFLAGS += -DWARN_NO_AUDIT
endif
endif

ifdef NO_AUDIT
override CFLAGS += -DNO_AUDIT
else
LIBS += -laudit
endif

# Append required CFLAGS
override CFLAGS += $(INCLUDES) $(PLUGIN_DIR_SQ) $(VAR_DIR)
override CFLAGS += $(udis86-flags) $(blk-flags)
override LDFLAGS += $(udis86-ldflags)

CMD_TARGETS = trace-cmd $(BUILD_PYTHON)

###
#    Default we just build trace-cmd
#
#    If you want kernelshark, then do:  make gui
###

all: all_cmd plugins show_gui_make

all_cmd: $(CMD_TARGETS)

CMAKE_COMMAND = /usr/bin/cmake

$(kshark-dir)/build/Makefile: $(kshark-dir)/CMakeLists.txt
	$(Q) cd $(kshark-dir)/build && $(CMAKE_COMMAND) -D_INSTALL_PREFIX=$(prefix) ..

gui: force $(CMD_TARGETS) $(kshark-dir)/build/Makefile
	$(Q)$(MAKE) $(S) -C $(kshark-dir)/build
	@echo "gui build complete"
	@echo "  kernelshark located at $(kshark-dir)/bin"

trace-cmd: force $(LIBTRACEEVENT_STATIC) $(LIBTRACECMD_STATIC)
	$(Q)$(MAKE) -C $(src)/tracecmd $(obj)/tracecmd/$@

$(LIBTRACEEVENT_SHARED): force
	$(Q)$(MAKE) -C $(src)/lib/traceevent $@

$(LIBTRACEEVENT_STATIC): force
	$(Q)$(MAKE) -C $(src)/lib/traceevent $@

$(LIBTRACECMD_STATIC): force $(obj)/plugins/trace_plugin_dir
	$(Q)$(MAKE) -C $(src)/lib/trace-cmd $@

$(LIBTRACECMD_SHARED): force $(obj)/plugins/trace_plugin_dir
	$(Q)$(MAKE) -C $(src)/lib/trace-cmd $@

libtraceevent.so: $(LIBTRACEEVENT_SHARED)
libtraceevent.a: $(LIBTRACEEVENT_STATIC)
libtracecmd.a: $(LIBTRACECMD_STATIC)
libtracecmd.so: $(LIBTRACECMD_SHARED)

libs: $(LIBTRACECMD_SHARED) $(LIBTRACEEVENT_SHARED)

plugins: force $(obj)/plugins/trace_plugin_dir $(obj)/plugins/trace_python_dir
	$(Q)$(MAKE) -C $(src)/plugins

$(obj)/plugins/trace_plugin_dir: force
	$(Q)$(MAKE) -C $(src)/plugins $@

$(obj)/plugins/trace_python_dir: force
	$(Q)$(MAKE) -C $(src)/plugins $@

show_gui_make:
	@echo "Note: to build the gui, type \"make gui\""
	@echo "      to build man pages, type \"make doc\""

PHONY += show_gui_make

define find_tag_files
	find . -name '\.pc' -prune -o -name '*\.[ch]' -print -o -name '*\.[ch]pp' \
		! -name '\.#' -print
endef

tags:	force
	$(RM) tags
	$(call find_tag_files) | xargs ctags --extra=+f --c-kinds=+px

TAGS:	force
	$(RM) TAGS
	$(call find_tag_files) | xargs etags

cscope: force
	$(RM) cscope*
	$(call find_tag_files) | cscope -b -q

install_plugins: force
	$(Q)$(MAKE) -C $(src)/plugins $@

install_python: force
	$(Q)$(MAKE) -C $(src)/python $@

install_bash_completion: force
	$(Q)$(call do_install_data,$(src)/tracecmd/trace-cmd.bash,$(BASH_COMPLETE_DIR))

install_cmd: all_cmd install_plugins install_python install_bash_completion
	$(Q)$(call do_install,$(obj)/tracecmd/trace-cmd,$(bindir_SQ))

install: install_cmd
	@echo "Note: to install the gui, type \"make install_gui\""
	@echo "      to install man pages, type \"make install_doc\""

install_gui: install_cmd gui
	$(Q)$(MAKE) $(S) -C $(kshark-dir)/build install

install_libs: libs
	$(Q)$(call do_install,$(LIBTRACECMD_SHARED),$(libdir_SQ))
	$(Q)$(call do_install,$(LIBTRACEEVENT_SHARED),$(libdir_SQ))
	$(Q)$(call do_install,$(src)/include/traceevent/event-parse.h,$(includedir_SQ)/traceevent)
	$(Q)$(call do_install,$(src)/include/traceevent/trace-seq.h,$(includedir_SQ)/traceevent)
	$(Q)$(call do_install,$(src)/include/trace-cmd/trace-cmd.h,$(includedir_SQ))
	$(Q)$(call do_install,$(src)/include/trace-cmd/trace-filter-hash.h,$(includedir_SQ))

doc:
	$(MAKE) -C $(src)/Documentation all

doc_clean:
	$(MAKE) -C $(src)/Documentation clean

install_doc:
	$(MAKE) -C $(src)/Documentation install

clean:
	$(RM) *.o *~ *.a *.so .*.d
	$(RM) tags TAGS cscope*
	$(MAKE) -C $(src)/lib/traceevent clean
	$(MAKE) -C $(src)/lib/trace-cmd clean
	$(MAKE) -C $(src)/plugins clean
	$(MAKE) -C $(src)/python clean
	$(MAKE) -C $(src)/tracecmd clean
	if [ -f $(kshark-dir)/build/Makefile ]; then $(MAKE) -C $(kshark-dir)/build clean; fi


##### PYTHON STUFF #####

report_noswig: force
	$(Q)echo
	$(Q)echo "    NO_PYTHON forced: swig not installed, not compiling python plugins"
	$(Q)echo

report_nopythondev: force
	$(Q)echo
	$(Q)echo "    python-dev is not installed, not compiling python plugins"
	$(Q)echo

ifndef NO_PYTHON
PYTHON_INCLUDES = `pkg-config --cflags $(PYTHON_VERS)`
PYTHON_LDFLAGS = `pkg-config --libs $(PYTHON_VERS)` \
		$(shell $(PYTHON_VERS)-config --ldflags)
PYGTK_CFLAGS = `pkg-config --cflags pygtk-2.0`
else
PYTHON_INCLUDES =
PYTHON_LDFLAGS =
PYGTK_CFLAGS =
endif

export PYTHON_INCLUDES
export PYTHON_LDFLAGS
export PYGTK_CFLAGS

ctracecmd.so: force $(LIBTRACECMD_STATIC)
	$(Q)$(MAKE) -C $(src)/python $@

ctracecmdgui.so: force $(LIBTRACECMD_STATIC) trace-view
	$(Q)$(MAKE) -C $(src)/python $@

PHONY += python
python: $(PYTHON)

PHONY += python-gui
python-gui: $(PYTHON_GUI)

PHONY += python-plugin
python-plugin: $(PYTHON_PLUGINS)

plugin_python.so: force $(obj)/plugins/trace_python_dir
	$(Q)$(MAKE) -C $(src)/plugins $(obj)/plugins/plugin_python.so

dist:
	git archive --format=tar --prefix=trace-cmd-$(TRACECMD_VERSION)/ HEAD \
		> ../trace-cmd-$(TRACECMD_VERSION).tar
	cat ../trace-cmd-$(TRACECMD_VERSION).tar | \
		bzip2 -c9 > ../trace-cmd-$(TRACECMD_VERSION).tar.bz2
	cat ../trace-cmd-$(TRACECMD_VERSION).tar | \
		xz -e -c8 > ../trace-cmd-$(TRACECMD_VERSION).tar.xz

PHONY += force
force:

# Declare the contents of the .PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
