# SPDX-License-Identifier: GPL-2.0

doc_dir:=$(src)/Documentation

export doc_dir

SUBDIR += trace-cmd
SUBDIR += libtracecmd

.PHONY: $(SUBDIR)

DOCDIR = $(src)/Documentation
ASCIIDOC=asciidoc
ASCIIDOC_CONF	 =  $(DOCDIR)/asciidoc.conf
ASCIIDOC_EXTRA = --unsafe -f $(ASCIIDOC_CONF)
ASCIIDOC_HTML = xhtml11
MANPAGE_XSL = $(DOCDIR)/manpage-normal.xsl
XMLTO_EXTRA =
INSTALL?=install
RM ?= rm -f

ASCIIDOC_INSTALLED := $(shell command -v $(ASCIIDOC) 2> /dev/null)
ifndef ASCIIDOC_INSTALLED
	missing_tools += $(ASCIIDOC)
endif

XMLTO=xmlto
XMLTO_INSTALLED := $(shell command -v $(XMLTO) 2> /dev/null)
ifndef XMLTO_INSTALLED
	missing_tools += $(XMLTO)
endif

#
# For asciidoc ...
#	-7.1.2,	no extra settings are needed.
#	8.0-,	set ASCIIDOC8.
#

#
# For docbook-xsl ...
#	-1.68.1,	set ASCIIDOC_NO_ROFF? (based on changelog from 1.73.0)
#	1.69.0,		no extra settings are needed?
#	1.69.1-1.71.0,	set DOCBOOK_SUPPRESS_SP?
#	1.71.1,		no extra settings are needed?
#	1.72.0,		set DOCBOOK_XSL_172.
#	1.73.0-,	set ASCIIDOC_NO_ROFF
#

#
# If you had been using DOCBOOK_XSL_172 in an attempt to get rid
# of 'the ".ft C" problem' in your generated manpages, and you
# instead ended up with weird characters around callouts, try
# using ASCIIDOC_NO_ROFF instead (it works fine with ASCIIDOC8).
#

ifdef ASCIIDOC8
ASCIIDOC_EXTRA += -a asciidoc7compatible
endif
ifdef DOCBOOK_XSL_172
ASCIIDOC_EXTRA += -a libtracecmd-asciidoc-no-roff
MANPAGE_XSL = $(DOCDIR)/manpage-1.72.xsl
else
	ifdef ASCIIDOC_NO_ROFF
	# docbook-xsl after 1.72 needs the regular XSL, but will not
	# pass-thru raw roff codes from asciidoc.conf, so turn them off.
	ASCIIDOC_EXTRA += -a libtracecmd-asciidoc-no-roff
	endif
endif
ifdef MAN_BOLD_LITERAL
XMLTO_EXTRA += -m $(DOCDIR)/manpage-bold-literal.xsl
endif
ifdef DOCBOOK_SUPPRESS_SP
XMLTO_EXTRA += -m $(DOCDIR)/manpage-suppress-sp.xsl
endif

ifdef USE_ASCIIDOCTOR
ASCIIDOC = asciidoctor
ASCIIDOC_EXTRA = -a compat-mode
ASCIIDOC_EXTRA += -I. -rasciidoctor-extensions
ASCIIDOC_HTML = xhtml5
endif

ifneq ($(findstring $(MAKEFLAGS),w),w)
PRINT_DIR = --no-print-directory
else # "make -w"
NO_SUBDIR = :
endif

export ASCIIDOC ASCIIDOC_CONF ASCIIDOC_EXTRA ASCIIDOC_HTML
export MANPAGE_XSL
export XMLTO XMLTO_INSTALLED XMLTO_EXTRA
export  missing_tools
export RM

all: $(SUBDIR)
clean: $(SUBDIR)
install: $(SUBDIR)

$(SUBDIR):
	make -C $@ $(MAKECMDGOALS)

