# SPDX-License-Identifier: GPL-2.0

# Include the utils
include $(src)/scripts/utils.mk

# This Makefile and manpage XSL files were taken from libtracefs
# and modified for libtracecmd

MAN3_TXT= \
	$(wildcard libtracecmd-*.txt) \
	libtracecmd.txt

MAN_TXT = $(MAN3_TXT)
_MAN_XML=$(patsubst %.txt,%.xml,$(MAN_TXT))
_MAN_HTML=$(patsubst %.txt,%.html,$(MAN_TXT))
_DOC_MAN3=$(patsubst %.txt,%.m,$(MAN3_TXT))

MAN_XML=$(addprefix $(OUTPUT),$(_MAN_XML))
MAN_HTML=$(addprefix $(OUTPUT),$(_MAN_HTML))
DOC_MAN3=$(addprefix $(OUTPUT),$(_DOC_MAN3))

# Make the path relative to DESTDIR, not prefix
ifndef DESTDIR
prefix?=$(HOME)
endif
bindir?=$(prefix)/bin
htmldir?=$(prefix)/share/doc/libtracecmd-doc
pdfdir?=$(prefix)/share/doc/libtracecmd-doc
mandir?=$(prefix)/share/man
man3dir=$(mandir)/man3

ifdef USE_ASCIIDOCTOR
ASCIIDOC_EXTRA += -a mansource="libtracecmd" -a manmanual="libtracecmd Manual"
endif

all: check-man-tools html man

man: man3
man3: $(DOC_MAN3)

html: $(MAN_HTML)

$(MAN_HTML) $(DOC_MAN3): $(ASCIIDOC_CONF)

install: check-man-tools install-man install-html

check-man-tools:
ifdef missing_tools
	$(error "You need to install $(missing_tools) for man pages")
endif

install-%.3: $(OUTPUT)%.3
	$(Q)$(call do_install_docs,$<,$(man3dir),644);

do-install-man: man $(addprefix install-,$(wildcard $(OUTPUT)*.3))

install-man: man
	$(Q)$(MAKE) -C . do-install-man

install-%.txt: $(OUTPUT)%.html
	$(Q)$(call do_install_docs,$<,$(htmldir),644);

do-install-html: html $(addprefix install-,$(wildcard *.txt))

install-html: html do-install-html

uninstall: uninstall-man uninstall-html

uninstall-man:
	$(Q)$(RM) $(addprefix $(DESTDIR)$(man3dir)/,$(DOC_MAN3))

uninstall-html:
	$(Q)$(RM) $(addprefix $(DESTDIR)$(htmldir)/,$(MAN_HTML))

ifdef missing_tools
  DO_INSTALL_MAN = $(warning Please install $(missing_tools) to have the man pages installed)
else
  DO_INSTALL_MAN = do-install-man
endif

CLEAN_FILES =					\
	$(MAN_XML) $(addsuffix +,$(MAN_XML))	\
	$(MAN_HTML) $(addsuffix +,$(MAN_HTML))	\
	$(DOC_MAN3) *.3 *.m

clean:
	$(Q) $(RM) $(CLEAN_FILES)

ifdef USE_ASCIIDOCTOR
$(OUTPUT)%.m : $(OUTPUT)%.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b manpage -d manpage \
		$(ASCIIDOC_EXTRA) -alibtracecmd_version=$(LIBTRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@
endif

$(OUTPUT)%.m : $(OUTPUT)%.xml
	$(QUIET_XMLTO)$(RM) $@ && \
	$(XMLTO) -o $(OUTPUT). -m $(MANPAGE_XSL) $(XMLTO_EXTRA) man $<; \
	touch $@

$(OUTPUT)%.xml : %.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b docbook -d manpage \
		$(ASCIIDOC_EXTRA) -alibtracecmd_version=$(LIBTRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@

$(MAN_HTML): $(OUTPUT)%.html : %.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b $(ASCIIDOC_HTML) -d manpage \
		$(ASCIIDOC_EXTRA) -alibtracecmd_version=$(LIBTRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@
