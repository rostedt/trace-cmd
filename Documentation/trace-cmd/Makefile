# SPDX-License-Identifier: GPL-2.0

# Include the utils
include $(src)/scripts/utils.mk

# This Makefile and manpage XSL files were taken from libtracefs
# and modified for libtracecmd

MAN1_TXT= \
	$(wildcard trace-cmd*.1.txt)

MAN5_TXT= \
	$(wildcard trace-cmd*.5.txt)

MAN_TXT = $(MAN1_TXT) $(MAN5_TXT)
_MAN_XML=$(patsubst %.txt,%.xml,$(MAN_TXT))
_MAN_HTML=$(patsubst %.txt,%.html,$(MAN_TXT))
_DOC_MAN1=$(patsubst %.1.txt,%.1,$(MAN1_TXT))
_DOC_MAN5=$(patsubst %.5.txt,%.5,$(MAN5_TXT))

MAN_XML=$(addprefix $(OUTPUT),$(_MAN_XML))
MAN_HTML=$(addprefix $(OUTPUT),$(_MAN_HTML))
DOC_MAN1=$(addprefix $(OUTPUT),$(_DOC_MAN1))
DOC_MAN5=$(addprefix $(OUTPUT),$(_DOC_MAN5))

# Make the path relative to DESTDIR, not prefix
ifndef DESTDIR
prefix?=$(HOME)
endif
bindir?=$(prefix)/bin
htmldir?=$(prefix)/share/doc/trace-cmd
pdfdir?=$(prefix)/share/doc/trace-cmd
mandir?=$(prefix)/share/man
man1dir=$(mandir)/man1
man5dir=$(mandir)/man5

ifdef USE_ASCIIDOCTOR
ASCIIDOC_EXTRA += -a mansource="libtracecmd" -a manmanual="libtracecmd Manual"
endif

all: check-man-tools html man

man: man1 man5
man1: $(DOC_MAN1)
man5: $(DOC_MAN5)

html: $(MAN_HTML)

$(MAN_HTML) $(DOC_MAN1) $(DOC_MAN5): $(ASCIIDOC_CONF)

install: check-man-tools install-man install-html

check-man-tools:
ifdef missing_tools
	$(error "You need to install $(missing_tools) for man pages")
endif

install-%.1: $(OUTPUT)%.1
	$(Q)$(call do_install_docs,$<,$(man1dir),644);

install-%.5: $(OUTPUT)%.5
	$(Q)$(call do_install_docs,$<,$(man5dir),644);

do-install-man: man $(addprefix install-,$(wildcard $(OUTPUT)*.1)) \
	$(addprefix install-,$(wildcard $(OUTPUT)*.5))

install-man: man
	$(Q)$(MAKE) -C . do-install-man

install-%.txt: $(OUTPUT)%.html
	$(Q)$(call do_install_docs,$<,$(htmldir),644);

do-install-html: html $(addprefix install-,$(wildcard *.txt))

install-html: html do-install-html

uninstall: uninstall-man uninstall-html

uninstall-man:
	$(Q)$(RM) $(addprefix $(DESTDIR)$(man1dir)/,$(DOC_MAN1))
	$(Q)$(RM) $(addprefix $(DESTDIR)$(man5dir)/,$(DOC_MAN5))

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
	$(DOC_MAN1) $(DOC_MAN5) *.1 *.5

clean:
	$(Q) $(RM) $(CLEAN_FILES)

ifdef USE_ASCIIDOCTOR
$(OUTPUT)%.1 : $(OUTPUT)%.1.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b manpage -d manpage \
		$(ASCIIDOC_EXTRA) -atracecmd_version=$(TRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@

$(OUTPUT)%.5 : $(OUTPUT)%.5.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b manpage -d manpage \
		$(ASCIIDOC_EXTRA) -atracecmd_version=$(TRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@
endif

$(OUTPUT)%.1 : $(OUTPUT)%.1.xml
	$(QUIET_XMLTO)$(RM) $@ && \
	$(XMLTO) -o $(OUTPUT). -m $(MANPAGE_XSL) $(XMLTO_EXTRA) man $<; \

$(OUTPUT)%.5 : $(OUTPUT)%.5.xml
	$(QUIET_XMLTO)$(RM) $@ && \
	$(XMLTO) -o $(OUTPUT). -m $(MANPAGE_XSL) $(XMLTO_EXTRA) man $<; \

$(OUTPUT)%.xml : %.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b docbook -d manpage \
		$(ASCIIDOC_EXTRA) -atracecmd_version=$(TRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@

$(MAN_HTML): $(OUTPUT)%.html : %.txt
	$(QUIET_ASCIIDOC)$(RM) $@+ $@ && \
	$(ASCIIDOC) -b $(ASCIIDOC_HTML) -d manpage \
		$(ASCIIDOC_EXTRA) -atracecmd_version=$(TRACECMD_VERSION) -o $@+ $< && \
	mv $@+ $@
