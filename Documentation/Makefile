
obj := $(obj)/Documentation
src := $(src)/Documentation

ifeq ($(VERBOSE),1)
  Q =
  print_asciidoc =
  print_xsltproc =
else
  Q = @
  print_asciidoc =		echo '      ASCIIDOC            '`basename $@`;
  print_xsltproc =		echo '      XSLTPROC            '`basename $@`;
endif

do_asciidoc_build =				\
	($(print_asciidoc)			\
	 asciidoc -d manpage -b docbook -o $@ $<)

do_xsltproc_build =				\
	($(print_xsltproc)			\
	 xsltproc --nonet -o $@ ${MANPAGE_DOCBOOK_XSL} $<)

#
# Most likely a docbook.xsl is already installed on the users system
# instead of creating a new wheel, lets reuse what's already there.
#
MANPAGE_DOCBOOK_XSL =  $(shell locate manpages/docbook.xsl | head -1)

$(obj)/%.xml: $(src)/%.txt
	$(Q)mkdir -p $(obj)
	$(Q)$(do_asciidoc_build)


$(obj)/%.1: $(obj)/%.xml manpage.xsl
	$(Q)$(do_xsltproc_build)

TEXT = $(wildcard *.txt)
XML = $(patsubst %.txt,$(obj)/%.xsl, ${TEXT})
MAN = $(patsubst %.txt,$(obj)/%.1, ${TEXT})

all: ${MAN}

manpage.xsl:
	@if [ ! -f ${MANPAGE_DOCBOOK_XSL} ]; then 		\
		echo "*********************************";	\
		echo "** No docbook.xsl is installed **";	\
		echo "** Can't make man pages        **";	\
		echo "*********************************";	\
	fi

clean:
	(cd $(obj); \
	 $(RM) *.xml *.1)
