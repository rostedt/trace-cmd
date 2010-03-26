
obj := $(obj)/Documentation
src := $(src)/Documentation

ifeq ($(VERBOSE),1)
  Q =
  print_asciidoc =
  print_xsltproc =
  hide_xsltproc_output =
else
  Q = @
  print_asciidoc =		echo '      ASCIIDOC            '`basename $@`;
  print_xsltproc =		echo '      XSLTPROC            '`basename $@`;
  hide_xsltproc_output = 2> /dev/null
endif

define manpage.xsl
	if [ ! -f ${MANPAGE_DOCBOOK_XSL} ]; then 		\
		echo "*********************************";	\
		echo "** No docbook.xsl is installed **";	\
		echo "** Can't make man pages        **";	\
		echo "*********************************";	\
		exit 1;						\
	fi
endef

do_asciidoc_build =				\
	($(print_asciidoc)			\
	 asciidoc -d manpage -b docbook -o $@ $<)

do_xsltproc_build =				\
	($(print_xsltproc)			\
	 xsltproc --nonet -o $@ ${MANPAGE_DOCBOOK_XSL} $< $(hide_xsltproc_output))

#
# Most likely a docbook.xsl is already installed on the users system
# instead of creating a new wheel, lets reuse what's already there.
#
MANPAGE_DOCBOOK_XSL =  $(shell locate manpages/docbook.xsl | head -1)

$(obj)/%.xsl: $(src)/%.txt
	$(Q)mkdir -p $(obj)
	$(Q)$(do_asciidoc_build)


$(obj)/%.1: $(obj)/%.xsl
	@$(call manpage.xsl)
	$(Q)$(do_xsltproc_build)

TEXT = $(wildcard *.txt)
XML = $(patsubst %.txt,$(obj)/%.xsl, ${TEXT})
MAN = $(patsubst %.txt,$(obj)/%.1, ${TEXT})

all: ${MAN}


clean:
	(cd $(obj); \
	 $(RM) *.xml *.xsl *.1)
