
obj := $(obj)/Documentation
src := $(src)/Documentation

#
# Most likely a docbook.xsl is already installed on the users system
# instead of creating a new wheel, lets reuse what's already there.
#
MANPAGE_DOCBOOK_XSL =  $(shell locate manpages/docbook.xsl | head -1)

$(obj)/%.xml: $(src)/%.txt
	mkdir -p $(obj)
	asciidoc -d manpage -b docbook -o $@ $<

$(obj)/%.1: $(obj)/%.xml manpage.xsl
	xsltproc --nonet -o $@ ${MANPAGE_DOCBOOK_XSL} $<

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
