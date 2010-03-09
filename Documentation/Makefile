
#
# Most likely a docbook.xsl is already installed on the users system
# instead of creating a new wheel, lets reuse what's already there.
#
MANPAGE_DOCBOOK_XSL =  $(shell locate manpages/docbook.xsl | head -1)

%.xml: %.txt
	asciidoc -d manpage -b docbook $<

%.1: %.xml manpage.xsl
	xsltproc --nonet ${MANPAGE_DOCBOOK_XSL} $< > $@

TEXT = $(wildcard *.txt)
XML = $(patsubst %.txt,%.xsl, ${TEXT})
MAN = $(patsubst %.txt,%.1, ${TEXT})

all: ${MAN}

manpage.xsl:
	@if [ ! -f ${MANPAGE_DOCBOOK_XSL} ]; then 		\
		echo "*********************************";	\
		echo "** No docbook.xsl is installed **";	\
		echo "** Can't make man pages        **";	\
		echo "*********************************";	\
	fi

clean:
	$(RM) *.xml *.1
