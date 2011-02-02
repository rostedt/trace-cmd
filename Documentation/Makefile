
obj := $(obj)/Documentation
src := $(src)/Documentation

ifeq ($(VERBOSE),1)
  Q =
  print_asciidoc =
  print_xsltproc =
  print_install =
  hide_xsltproc_output =
else
  Q = @
  print_asciidoc =		echo '      ASCIIDOC            '`basename $@`;
  print_xsltproc =		echo '      XSLTPROC            '`basename $@`;
  print_install =		echo '      INSTALL             '`basename $1`'	to	$(DESTDIR_SQ)'$2;
  hide_xsltproc_output = 2> /dev/null
endif

define manpage.xsl
	if [ -z ${MANPAGE_DOCBOOK_XSL} ]; then 			\
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
# asciidoc requires a synopsis, but file format man pages (5) do
# not require them. This removes it from the file in the final step.
define remove_synopsis
	(sed -e '/^\.SH "SYNOPSIS"/,/ignore/d' $1 > $1.tmp;\
	 mv $1.tmp $1)
endef

#
# Most likely a docbook.xsl is already installed on the users system
# instead of creating a new wheel, lets reuse what's already there.
#
MANPAGE_DOCBOOK_XSL ?=  $(shell locate manpages/docbook.xsl | head -1)

$(obj)/%.xsl: $(src)/%.txt
	$(Q)mkdir -p $(obj)
	$(Q)$(do_asciidoc_build)


$(obj)/%.1: $(obj)/%.1.xsl
	@$(call manpage.xsl)
	$(Q)$(do_xsltproc_build)

$(obj)/%.5: $(obj)/%.5.xsl
	@$(call manpage.xsl)
	$(Q)$(do_xsltproc_build)
	$(Q)$(call remove_synopsis, $@)

TEXT1 = $(wildcard *.1.txt)
MAN1 = $(patsubst %.1.txt,$(obj)/%.1, ${TEXT1})
TEXT5 = $(wildcard *.5.txt)
MAN5 = $(patsubst %.5.txt,$(obj)/%.5, ${TEXT5})

all: $(MAN1) $(MAN5)

# Need to find out how to export a macro instead of
# copying this from the main Makefile.
define do_install
	$(print_install)				\
	if [ ! -d '$(DESTDIR_SQ)$2' ]; then		\
		$(INSTALL) -d -m 755 '$(DESTDIR_SQ)$2';	\
	fi;						\
	$(INSTALL) $1 '$(DESTDIR_SQ)$2'
endef

MAN1_INSTALL = $(MAN1:%.1=%.1.install)
MAN5_INSTALL = $(MAN5:%.5=%.5.install)

$(MAN1_INSTALL): %.1.install : %.1 force
	$(Q)$(call do_install,$<,$(man_dir_SQ)/man1)
$(MAN5_INSTALL): %.5.install : %.5 force
	$(Q)$(call do_install,$<,$(man_dir_SQ)/man5)

html_dir = $(src)/HTML
image_dir = $(html_dir)/images

HTML = $(wildcard $(html_dir)/*.html)
IMGS = $(wildcard $(image_dir)/*.png)

HTML_INSTALL = $(subst .html,.html.install,$(HTML))
IMGS_INSTALL = $(subst .png,.png.install,$(IMGS))

$(HTML_INSTALL): %.html.install : %.html force
	$(Q)$(call do_install,$<,'$(html_install_SQ)')

$(IMGS_INSTALL): %.png.install : %.png force
	$(Q)$(call do_install,$<,'$(img_install_SQ)')


GUI_INSTALL = $(HTML_INSTALL) $(IMGS_INSTALL)

install: $(MAN1_INSTALL) $(MAN5_INSTALL) $(GUI_INSTALL)

clean:
	(cd $(obj); \
	 $(RM) *.xml *.xsl *.1 *.5)

.PHONE: force
force:
