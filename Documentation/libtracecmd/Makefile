# SPDX-License-Identifier: GPL-2.0

# Include the utils
include $(src)/scripts/utils.mk

bdir:=$(doc_dir)/libtracecmd

$(bdir)/%.xsl: $(bdir)/%.txt
	$(Q)mkdir -p $(bdir)
	$(Q)$(do_asciidoc_build)


$(bdir)/%.3: $(bdir)/%.3.xsl
	@$(call manpage.xsl)
	$(Q)$(do_xsltproc_build)

TEXT3 = $(wildcard $(bdir)/*.3.txt)
MAN3 = $(patsubst $(bdir)/%.3.txt,$(bdir)/%.3, ${TEXT3})

all: $(MAN3)

MAN3_INSTALL = $(MAN3:%.3=%.3.install)

$(MAN3_INSTALL): %.3.install : %.3 force
	$(Q)$(call do_install_docs,$<,$(man_dir_SQ)/man3)

install: $(MAN3_INSTALL)

clean:
	$(Q)(cd $(bdir); \
		$(RM) *.xml *.xsl *.3)

.PHONE: force
force:
