
%.1: %.sgml
	$(DOC_TO_MAN) $< > $@

%.html: %.sgml
	docbook2html $<
	mv index.html $@

distclean: clean

clean:
	rm -f ${man_MANS} ${man_HTMLS}

SGML_FILES = pxcrypt.sgml

EXTRA_DIST = $(SGML_FILES)

man_MANS = $(SGML_FILES:.sgml=.1)
man_HTMLS = $(SGML_FILES:.sgml=.html)

html: $(SGML_FILES:.sgml=.html)
