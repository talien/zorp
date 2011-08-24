ERROR_FILES = reject.msg

LANGUAGES = en hu
EXTRA_DIST = $(addprefix en/,$(ERROR_FILES)) $(addprefix hu/,$(ERROR_FILES))

pkgdatadir = @datadir@/zorp/pop3

install-data-hook:
	for lang in $(LANGUAGES); do \
		test -f $(DESTDIR)$(pkgdatadir)/$$lang || mkdir -p $(DESTDIR)$(pkgdatadir)/$$lang; \
		$(INSTALL) -c -m 644 $(addprefix $(srcdir)/$${lang}/,$(ERROR_FILES)) $(DESTDIR)$(pkgdatadir)/$${lang}; \
	done
