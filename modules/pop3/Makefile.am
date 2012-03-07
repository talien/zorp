SUBDIRS = debian messages

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Pop3.py

pkglib_LTLIBRARIES = libpop3.la

libpop3_la_SOURCES = pop3.c pop3misc.c pop3cmd.c pop3policy.c pop3data.c pop3auth.c  pop3cmd.h pop3.h pop3policy.h pop3misc.h pop3data.h

EXTRA_DIST = $(pkgdata_DATA)
