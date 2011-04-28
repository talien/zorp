SUBDIRS = . tests

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Smtp.py

pkglib_LTLIBRARIES = libsmtp.la

libsmtp_la_SOURCES = smtp.c smtpcmd.c smtpdata.c smtpmsg.c smtppolicy.c smtp.h smtpmsg.h

EXTRA_DIST = $(pkgdata_DATA) 

