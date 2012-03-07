SUBDIRS = zorp

LIBS = @DEPS_LIBS@ @ZORP_LIBS@
lib_LTLIBRARIES = libzorpproxy.la

if PRO
libzorpproxy_la_PRO_SOURCES =	\
	polling_proxy.c
else
libzorpproxy_la_PRO_SOURCES =
endif

libzorpproxy_la_SOURCES = 		\
	dottransfer.c			\
	errorloader.c			\
	transfer2.c                     \
        $(libzorpproxy_la_PRO_SOURCES)
