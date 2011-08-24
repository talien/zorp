LIBS=@MODULETESTS_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

check_PROGRAMS = smtp_sanitize_addr

smtp_sanitize_addr_SOURCES = smtp_sanitize_addr.c
smtp_sanitize_addr_LDADD = ../smtpcmd.lo ../smtp.lo ../smtppolicy.lo ../smtpdata.lo ../smtpmsg.lo

TESTS = smtp_sanitize_addr
