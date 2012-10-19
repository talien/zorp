# vim: ts=8 sts=4 expandtab autoindent
from Zorp.Core import *
from Zorp.Zorp import quit, log
from traceback import *

config.options.kzorp_enabled = FALSE

def init(names, virtual_name, is_master):
    try:
        log("session_id", "core.error", 1, "test_format='%s'", "test_value")
        log("session_id", "core.error", 1, "test_format='%s'", ("test_value", ))
        log("session_id", "core.error", 1, "test_format='%s'" % "test_value")
        log("session_id", "core.error", 1, "test_format='%s'" % ("test_value", ))
    except Exception, e:
        print_exc()
        quit(1)
        return 1

    quit(0)
    return 1

# Local Variables:
# mode: python
# indent-tabs-mode: nil
# python-indent: 4
# End:
