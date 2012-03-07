from Zorp.Core import *
from socket import inet_ntoa, inet_aton
from traceback import print_exc
import struct

config.options.kzorp_enabled = FALSE

true = 1
false = 0

def test(str, res, expect):
	if res != expect:
		print str, 'failed,', res, 'should be: ', expect
	else:
		print str, 'ok,', res
		
def init(names, virtual_name, is_master):
	try:
		subnet = InetSubnet("192.168.0.1/24")
		test("netaddr(): ", subnet.addr_str(), "192.168.0.0")
		test("broadcast(): ", subnet.broadcast(), struct.unpack("I", inet_aton("192.168.0.255"))[0])
		test("netmask(): ", subnet.netmask_int(), struct.unpack("I", inet_aton("255.255.255.0"))[0])

	except Exception, e:
		print 'exception: fail', e
		print_exc()
		Zorp.quit(1)
		return 0

	Zorp.quit(0)
	return 1
