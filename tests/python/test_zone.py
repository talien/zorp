from Zorp.Core import *
from Zorp.Zorp import quit
from Zorp.Zone import Zone
from Zorp.Session import MasterSession
from traceback import *
from time import time
from socket import htonl

config.options.kzorp_enabled = FALSE

def test(str, res, expect):
	if res != expect:
		print str, 'failed,', res, 'should be: ', expect
		raise 'test error'
	else:
		print str, 'ok,', res

def init(names, virtual_name, is_master):
	try:
		t1 = Zone("test1", "192.168.0.0/24", inbound_services=["s1"], outbound_services=["s2"])
		t2 = Zone("test2", "192.168.0.32/27")
		t3 = Zone("test3", "192.168.0.0/26")
		t4 = Zone("test4", "192.168.0.64/27")
		t5 = Zone("test5", "192.168.0.96/27")
		t6 = Zone("test6", "192.168.0.0/25")
		t7 = Zone("test7", "192.168.0.0/16")
		t8 = Zone("test8", "192.168.1.1/32", admin_parent="test1")
		t9 = Zone("test9", "192.168.1.2/32", admin_parent="test8")
		t10 = Zone("test10", "192.168.1.3/32", admin_parent="test9", umbrella=1)
		t11 = Zone("test11", "192.168.1.4/32", admin_parent="test9")
		t12 = Zone("test12", "192.168.1.5/32", inbound_services=['*'])
		t13 = Zone("test13", "192.168.1.6/32", outbound_services=['*'])
		t14 = Zone("test14", "192.168.0.184", outbound_services=['*'])
                t15 = Zone("test15", "dead:beef:baad:c0ff:ee00:1122:3344:5566/127", outbound_services=['*'])
		
		test('192.168.0.1', Zone.lookup(SockAddrInet('192.168.0.1', 10)), t3)
		test('192.168.0.33', Zone.lookup(SockAddrInet('192.168.0.33', 10)), t2)
		test('192.168.0.65', Zone.lookup(SockAddrInet('192.168.0.65', 10)), t4)
		test('192.168.0.97', Zone.lookup(SockAddrInet('192.168.0.97', 10)), t5)
		test('192.168.0.129', Zone.lookup(SockAddrInet('192.168.0.129', 10)), t1)
		test('192.168.1.129', Zone.lookup(SockAddrInet('192.168.1.129', 10)), t7)
		test('192.168.0.184', Zone.lookup(SockAddrInet('192.168.0.184', 10)), t14)
		test('dead:beef:baad:c0ff:ee00:1122:3344:5566', Zone.lookup(SockAddrInet6('dead:beef:baad:c0ff:ee00:1122:3344:5566', 10)), t15)
		test('dead:beef:baad:c0ff:ee00:1122:3344:5566', Zone.lookup(SockAddrInet6('dead:beef:baad:c0ff:ee00:1122:3344:5567', 10)), t15)

		inet = Zone("internet", "0.0.0.0/0", inbound_services=["s2"], outbound_services=["s1"])
		test('1.1.1.1', Zone.lookup(SockAddrInet('1.1.1.1', 10)), inet)
		s = MasterSession()
		s.setService(Service("s1", None))
		s.setServer(SockAddrInet('192.168.1.2', 9999))

		test('service s1#1', t1.isInboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s1#2', t1.isOutboundServicePermitted(s.service), ZV_REJECT)
		test('service s1#3', inet.isInboundServicePermitted(s.service), ZV_REJECT)
		test('service s1#4', inet.isOutboundServicePermitted(s.service), ZV_ACCEPT)
		###
		test('service s1#5', t10.isOutboundServicePermitted(s.service), ZV_REJECT)
		test('service s1#6', t10.isInboundServicePermitted(s.service), ZV_REJECT)
		
		test('service s1#7', t11.isOutboundServicePermitted(s.service), ZV_REJECT)
		test('service s1#8', t11.isInboundServicePermitted(s.service), ZV_ACCEPT)

		test('service s1#9', t12.isInboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s1#10', t12.isOutboundServicePermitted(s.service), ZV_REJECT)

		test('service s1#11', t13.isOutboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s1#12', t13.isInboundServicePermitted(s.service), ZV_REJECT)
		
		
		s.service = Service("s2", None)
		test('service s2#1', t1.isInboundServicePermitted(s.service), ZV_REJECT)
		test('service s2#2', t1.isOutboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s2#3', inet.isInboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s2#4', inet.isOutboundServicePermitted(s.service), ZV_REJECT)
		###
		test('service s2#5', t10.isInboundServicePermitted(s.service), ZV_REJECT)
		test('service s2#6', t10.isOutboundServicePermitted(s.service), ZV_REJECT)

		test('service s2#7', t11.isOutboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s2#8', t11.isInboundServicePermitted(s.service), ZV_REJECT)

		test('service s2#9', t12.isInboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s2#10', t12.isOutboundServicePermitted(s.service), ZV_REJECT)

		test('service s2#11', t13.isOutboundServicePermitted(s.service), ZV_ACCEPT)
		test('service s2#12', t13.isInboundServicePermitted(s.service), ZV_REJECT)

	except Exception, e:
		print_exc()
		quit(1)
		return 1
		
	quit(0)
	return 1
