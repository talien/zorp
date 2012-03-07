from Zorp.Core import *
from Zorp.Plug import *

from Zorp.Session import MasterSession
from Zorp.NAT import NAT_SNAT, NAT_DNAT
from Zorp.Zorp import quit
from traceback import *

config.options.kzorp_enabled = FALSE

def testcase(nat, session, addrs, type, expected_result):
	res = nat.performTranslation(session, addrs, type)
	
	if not res.equal(expected_result):
		print 'invalid result res=%s, expected_result=%s' % (res.format(), expected_result.format())
		raise ValueError

def zorp():
	try:
		s = MasterSession()
		s.setService(Service("s1", None))
	
		nat = NATPolicy('test', GeneralNAT(
				[(InetSubnet('0.0.0.0/32'), InetSubnet('10.0.0.0/8'), InetSubnet('20.0.0.0/8')),
				 (InetSubnet('0.0.0.0/32'), InetSubnet('11.0.0.0/8'), InetSubnet('192.168.0.0/24')),
                                 (Inet6Subnet('::/128'), Inet6Subnet('1200::/8'), Inet6Subnet('2300::/8')),
				]))
		
		testcase(nat, s, (None, SockAddrInet('10.0.0.1', 8888)), NAT_DNAT, SockAddrInet('20.0.0.1', 8888))
		testcase(nat, s, (None, SockAddrInet('11.0.0.0', 8888)), NAT_DNAT, SockAddrInet('192.168.0.0', 8888))
		testcase(nat, s, (None, SockAddrInet('11.0.1.1', 8888)), NAT_DNAT, SockAddrInet('192.168.0.1', 8888))
		testcase(nat, s, (None, SockAddrInet('11.255.255.255', 8888)), NAT_DNAT, SockAddrInet('192.168.0.255', 8888))
                testcase(nat, s, (None, SockAddrInet6('1234::', 8888)), NAT_DNAT, SockAddrInet6('2334::', 8888))
	except Exception, e:
		print_exc()
		quit(1)
		return 1
		
	quit(0)
	return 1
