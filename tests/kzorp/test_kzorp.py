#!/usr/bin/env python

import os
import errno

import string
import struct
import socket
import glob

import optparse
import sys
import types
from kznf.kznfnetlink import *
from kznf.nfnetlink import *
from kznf import *

import unittest

from Zorp.Zone import InetZone
from Zorp.Subnet import InetDomain, Inet6Subnet, InetSubnet
FALSE = 0
TRUE = 1

def update_dict(d, **kwargs):
  ret = d.copy()
  ret.update(kwargs)
  return ret

def inet_ntoa(a):
  return "%s.%s.%s.%s" % ((a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff)

def inet_aton(a):
  r = 0L
  for n in a.split("."):
    r = (r << 8) + int(n)
  return r

def size_to_mask(family, size):
  if family == socket.AF_INET:
    max_size = 32
  elif family == socket.AF_INET6:
    max_size = 128
  else:
    raise ValueError, "address family not supported; family='%d'" % family

  if size > max_size:
    raise ValueError, "network size is greater than the maximal size; size='%d', max_size='%d'" % (size, max_size)

  packed_mask = ''
  actual_size = 0
  while actual_size + 8 < size:
    packed_mask += '\xff'
    actual_size = actual_size + 8

  if actual_size <= size:
    packed_mask += chr((0xff << (8 - (size - actual_size))) & 0xff)
    actual_size = actual_size + 8

  while actual_size < max_size:
    packed_mask += '\x00'
    actual_size = actual_size + 8
  
  return socket.inet_ntop(family, packed_mask)

def curry(fn, *cargs, **ckwargs):
    def call_fn(*fargs, **fkwargs):
        d = ckwargs.copy()
        d.update(fkwargs)
        return fn(*(cargs + fargs), **d)
    return call_fn

def compose(f, g):
  return lambda *args, **kwargs: f(g(*args, **kwargs))

class KZorpComm(unittest.TestCase):
  handle = None
  _flushables = [
                  KZNL_MSG_FLUSH_ZONE,
                  KZNL_MSG_FLUSH_SERVICE,
                  KZNL_MSG_FLUSH_DISPATCHER,
                  KZNL_MSG_FLUSH_BIND
                ]

  def __init__(self, *args):
    unittest.TestCase.__init__(self, *args)
    self.create_handle()
    self._in_transaction = False
    self.flush_all()

  def __del__(self):
    self.close_handle()

  def create_handle(self):
    if self.handle == None:
      self.handle = kznfnetlink.Handle()
      self.assertNotEqual(self.handle, None)
      self.handle.register_subsystem(Subsystem(NFNL_SUBSYS_KZORP))

  def close_handle(self):
    if self.handle:
      self.handle.close()
      self.handle = None

  def reopen_handle(self):
    self.close_handle()
    self.create_handle()
    self._in_transaction = False

  def send_message(self, message_type, message, assert_on_error = True, message_handler = None, dump = False, error_handler=None):
    self.assertNotEqual(message, None)
    self.create_handle()

    #FIXME: it is just a workaround of a KZrop python module bug
    message_flags = NLM_F_REQUEST
    if dump == True:
      message_flags |= NLM_F_DUMP
    else:
      message_flags |= NLM_F_ACK

    kzorp_message = self.handle.create_message(NFNL_SUBSYS_KZORP, message_type, message_flags)
    kzorp_message.set_nfmessage(message)

    res = self.handle.talk(kzorp_message, (0, 0), message_handler)
    if assert_on_error:
      #FIXME: positive values should mean error
      if error_handler is None:
        self.assertTrue(res >= 0, ("talk with KZorp failed: result='%d' error='%s'" % (res, os.strerror(-res))))
      else:
        error_handler(res)

    return res

  def start_transaction(self, instance_name = KZ_INSTANCE_GLOBAL, cookie = 0L):
    self.send_message(KZNL_MSG_START, create_start_msg(instance_name, cookie))
    self._in_transaction = True

  def end_transaction(self, instance_name = KZ_INSTANCE_GLOBAL):
    self.send_message(KZNL_MSG_COMMIT, create_commit_msg())
    self._in_transaction = False

  def flush_all(self):
    if self._in_transaction:
      self.reopen_handle()
      self._in_transaction = False

    for message_type in self._flushables:
      self.start_transaction()

      self.send_message(message_type, create_flush_msg())

      self.end_transaction()

class KZorpBaseTestCaseZones(KZorpComm):
  _dumped_zones = []

  def _dump_zone_handler(self, message):
    self._dumped_zones.append(message)

  def check_zone_num(self, num_zones = 0, in_transaction = True):
    self._dumped_zones = []

    if in_transaction == True:
      self.start_transaction()
    self.send_message(KZNL_MSG_GET_ZONE, create_get_zone_msg(None), message_handler = self._dump_zone_handler, dump = True)
    if in_transaction == True:
      self.end_transaction()

    self.assertEqual(num_zones, len(self._dumped_zones))

  def get_zone_attrs(self, message):
    self.assertEqual (message.type & 0xff, KZNL_MSG_ADD_ZONE)

    attrs = message.get_nfmessage().get_attributes()
    self.assertEqual(attrs.has_key(KZA_ZONE_PARAMS), True)

    return attrs

  def get_zone_name(self, message):
    attrs = self.get_zone_attrs(message)
    if attrs.has_key(KZA_ZONE_NAME) == True:
      return parse_name_attr(attrs[KZA_ZONE_NAME])

    return None

  def get_zone_uname(self, message):
    attrs = self.get_zone_attrs(message)
    self.assertEqual(attrs.has_key(KZA_ZONE_PARAMS), True)
    self.assertEqual(attrs.has_key(KZA_ZONE_UNAME), True)

    return parse_name_attr(attrs[KZA_ZONE_UNAME])

  def get_zone_range(self, message):
    attrs = self.get_zone_attrs(message)
    self.assertEqual(attrs.has_key(KZA_ZONE_RANGE), True)

    (family, addr, mask) = parse_inet_range_attr(attrs[KZA_ZONE_RANGE])

    return "%s/%s" % (socket.inet_ntop(family, addr), socket.inet_ntop(family, mask))

  def send_add_zone_message(self, inet_zone):
    for m in inet_zone.buildKZorpMessage():
      self.send_message(m[0], m[1])

  def _check_zone_params(self, add_zone_message, zone_data):
    self.assertEqual(self.get_zone_name(add_zone_message), zone_data['name'])
    self.assertEqual(self.get_zone_uname(add_zone_message), zone_data['uname'])

    attrs = self.get_zone_attrs(add_zone_message)
    self.assertEqual(zone_data['flags'], parse_int32_attr(attrs[KZA_ZONE_PARAMS]))

    family = zone_data['family']
    self.assertEqual(self.get_zone_range(add_zone_message), "%s/%s" % (zone_data['address'], size_to_mask(family, zone_data['mask'])))

class KZorpTestCaseZones(KZorpBaseTestCaseZones):
  _zones = [
             {'name' :  'a', 'uname' : 'root', 'pname' : None,   'address' : '10.0.100.1',     'mask' : 32, 'flags' : KZF_ZONE_UMBRELLA, 'family' : socket.AF_INET},
             {'name' :  'b', 'uname' :    'b', 'pname' : 'root', 'address' : '10.0.102.1',     'mask' : 31, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'c', 'uname' :    'c', 'pname' :    'b', 'address' : '10.0.103.1',     'mask' : 30, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'd', 'uname' :    'd', 'pname' :    'b', 'address' : '10.0.104.1',     'mask' : 29, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'e', 'uname' :    'e', 'pname' :    'b', 'address' : '10.0.105.1',     'mask' : 28, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'f', 'uname' :    'f', 'pname' :    'b', 'address' : '10.0.106.1',     'mask' : 27, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'g', 'uname' :    'g', 'pname' :    'f', 'address' : '10.0.107.1',     'mask' : 26, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'h', 'uname' :    'h', 'pname' :    'g', 'address' : '10.0.108.1',     'mask' : 25, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'i', 'uname' :    'i', 'pname' :    'g', 'address' : '10.0.109.1',     'mask' : 24, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' :  'j', 'uname' :    'j', 'pname' :    'g', 'address' : '10.0.110.1',     'mask' : 23, 'flags' : 0, 'family' : socket.AF_INET},
             {'name' : 'a6', 'uname' :   'k6', 'pname' :   None, 'address' : 'fc00:0:101:1::', 'mask' : 64, 'flags' : 0, 'family' : socket.AF_INET6},
           ]

  def setUp(self):
    self.start_transaction()

    for zone in self._zones:
      family = zone['family']
      add_zone_message = create_add_zone_msg(zone['name'],  zone['flags'],         \
                                             family = family,                      \
                                             uname = zone['uname'],                \
                                             pname = zone['pname'],                \
                                             address = socket.inet_pton(family, zone['address']), \
                                             mask = socket.inet_pton(family, size_to_mask(family, zone['mask'])))
      self.send_message(KZNL_MSG_ADD_ZONE, add_zone_message)

    self.end_transaction()
    self._index = -1
    self._add_zone_message = None
    self._add_zone_messages = []

  def tearDown(self):
    self.flush_all()

  def test_add_zone(self):
    #set up and ter down test the zone addition
    self.check_zone_num(len(self._zones))

  def test_add_zone_errors(self):
    zones = [
              {'name' : 'fake', 'uname' :  'x0', 'pname' :  None, 'address' : None, 'mask' : None, 'flags' : 0x2, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
              {'name' : 'fake', 'uname' :  'x1', 'pname' :   'x', 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.ENOENT},
              {'name' : 'fake', 'uname' :   'a',  'pname' : 'xx', 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.ENOENT},
              {'name' : 'fake', 'uname' :   'a',  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : 0},
              {'name' : 'fake', 'uname' :   'a',  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.EEXIST},
              {'name' : 'fake', 'uname' :  None,  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : 0},
              {'name' : 'fake', 'uname' :  'x2',  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : 0},
              {'name' :    '',  'uname' :  'x3',  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
              {'name' : 'fake', 'uname' :    '',  'pname' : None, 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
              {'name' : 'fake', 'uname' :  None,  'pname' :   '', 'address' : None, 'mask' : None, 'flags' :   0, 'family' : socket.AF_INET, 'error' : -errno.EINVAL},
            ]

    add_zone_message = create_add_zone_msg('a', 0);
    res = self.send_message(KZNL_MSG_ADD_ZONE, add_zone_message, assert_on_error = False)
    self.assertEqual(res, -errno.ENOENT)

    self.start_transaction()
    for zone in zones:
      mask = zone['mask']
      if mask != None:
        mask = size_to_mask(mask)

      if zone['address'] != None:
        add_zone_message = create_add_zone_msg(zone['name'],  zone['flags'],         \
                                               family = zone['family'],              \
                                               uname = zone['uname'],                \
                                               pname = zone['pname'],                \
                                               address = inet_aton(zone['address']), \
                                               mask = mask)
      else:
        add_zone_message = create_add_zone_msg(zone['name'],  zone['flags'],         \
                                               family = zone['family'],              \
                                               uname = zone['uname'],                \
                                               pname = zone['pname'])

      res = self.send_message(KZNL_MSG_ADD_ZONE, add_zone_message, assert_on_error = False)
      self.assertEqual(res, zone['error'])
    self.end_transaction()

  def _get_zone_message_handler(self, msg):
    self._add_zone_message = msg
    self._index += 1

    self._check_zone_params(msg, self._zones[self._index])

  def test_get_zone_by_name(self):
    #get each created zone
    for zone in self._zones:
      zone_name = zone['uname']
      self.send_message(KZNL_MSG_GET_ZONE, create_get_zone_msg(zone_name), message_handler = self._get_zone_message_handler)
    self.assertNotEqual(self._index, len(self._zones))

    #get a not existent zone
    self.assertNotEqual(self._zones[0]['name'], self._zones[0]['uname'])
    res = self.send_message(KZNL_MSG_GET_ZONE, create_get_zone_msg(self._zones[0]['name']), assert_on_error = False)
    self.assertEqual(res, -errno.ENOENT)

  def _get_zones_message_handler(self, msg):
    self._add_zone_messages.append(msg)

  def test_get_zone_with_dump(self):
    #get the dump of zones
    self.send_message(KZNL_MSG_GET_ZONE, create_get_zone_msg(None), message_handler = self._get_zones_message_handler, dump = True)
    self.assertEqual(len(self._add_zone_messages), len(self._zones))
    for add_zone_message in self._add_zone_messages:
      for i in range(len(self._zones)):
        if self.get_zone_uname(add_zone_message) == self._zones[i]['uname']:
          self._check_zone_params(add_zone_message, self._zones[i])
          break
      else:
        self.assert_(True, "zone with name %s could not find in the dump" % self.get_zone_uname(add_zone_message))

attrmap = {
            KZA_SVC_NAME: (create_name_attr, parse_name_attr),
            KZA_SVC_PARAMS: (create_service_params_attr, parse_service_params_attr),
            KZA_SVC_SESSION_CNT: (create_int32_attr, parse_int32_attr),
            KZA_SVC_ROUTER_DST_ADDR: (create_inet_addr_attr, parse_inet_addr_attr),
            KZA_SVC_ROUTER_DST_PORT: (create_port_attr, parse_port_attr),
            KZA_SVC_NAT_SRC: (create_nat_range_attr, parse_nat_range_attr),
            KZA_SVC_NAT_DST: (create_nat_range_attr, parse_nat_range_attr),
            KZA_SVC_NAT_MAP: (create_nat_range_attr, parse_nat_range_attr),
          }

def create_attr(type, *attr):
  return attrmap[type][0](type, *attr)

def parse_attr(type, attr):
  if not attr.has_key(type):
    return None
  return attrmap[type][1](attr[type])

def create_message(attrs):
  m = NfnetlinkMessage(socket.AF_NETLINK, 0, 0)
  for (type, values) in attrs.items():
    m.append_attribute(create_attr(type, *values))
  return m

def service_get_flags(transparent, forge_addr):
  flags = 0
  if (transparent): flags |= KZF_SVC_TRANSPARENT
  if (forge_addr): flags |= KZF_SVC_FORGE_ADDR
  return flags
    
class Message:
  def __init__(self, type):
    self.message_type = type
    self.attributes = {}

  def addAttribute(self, attr_type, attr_value):
    self.attributes[attr_type] = attr_value
    return self

  def getMessage(self):
    return create_message(self.attributes)

  def send(self, comm, handler = None):
    return comm.send_message(self.message_type, self.getMessage(), message_handler = handler, assert_on_error=False)

  def __str__(self):
    return "<%d %s>" % self.message_type, str(self.attributes)

class BadType(Exception):
  pass

class BadResponse(Exception):
  pass

class MissingAttributes(Exception):
  def __init__(self, set1, set2):
    self.set1 = set1
    self.set2 = set2

  def __str__(self):
    return "<%s> != <%s>" % (str(self.set1), str(self.set2))

class Message_Add_Service(Message):
  def __init__(self, name, params):
    Message.__init__(self, KZNL_MSG_ADD_SERVICE)
    self.addAttribute(KZA_SVC_NAME, (name,))
    self.addAttribute(KZA_SVC_PARAMS, params)

  def verify(self, comm):
    def check_response(r):
      if (r.type & 0xff != KZNL_MSG_ADD_SERVICE): raise BadType
      attrs = r.get_nfmessage().get_attributes()
      
      if (not (attrs.has_key(KZA_SVC_PARAMS) and attrs.has_key(KZA_SVC_NAME))): raise BadResponse

      # FIXME: must fix how we store attributes in self.attributes:
      # they are not directly comparable at the moment because single
      # values are not stored as tuples, but parse_attr always returns
      # tuples
      #set1 = frozenset(tuple([(a[0], (parse_attr(a[0], attrs),) for a in attrs.items() ]))
      #set2 = frozenset(tuple(self.attributes.items()))
      #
      #if set1 != set2: raise MissingAttributes(set1, set2)

    comm.send_message(KZNL_MSG_GET_SERVICE, create_message({KZA_SVC_NAME: self.attributes[KZA_SVC_NAME]}), message_handler = check_response)

class Message_Add_Service_Forward(Message_Add_Service):
  def __init__(self, name, transparent = True, forge_addr = False):
    Message_Add_Service.__init__(self, name, (KZ_SVC_FORWARD, service_get_flags(transparent, forge_addr)))

class Message_Add_Service_Forward_Nontransparent(Message_Add_Service_Forward):
  def __init__(self, name, router, forge_addr = False):
    Message_Add_Service_Forward.__init__(self, name, False, forge_addr)
    self.attributes[KZA_SVC_ROUTER_DST_ADDR] = router

class Message_Add_Service_Proxy(Message_Add_Service):
  def __init__(self, name, flags = 0, transparent = False, forge_addr = False):
    Message_Add_Service.__init__(self, name, (KZ_SVC_PROXY, flags))

class KZorpTestCaseServices(KZorpComm):

  def create_add_service_nat_msg_helper(name, mapping, flags, type):
    m = create_add_service_nat_msg(name, mapping)
    m.append_attribute(create_service_params_attr(KZA_SVC_PARAMS, type, flags))
    return m
  def create_add_service_session_cnt(cnt, name):
    m = create_add_proxyservice_msg(name)
    m.append_attribute(create_int32_attr(KZA_SVC_SESSION_CNT, cnt))
    return m
  def service_with_attrs(m, attr_type, attr_value):
    m.append_attribute(create_attr(attr_type, attr_value))
    return m

  services = [
      (create_add_proxyservice_msg,       { 'name': "test-proxy" }, { KZA_SVC_NAME: "test-proxy", KZA_SVC_PARAMS: (0, KZ_SVC_PROXY), KZA_SVC_SESSION_CNT: 0 }),
      (create_add_pfservice_msg,          { 'name': "test-forward", 'flags': KZF_SVC_TRANSPARENT }, { KZA_SVC_NAME: "test-forward", KZA_SVC_PARAMS: (1, KZ_SVC_FORWARD)}),
      (create_add_pfservice_msg,          { 'name': "test3", 'flags': 0, 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }, { KZA_SVC_NAME: "test3", KZA_SVC_PARAMS: (0, KZ_SVC_FORWARD), KZA_SVC_ROUTER_DST_ADDR: socket.inet_pton(socket.AF_INET, '1.2.3.4'), KZA_SVC_ROUTER_DST_PORT: 1 } ),
      (create_add_pfservice_msg,          { 'name': "test6", 'flags': 3, 'dst_family': socket.AF_INET, 'dst_ip': socket.inet_pton(socket.AF_INET, '1.2.3.4'), 'dst_port': 1 }, { KZA_SVC_NAME: "test6", KZA_SVC_PARAMS: (3, KZ_SVC_FORWARD), KZA_SVC_ROUTER_DST_ADDR: None, KZA_SVC_ROUTER_DST_PORT: None } ),
      #(create_add_service_nat_msg_helper, { 'name': "test4", 'mapping': ((0,2,3,4,5),None,(0,2,3,4,5)), 'type': 1, 'flags': 0 }, { KZA_SVC_NAME: "test4", KZA_SVC_PARAMS: (0, 1) } ),
      (create_add_service_session_cnt, {'name': 'test5', 'cnt': 303}, { KZA_SVC_NAME: "test5", KZA_SVC_SESSION_CNT: 303 }),
             ]
  services3 = [
      Message_Add_Service_Proxy("test-proxy").addAttribute(KZA_SVC_SESSION_CNT, (303,)),
      Message_Add_Service_Forward("test-forward"),
      Message_Add_Service_Forward_Nontransparent("test-forward-nontransparent", (socket.AF_INET, socket.inet_pton(socket.AF_INET, '1.2.3.4'))).addAttribute(KZA_SVC_ROUTER_DST_PORT, (1025, )),
      Message_Add_Service_Forward("test-forward-transparent", True, True).addAttribute(KZA_SVC_ROUTER_DST_ADDR, (socket.AF_INET, socket.inet_pton(socket.AF_INET, '1.2.3.4'))).addAttribute(KZA_SVC_ROUTER_DST_PORT, (1025, ))
      ]

  def check_svc_num(self, num_svc):
    _dumped_zones = []
    self.send_message(KZNL_MSG_GET_SERVICE, create_get_service_msg(None), message_handler = _dumped_zones.append, dump = True)
    self.assertEqual(num_svc, len(_dumped_zones))

  def print_service(self, m):
    attrs = m.get_nfmessage().get_attributes()
    print parse_name_attr(attrs[KZA_SVC_NAME]), attrs.keys()
    
  def test_add_message(self):
    self.start_transaction()
    res = [ m.send(self) for m in self.services3 ]
    self.end_transaction()
    ver = [ m.verify(self) for m in self.services3 ]

  def test_get_service(self):
    def check_get_reply(self, service, reply):
      msg = service[1]
      reply_attrs = self.get_service_attrs(reply)
      for (attr_type, value) in service[2].items():
        self.assertEqual(parse_attr(attr_type, reply_attrs), service[2][attr_type])

    self.check_svc_num(len(self.services))
    self.assertEqual(-2, self.send_message(KZNL_MSG_GET_SERVICE, create_get_service_msg("nonexistent"), assert_on_error=False))

    for service in self.services:
      self.send_message(KZNL_MSG_GET_SERVICE, create_get_service_msg(service[1].get('name')), message_handler = curry(check_get_reply, self, service))

  def check_send(self, type, message, return_value):
    self.start_transaction()
    r = self.send_message(type, message, assert_on_error=False)
    self.end_transaction()
    self.assertEqual(return_value, r)

  def test_add_service_duplicated(self):
    service_cnt = len(self.services)
    #duplicated entry check: the matching service was in the same transaction
    self.start_transaction()
    self.send_message(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg("dupe1"))
    res = self.send_message(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg("dupe1"), assert_on_error=False)
    self.end_transaction()
    self.assertEqual(-errno.EEXIST, res)
    service_cnt += 1
    self.check_svc_num(service_cnt)

    #duplicated entry check: the matching service was already existing
    self.check_send(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg("dupe1"), -errno.EEXIST)
    self.check_svc_num(service_cnt)

  def test_add_service_invalid(self):
    service_cnt = len(self.services)
    #invalid service type
    self.check_send(KZNL_MSG_ADD_SERVICE, create_message({KZA_SVC_NAME: ("invalid_service_type", ), KZA_SVC_PARAMS: (KZ_SVC_INVALID, 3) }), -errno.EINVAL)
    self.check_svc_num(service_cnt)

  def test_add_service(self):
    services2 = [
        (create_message, {"attrs": {KZA_SVC_NAME: ("test8",), KZA_SVC_PARAMS: (KZ_SVC_PROXY, 0)}}, { KZA_SVC_NAME: "test7" }),
        ]

    service_cnt = len(self.services)

    #outside of transaction
    self.assertEqual(-errno.ENOENT, self.send_message(KZNL_MSG_ADD_SERVICE, self.services[0][0](**self.services[0][1]), assert_on_error=False))
    self.check_svc_num(service_cnt)
    m = Message_Add_Service_Proxy(KZNL_MSG_ADD_SERVICE, "proba")

    #FIXME: "TypeError: unsupported operand type(s) for &: 'str' and 'long"
    #self.start_transaction(KZ_TR_TYPE_SERVICE)
    #m.send(self)
    #self.end_transaction()
    #m.verify(self)

  def test_add_service_flags(self):
    service_cnt = len(self.services)

    for i in xrange(4):
      self.check_send(KZNL_MSG_ADD_SERVICE, create_message({KZA_SVC_NAME: ("flag-%d" % i,), KZA_SVC_PARAMS: (KZ_SVC_PROXY, i)}), 0)
    service_cnt += 4
    self.check_svc_num(service_cnt)

    # using undefined flags
    self.start_transaction()
    res = self.send_message(KZNL_MSG_ADD_SERVICE, create_message({KZA_SVC_NAME: ("flag-invalid",) , KZA_SVC_PARAMS: (KZ_SVC_PROXY, 0xfffffffc)}), assert_on_error=False)
    self.end_transaction()
    self.assertNotEqual(0, res)

  def test_add_service_nontransparent(self):
    service_cnt = len(self.services)
    self.check_send(KZNL_MSG_ADD_SERVICE, create_message({KZA_SVC_NAME: ("test-nontransparent-router",), KZA_SVC_PARAMS: (KZ_SVC_FORWARD, 0), KZA_SVC_ROUTER_DST_ADDR: (socket.AF_INET, socket.inet_pton(socket.AF_INET, '1.2.3.4')), KZA_SVC_ROUTER_DST_PORT: (10010, )}), 0)
    service_cnt += 1
    self.check_svc_num(service_cnt)

    self.check_send(KZNL_MSG_ADD_SERVICE, create_message({KZA_SVC_NAME: ("test-nontransparent-norouter",), KZA_SVC_PARAMS: (KZ_SVC_FORWARD, 0)}), -errno.EINVAL)
    self.check_svc_num(service_cnt)

  def _test_add_service_nat(self, nat_type):
    service_cnt = len(self.services)
    self.check_send(nat_type, create_message({KZA_SVC_NAME: ("test-forward",)}), -errno.EINVAL)
    self.check_send(nat_type, create_message({KZA_SVC_NAME: ("test-forward",), KZA_SVC_NAT_MAP: (1, 12345678, 123456789, 12344, 12345)}), -errno.EINVAL)

    if (nat_type == KZNL_MSG_ADD_SERVICE_NAT_SRC):
      self.check_send(nat_type, create_message({KZA_SVC_NAME: ("test-forward",), KZA_SVC_NAT_DST: (1, 12345678, 123456789, 12344, 12345), KZA_SVC_NAT_MAP: (1, 12345678, 123456789, 12344, 12345)}), -errno.EINVAL)

    self.check_svc_num(service_cnt)

    #adding a nat rule to a service added in the same transaction
    self.start_transaction()
    self.send_message(KZNL_MSG_ADD_SERVICE, create_add_pfservice_msg('test-nat', 1))
    self.send_message(nat_type, create_message( {
            KZA_SVC_NAME: ("test-nat",),
            KZA_SVC_NAT_SRC: (1, 12345688, 12345689, 1024, 1025),
            KZA_SVC_NAT_MAP: (1, 12345688, 12345689, 1024, 1025),
          }), 0)
    self.end_transaction()
    service_cnt += 2
    self.check_svc_num(service_cnt)

  def test_add_service_nat_dst(self):
    self._test_add_service_nat(KZNL_MSG_ADD_SERVICE_NAT_DST)

  def test_add_service_nat_src(self):
    self._test_add_service_nat(KZNL_MSG_ADD_SERVICE_NAT_SRC)

  def setUp(self):
    self.start_transaction()
    for service in self.services:
      self.send_message(KZNL_MSG_ADD_SERVICE, service[0](**service[1]))
    self.end_transaction()

  def tearDown(self):
    self.flush_all();

  def get_service_attrs(self, message):
    self.assertEqual (message.type & 0xff, KZNL_MSG_ADD_SERVICE)

    attrs = message.get_nfmessage().get_attributes()
    self.assertEqual(attrs.has_key(KZA_SVC_PARAMS), True)
    self.assertEqual(attrs.has_key(KZA_SVC_NAME), True)

    return attrs

class KZorpTestCaseFlush(KZorpComm):

  def __init__(self, *args):
    KZorpComm.__init__(self, *args)

  def setUp(self):
    self._response_message_num = 0
    self.start_transaction()
    message_add_dispatcher = create_add_dispatcher_sabind_msg('dispatcher_name', 0, socket.IPPROTO_TCP, 1000, inet_aton('12.3.4.5'), [(80, 80)])
    self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher)
    self.end_transaction()

    self.start_transaction()
    self.send_message(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg('proxyservice'))
    self.send_message(KZNL_MSG_ADD_SERVICE, create_add_pfservice_msg('pfservice', KZF_SVC_TRANSPARENT))
    self.end_transaction()

    self.start_transaction()
    self.send_message(KZNL_MSG_ADD_ZONE, create_add_zone_msg('zone', 0))
    self.send_message(KZNL_MSG_ADD_ZONE_SVC_IN, create_add_zone_svc_msg('zone', 'proxyservice'))
    self.end_transaction()

  def tearDown(self):
    self.flush_all()

  def message_handler(self, message):
    self._response_message_num += 1

  def test_flush_zones(self):
    self.start_transaction()
    self.send_message(KZNL_MSG_FLUSH_ZONE, create_flush_msg(), message_handler = self.message_handler)
    self.end_transaction()

    self.send_message(KZNL_MSG_GET_ZONE, create_get_zone_msg(None), message_handler = self.message_handler, dump = True)
    self.assertEqual(self._response_message_num, 0)

  def test_flush_services(self):
    self.start_transaction()
    self.send_message(KZNL_MSG_FLUSH_SERVICE, create_flush_msg(), message_handler = self.message_handler)
    self.end_transaction()

    self.send_message(KZNL_MSG_GET_SERVICE, create_get_service_msg(None), message_handler = self.message_handler, dump = True)
    self.assertEqual(self._response_message_num, 0)

  def test_flush_dispatchers(self):
    self.start_transaction()
    self.send_message(KZNL_MSG_FLUSH_DISPATCHER, create_flush_msg(), message_handler = self.message_handler)
    self.end_transaction()

    self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg(None), message_handler = self.message_handler, dump = True)
    self.assertEqual(self._response_message_num, 0)

class KZorpTestCaseTransaction(KZorpBaseTestCaseZones):
  def setUp(self):
    self.check_zone_num(0)

  def tearDown(self):
    self.flush_all()

  def test_transactions(self):
    # Start a transaction
    self.start_transaction(KZ_INSTANCE_GLOBAL, 123456789L)
 
    # Start the transaction again without end transaction
    message = create_start_msg(KZ_INSTANCE_GLOBAL, 987654321L)
    res = self.send_message(KZNL_MSG_START, message, False)
    self.assertEqual(res, -errno.EINVAL)
 
    # Commit the transaction without any change
    self.end_transaction()
 
    # Commit the transaction again out of the transaction
    res = self.send_message(KZNL_MSG_COMMIT, message, False)
    self.assertEqual(res, -errno.ENOENT)

  def test_transaction_collision(self):
    self.start_transaction()

    message = create_start_msg(KZ_INSTANCE_GLOBAL)
    res = self.send_message(KZNL_MSG_START, message, False)
    self.assertEqual(res, -errno.EINVAL)

    self.end_transaction()

  def test_transaction_abort(self):
    self.start_transaction()
    self.send_message(KZNL_MSG_ADD_ZONE, create_add_zone_msg('zone', 0))
    self.end_transaction()
    self.check_zone_num(1)

    # Start a transaction
    self.start_transaction()

    self.send_message(KZNL_MSG_ADD_ZONE, create_add_zone_msg('a', 0))
    self.check_zone_num(1, False)

    # Abort the transaction
    self.reopen_handle()

    self.check_zone_num(1, False)


class KZorpBaseTestCaseDispatchers(KZorpComm):
  _dumped_dispatchers = []
  _zones = [
             InetZone('internet', ['0.0.0.0/0']),
             InetZone('A',        ['10.99.101.0/25',   '10.99.201.0/25'],   inbound_services=[ "serv1"]),
             InetZone('AA',       ['10.99.101.0/28',   '10.99.201.0/28'],   inbound_services=[ "serv1"],                  admin_parent='A'),
             InetZone('AAA',      ['10.99.101.0/30',   '10.99.201.0/30'],   inbound_services=[ "serv1"],                  admin_parent='AA'),
             InetZone('AAZ',      ['10.99.101.4/30',   '10.99.201.4/30'],   outbound_services=[ "serv1"],                 admin_parent='AA'),
             InetZone('AB',       ['10.99.101.64/28',  '10.99.201.64/28'],  inbound_services=[ "serv1"],   umbrella=TRUE, admin_parent='A'),
             InetZone('ABA',      ['10.99.101.64/30',  '10.99.201.64/30'],  inbound_services=[ "serv1"],                  admin_parent='AB'),
             InetZone('ABZ',      ['10.99.101.68/30',  '10.99.201.68/30'],  outbound_services=[ "serv1"],                 admin_parent='AB'),
             InetZone('AY',       ['10.99.101.80/28',  '10.99.201.80/28'],  outbound_services=[ "serv1"],  umbrella=TRUE, admin_parent='A'),
             InetZone('AYA',      ['10.99.101.80/30',  '10.99.201.80/30'],  inbound_services=[ "serv1"],                  admin_parent='AY'),
             InetZone('AYZ',      ['10.99.101.84/30',  '10.99.201.84/30'],  outbound_services=[ "serv1"],                 admin_parent='AY'),
             InetZone('AZ',       ['10.99.101.16/28',  '10.99.201.16/28'],  outbound_services=[ "serv1"],                 admin_parent='A'),
             InetZone('AZA',      ['10.99.101.16/30',  '10.99.201.16/30'],  inbound_services=[ "serv1"],                  admin_parent='AZ'),
             InetZone('AZZ',      ['10.99.101.20/30',  '10.99.201.20/30'],  outbound_services=[ "serv1"],                 admin_parent='AZ'),
             InetZone('Z',        ['10.99.101.128/25', '10.99.201.128/25'], outbound_services=[ "serv1"]),
             InetZone('ZA',       ['10.99.101.128/28', '10.99.201.128/28'], inbound_services=[ "serv1"],                  admin_parent='Z'),
             InetZone('ZAA',      ['10.99.101.128/30', '10.99.201.128/30'], inbound_services=[ "serv1"],                  admin_parent='ZA'),
             InetZone('ZAZ',      ['10.99.101.132/30', '10.99.201.132/30'], outbound_services=[ "serv1"],                 admin_parent='ZA'),
             InetZone('ZB',       ['10.99.101.192/28', '10.99.201.192/28'], inbound_services=[ "serv1"],   umbrella=TRUE, admin_parent='Z'),
             InetZone('ZBA',      ['10.99.101.192/30', '10.99.201.192/30'], inbound_services=[ "serv1"],                  admin_parent='ZB'),
             InetZone('ZBZ',      ['10.99.101.196/30', '10.99.201.196/30'], outbound_services=[ "serv1"],                 admin_parent='ZB'),
             InetZone('ZY',       ['10.99.101.208/28', '10.99.201.208/28'], outbound_services=[ "serv1"],  umbrella=TRUE, admin_parent='Z'),
             InetZone('ZYA',      ['10.99.101.208/30', '10.99.201.208/30'], inbound_services=[ "serv1"],                  admin_parent='ZY'),
             InetZone('ZYZ',      ['10.99.101.212/30', '10.99.201.212/30'], outbound_services=[ "serv1"],                 admin_parent='ZY'),
             InetZone('ZZ',       ['10.99.101.144/28', '10.99.201.144/28'], outbound_services=[ "serv1"],                 admin_parent='Z'),
             InetZone('ZZA',      ['10.99.101.144/30', '10.99.201.144/30'], inbound_services=[ "serv1"],                  admin_parent='ZZ'),
             InetZone('ZZZ',      ['10.99.101.148/30', '10.99.201.148/30'], outbound_services=[ "serv1"],                 admin_parent='ZZ'),

           ]

  def _dump_dispatcher_handler(self, message):
    self._dumped_dispatchers.append(message)

  def check_dispatcher_num(self, num_dispatchers = 0, in_transaction = True):
    self._dumped_dispatchers = []

    if in_transaction == True:
      self.start_transaction()
    self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg(None), message_handler = self._dump_dispatcher_handler, dump = True)
    if in_transaction == True:
      self.end_transaction()

    self.assertEqual(num_dispatchers, len(self._dumped_dispatchers))

  def get_dispatcher_attrs(self, message):
    #self.assertEqual (message.type & 0xff, KZNL_MSG_ADD_DISPATCHER)

    attrs = message.get_nfmessage().get_attributes()
    self.assertEqual(attrs.has_key(KZA_DPT_PARAMS), True)

    return attrs

  def get_dispatcher_name(self, message):
    attrs = self.get_dispatcher_attrs(message)
    if attrs.has_key(KZA_DPT_NAME) == True:
      return parse_name_attr(attrs[KZA_DPT_NAME])

    return None

  def _check_dispatcher_params(self, add_dispatcher_message, dispatcher_data):
    self.assertEqual(self.get_dispatcher_name(add_dispatcher_message), dispatcher_data['name'])

    attrs = self.get_dispatcher_attrs(add_dispatcher_message)
    flags, proxy_port, dispatcher_type = parse_dispatcher_params_attr(attrs[KZA_DPT_PARAMS])
    self.assertEqual(dispatcher_data['flags'], flags)
    self.assertEqual(dispatcher_data['proxy_port'], proxy_port)
    self.assertEqual(dispatcher_data['type'], dispatcher_type)

    if dispatcher_type == KZ_DPT_TYPE_INET:
      proto, rule_addr, rule_ports = parse_bind_addr_attr(attrs[KZA_DPT_BIND_ADDR])
      self.assertEqual(dispatcher_data['rule_addr'], inet_ntoa(rule_addr))
    elif dispatcher_type == KZ_DPT_TYPE_IFACE:
      proto, ifname, rule_ports, pref_addr = parse_bind_iface_attr(attrs[KZA_DPT_BIND_IFACE])
      self.assertEqual(dispatcher_data['ifname'], ifname)
      self.assertEqual(pref_addr, 0)
    elif dispatcher_type == KZ_DPT_TYPE_IFGROUP:
      proto, ifgroup, mask, rule_ports, pref_addr = parse_bind_ifgroup_attr(attrs[KZA_DPT_BIND_IFGROUP])
      self.assertEqual(dispatcher_data['ifgroup'], ifgroup)
      self.assertEqual(dispatcher_data['mask'], mask)
      self.assertEqual(pref_addr, 0)
    elif dispatcher_type == KZ_DPT_TYPE_N_DIMENSION:
      num_rules = parse_n_dimension_attr(attrs[KZA_DISPATCHER_N_DIMENSION_PARAMS])
      self.assertEqual(dispatcher_data['num_rules'], num_rules)

    if dispatcher_type == KZ_DPT_TYPE_INET or \
       dispatcher_type == KZ_DPT_TYPE_IFACE or \
       dispatcher_type == KZ_DPT_TYPE_IFGROUP:
      self.assertEqual(dispatcher_data['proto'], proto)
      self.assertEqual(dispatcher_data['rule_ports'], rule_ports)

  def _check_add_rule_params(self, add_dispatcher_message, rule_data):

    attrs = add_dispatcher_message.get_nfmessage().get_attributes()
    rule_id, service, rules = parse_rule_attrs(attrs)

    self.assertEqual(rule_data['rule_id'], rule_id)
    self.assertEqual(rule_data['service'], service)

    self.assertEqual(len(rule_data['entry_nums']), len(rules))

    for k, v in rule_data['entry_nums'].items():
      self.assertEqual(k in rules, True)
      self.assertEqual((rule_data['entry_nums'][k],), rules[k])

  def _check_add_rule_entry_params(self, add_dispatcher_message, rule_entry_data, rule_entry_index):

    attrs = add_dispatcher_message.get_nfmessage().get_attributes()
    rule_id, rule_entries = parse_rule_entry_attrs(attrs)
    self.assertEqual(rule_entry_data['rule_id'], rule_id)

    for k, v in rule_entry_data['entry_values'].items():
      if rule_entry_data['entry_nums'][k] > rule_entry_index:
        self.assertEqual(k in rule_entries, True)
        if k in [KZA_N_DIMENSION_SRC_IP, KZA_N_DIMENSION_DST_IP, KZA_N_DIMENSION_SRC_IP6, KZA_N_DIMENSION_DST_IP6]:
          (family, addr, mask) = rule_entries[k]
          self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index].addr_packed(), addr)
          self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index].netmask_packed(), mask)
        elif k == KZA_N_DIMENSION_SRC_PORT or k == KZA_N_DIMENSION_DST_PORT:
          self.assertEqual(rule_entry_data['entry_values'][k][rule_entry_index], rule_entries[k])
        else:
          self.assertEqual((rule_entry_data['entry_values'][k][rule_entry_index],), rule_entries[k])

  def setup_service_dispatcher(self, services, dispatchers, add_zone = True, add_service = True):
    self._dumped_diszpancsers = []

    if add_zone:
      self.start_transaction()

      for zone in self._zones:
        self.send_add_zone_message(zone)

      self.end_transaction()

    if add_service:
      self.start_transaction()

      for service in services:
        if type(service) == types.DictType:
          service = service['name']
        self.send_message(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg(service))

      self.end_transaction()

    self.start_transaction()

    for dispatcher in dispatchers:
      if ('type' in dispatcher) and (dispatcher['type'] != KZ_DPT_TYPE_N_DIMENSION):
        continue

      message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                                 dispatcher['flags'],       \
                                                                 dispatcher['proxy_port'],  \
                                                                 dispatcher['num_rules']    \
                                                                )

      self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, error_handler=lambda res: os.strerror(res)+" "+str(message_add_dispatcher))

      for rule in dispatcher['rules']:
        _max = 0
        for name, value in rule['entry_nums'].items():
          if _max < value:
            _max = value

        message_add_rule = create_add_n_dimension_rule_msg(dispatcher['name'], \
                                                           rule['rule_id'],    \
                                                           rule['service'],    \
                                                           rule['entry_nums']     \
                                                          )
        self.send_message(KZNL_MSG_ADD_RULE, message_add_rule)

        for i in range(_max):
          data = {}
          for dim_type in N_DIMENSION_ATTRS:
            if dim_type in rule['entry_nums'] and rule['entry_nums'][dim_type] > i:
              if dim_type in [KZA_N_DIMENSION_SRC_IP, KZA_N_DIMENSION_DST_IP, KZA_N_DIMENSION_SRC_IP6, KZA_N_DIMENSION_DST_IP6]:
                subnet = rule['entry_values'][dim_type][i]
                data[dim_type] = (subnet.addr_packed(), subnet.netmask_packed())
              else:
               data[dim_type] = rule['entry_values'][dim_type][i]
          message_add_rule_entry = create_add_n_dimension_rule_entry_msg(dispatcher['name'], rule['rule_id'], data)

          self.send_message(KZNL_MSG_ADD_RULE_ENTRY, message_add_rule_entry)

    self.end_transaction()

class KZorpTestCaseDispatchers(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):
  _all_dispatcher_flags = KZF_SVC_TRANSPARENT | KZF_DPT_FOLLOW_PARENT
  _dispatchers = [
                   { 'name' : 'bind_tcp',        'type' : KZ_DPT_TYPE_INET, 'flags' : KZF_DPT_TRANSPARENT,   'proto' : socket.IPPROTO_TCP, 'proxy_port' : 1,    'rule_ports' : [ (10001, 10001) ], 'rule_addr' : '10.0.0.1'},
                   { 'name' : 'bind_udp',        'type' : KZ_DPT_TYPE_INET, 'flags' : KZF_DPT_FOLLOW_PARENT, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 10,   'rule_ports' : [ (10002, 10003) ], 'rule_addr' : '10.0.0.1'},
                   { 'name' : 'bind_flags',      'type' : KZ_DPT_TYPE_INET, 'flags' : _all_dispatcher_flags, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 100,  'rule_ports' : [ (10002, 10003) ], 'rule_addr' : '10.0.0.2'},
                   { 'name' : 'bind_rule_ports', 'type' : KZ_DPT_TYPE_INET, 'flags' : 0,                     'proto' : socket.IPPROTO_UDP, 'proxy_port' : 1000, 'rule_ports' : [ (10001, 10001), (10002, 10003), (20004, 30004) ], 'rule_addr' : '10.0.0.3'},

                   { 'name' : 'ifacebind_tcp',        'type' : KZ_DPT_TYPE_IFACE, 'flags' : KZF_DPT_TRANSPARENT,   'proto' : socket.IPPROTO_TCP, 'proxy_port' : 1,    'rule_ports' : [ (10001, 10001) ], 'ifname' : 'eth0'},
                   { 'name' : 'ifacebind_udp',        'type' : KZ_DPT_TYPE_IFACE, 'flags' : KZF_DPT_FOLLOW_PARENT, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 10,   'rule_ports' : [ (10002, 10003) ], 'ifname' : 'eth1'},
                   { 'name' : 'ifacebind_flags',      'type' : KZ_DPT_TYPE_IFACE, 'flags' : _all_dispatcher_flags, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 100,  'rule_ports' : [ (10002, 10003) ], 'ifname' : 'lo'},
                   { 'name' : 'ifacebind_rule_ports', 'type' : KZ_DPT_TYPE_IFACE, 'flags' : 0,                     'proto' : socket.IPPROTO_UDP, 'proxy_port' : 1000, 'rule_ports' : [ (10001, 10001), (10002, 10003), (20004, 30004) ], 'ifname' : 'dummy'},

                   { 'name' : 'ifgroupbind_tcp',        'type' : KZ_DPT_TYPE_IFGROUP, 'flags' : KZF_DPT_TRANSPARENT,   'proto' : socket.IPPROTO_TCP, 'proxy_port' : 1,    'rule_ports' : [ (10001, 10001) ], 'ifgroup' : 0, 'mask' : 10},
                   { 'name' : 'ifgroupbind_udp',        'type' : KZ_DPT_TYPE_IFGROUP, 'flags' : KZF_DPT_FOLLOW_PARENT, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 10,   'rule_ports' : [ (10002, 10003) ], 'ifgroup' : 1, 'mask' : 11},
                   { 'name' : 'ifgroupbind_flags',      'type' : KZ_DPT_TYPE_IFGROUP, 'flags' : _all_dispatcher_flags, 'proto' : socket.IPPROTO_UDP, 'proxy_port' : 100,  'rule_ports' : [ (10002, 10003) ], 'ifgroup' : 2, 'mask' : 12},
                   { 'name' : 'ifgroupbind_rule_ports', 'type' : KZ_DPT_TYPE_IFGROUP, 'flags' : 0,                     'proto' : socket.IPPROTO_UDP, 'proxy_port' : 1000, 'rule_ports' : [ (10001, 10001), (10002, 10003), (20004, 30004) ], 'ifgroup' : 3, 'mask' : 13},

                   { 'name' : 'n_dimension', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                     'rules' : [
                                 { 'rule_id' : 1, 'service' : 'A_A',
                                   'entry_nums' :
                                               { 
                                                 KZA_N_DIMENSION_DST_PORT : 2,
                                                 KZA_N_DIMENSION_SRC_ZONE : 2

                                               },
                                   'entry_values' :
                                               {
                                                 KZA_N_DIMENSION_DST_PORT : [(12,12), (23, 44)],
                                                 KZA_N_DIMENSION_SRC_ZONE : ["AAA", "ZZZ"]
                                               } 
                                 }
                               ]
                   },
                   { 'name' : 'n_dimension_with_rules', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 3,
                     'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 1 },
                                   'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(5,6)] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFACE : 2, KZA_N_DIMENSION_DST_PORT : 3 },
                                   'entry_values' : { KZA_N_DIMENSION_IFACE : ['eth0', 'eth1'], KZA_N_DIMENSION_DST_PORT : [(3,3), (4,4), (50000,65534)]}
                                 },
                                 { 'rule_id'      : 3, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 1, KZA_N_DIMENSION_SRC_ZONE : 4, KZA_N_DIMENSION_DST_PORT : 2 },
                                   'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(1,2)], KZA_N_DIMENSION_SRC_ZONE : ['AAA', 'AZA', 'AA', 'A'], KZA_N_DIMENSION_DST_PORT : [(10000,10000), (20000, 30000)] }
                                 }
                               ]
                   },
                   { 'name' : 'n_dimension_with_ALL_rules', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                     'rules' : [ { 'rule_id'      : 1, 'service' : 'Z_Z',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFACE : 2, KZA_N_DIMENSION_PROTO : 1, KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_DST_PORT : 1, KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_SRC_ZONE : 3, KZA_N_DIMENSION_DST_IP : 2, KZA_N_DIMENSION_DST_ZONE : 1, KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFACE : ['eth4', 'eth2'], KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZA_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], KZA_N_DIMENSION_DST_PORT : [(5,6)], KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5/24')], KZA_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], KZA_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6/16'), InetDomain('4.5.6.7/8')], KZA_N_DIMENSION_DST_ZONE : 'AAA', KZA_N_DIMENSION_IFGROUP : [1]},
                                 },
                                 { 'rule_id'      : 2, 'service' : 'Z_Z',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 2, KZA_N_DIMENSION_DST_IP : 3, KZA_N_DIMENSION_SRC_ZONE : 1, KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_DST_PORT : 2, KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_PROTO : 1, KZA_N_DIMENSION_IFACE : 3 },
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AZA', 'ZAZ'], KZA_N_DIMENSION_DST_IP : [InetDomain('8.7.6.5'), InetDomain('7.6.5.4/31'), InetDomain('9.8.7.6/25')], KZA_N_DIMENSION_SRC_ZONE : 'ZZ', KZA_N_DIMENSION_SRC_IP : [InetDomain('5.4.3.2/32'), InetDomain('6.5.4.3/30')], KZA_N_DIMENSION_DST_PORT : [(66,66),(100,200)], KZA_N_DIMENSION_SRC_PORT : [(23,24), (30, 40)], KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZA_N_DIMENSION_IFACE : ['eth0', 'eth1', 'eth2'] }
                                 }
                               ]
                   }

                 ]

  _services_tmp = [
                    {'dispatcher_name' : 'n_dimension',   'name' : 'A_A', 'czone' : 'A', 'szone' : 'A'},
                    {'dispatcher_name' : 'n_dimension_2', 'name' : 'Z_Z', 'czone' : 'Z', 'szone' : 'Z'}
                  ]

  def __init__(self, *args):
    KZorpBaseTestCaseDispatchers.__init__(self, *args)
    KZorpBaseTestCaseZones.__init__(self, *args)

    self._add_dispatcher_messages = []
    self._add_dispatcher_message = None
    self._index = -1

  def setUp(self):
    self.setup_service_dispatcher(self._services_tmp, self._dispatchers)

    self.start_transaction()

    for dispatcher in self._dispatchers:
      dispatcher_type = dispatcher['type']
      if dispatcher_type == KZ_DPT_TYPE_N_DIMENSION:
        continue

      if dispatcher_type == KZ_DPT_TYPE_INET:
        message_add_dispatcher = create_add_dispatcher_sabind_msg(dispatcher['name'],                               \
                                                                  dispatcher['flags'],                              \
                                                                  dispatcher['proto'],                              \
                                                                  dispatcher['proxy_port'],                         \
                                                                  inet_aton(dispatcher['rule_addr']),               \
                                                                  dispatcher['rule_ports'])
      elif dispatcher_type == KZ_DPT_TYPE_IFACE:
        message_add_dispatcher = create_add_dispatcher_ifacebind_msg(dispatcher['name'],                               \
                                                                     dispatcher['flags'],                              \
                                                                     dispatcher['proto'],                              \
                                                                     dispatcher['proxy_port'],                         \
                                                                     dispatcher['ifname'],
                                                                     dispatcher['rule_ports'])
      elif dispatcher_type == KZ_DPT_TYPE_IFGROUP:
        message_add_dispatcher = create_add_dispatcher_ifgroupbind_msg(dispatcher['name'],                               \
                                                                       dispatcher['flags'],                              \
                                                                       dispatcher['proto'],                              \
                                                                       dispatcher['proxy_port'],                         \
                                                                       dispatcher['ifgroup'],
                                                                       dispatcher['mask'],
                                                                       dispatcher['rule_ports'])
      self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher)

    self.end_transaction()

  def tearDown(self):
    self.flush_all()
    pass

  def test_get_4k_dispatcher(self):
    services = ['A_A']
    _iface_num = 300
    _iface_list = []
    _iface_string = "abcdefghijklmno"
    for i in range(_iface_num):
      _iface_list.append(_iface_string)

    dispatchers = [{ 'name' : 'n_dimension_4k', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                     'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFACE : _iface_num, KZA_N_DIMENSION_PROTO : 1, KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_DST_PORT : 1, KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_SRC_ZONE : 3, KZA_N_DIMENSION_DST_IP : 2, KZA_N_DIMENSION_DST_ZONE : 1, KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFACE : _iface_list, KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZA_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], KZA_N_DIMENSION_DST_PORT : [(5,6)], KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5/24')], KZA_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ', 'Z'], KZA_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6/16'), InetDomain('4.5.6.7/8')], KZA_N_DIMENSION_DST_ZONE : 'AAA', KZA_N_DIMENSION_IFGROUP : [1]},
                                 }
                               ]
                 }]

    self.setup_service_dispatcher(services, dispatchers, False, False);
    self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg("n_dimension_4k"), message_handler = self._get_dispatchers_message_handler)
    self._check_dispatcher_params(self._add_dispatcher_messages[0], dispatchers[0])
    self._check_ndim_params(dispatchers)

  def test_n_dimension_errors(self):
    error_dup_dispatchers=[
                        { 'name' : 'n_dimension_error', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 0,
                        },

                        { 'name' : 'n_dimension_error2', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                          'rules' : [{ 'rule_id' : 1, 'service' : 'A_A',
                                       'entry_nums' : { KZA_N_DIMENSION_IFACE : 2},
                                       'errno' : 0
                                     }
                                    ]
                        }
                      ]
    error_num_rules_dispatchers=[
                        { 'name' : 'n_dimension_error3', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                          'rules' : [{ 'rule_id' : 2, 'service' : 'A_A',
                                       'entry_nums' : { KZA_N_DIMENSION_IFACE : 2},
                                       'errno' : 0
                                     },
                                     { 'rule_id' : 3, 'service' : 'A_A',
                                       'entry_nums' : { KZA_N_DIMENSION_IFACE : 2},
                                       'errno' : -errno.EINVAL
                                     }
                                    ]
                        },
                        { 'name' : 'n_dimension_error4', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                          'rules' : [{ 'rule_id' : 3, 'service' : 'A_A',
                                       'entry_nums' : { KZA_N_DIMENSION_IFACE : 2},
                                       #FIXME: this shouldbe: -errno.EEXIST
                                       'errno' : 0
                                     }
                                    ]
                        }
                      ]
    error_num_rule_entries=[
                        { 'name' : 'n_dimension_error5', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 8,
                          'rules' : [{ 'rule_id' : 4, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_IFACE : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_IFACE : ['eth4', 'eth2'] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 5, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_PROTO : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP, socket.IPPROTO_UDP] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 6, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(1,1), (2,2)] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 7, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(3,3),(4,5)] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 8, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.4'), InetDomain('2.3.4.5')] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 9, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['ZZZ', 'ZZ'] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 10, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetDomain('3.4.5.6'), InetDomain('4.5.6.7')] },
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     },
                                     { 'rule_id' : 11, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                       'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AAA', 'AA']},
                                       'rule_entry_errnos' : [0, -errno.ENOMEM]
                                     }
                                    ]
                        }
                       ]

    error_zones_exist=[
                        { 'name' : 'n_dimension_error6', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                          'rules' : [{ 'rule_id' : 12, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : 'BBB' },
                                       'rule_entry_errnos' : [-errno.ENOENT]
                                     },
                                     { 'rule_id' : 13, 'service' : 'A_A',
                                       'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1 },
                                       'entry_values' : { KZA_N_DIMENSION_DST_ZONE : 'CCC' },
                                       'rule_entry_errnos' : [-errno.ENOENT]
                                     }
                                    ]
                        }
                      ]

    #Check add_dispatcher without starting a transaction
    dispatcher = error_dup_dispatchers[0]
    message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                               dispatcher['flags'],       \
                                                               dispatcher['proxy_port'],  \
                                                               dispatcher['num_rules']    \
                                                              )

    res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)
    self.assertEqual(res, -errno.ENOENT)

    #check duplicated add_dispatcher
    self.start_transaction()
    message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                               dispatcher['flags'],       \
                                                               dispatcher['proxy_port'],  \
                                                               dispatcher['num_rules']    \
                                                               )
    res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)
    self.assertEqual(res, 0)
    res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)
    self.assertEqual(res, -errno.EEXIST)
    self.end_transaction()

    #check if num_rules > number of rule_entries
    dispathcer = error_dup_dispatchers[1]
    self.start_transaction()
    message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                               dispatcher['flags'],       \
                                                               dispatcher['proxy_port'],  \
                                                               dispatcher['num_rules']    \
                                                               )
    res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)
    self.assertEqual(res, 0)
    self.end_transaction()

    #check if num_rules < number of rule entries, check adding existing rule_id
    self.start_transaction()

    for i in range(len(error_num_rules_dispatchers)):
      dispatcher = error_num_rules_dispatchers[i]
      dispatcher_type = dispatcher['type']
      message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                                   dispatcher['flags'],       \
                                                                   dispatcher['proxy_port'],  \
                                                                   dispatcher['num_rules']    \
                                                                  )
      res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)

      for rule in dispatcher['rules']:
        message_add_rule = create_add_n_dimension_rule_msg(dispatcher['name'], \
                                                             rule['rule_id'],    \
                                                             rule['service'],    \
                                                             rule['entry_nums']     \
                                                            )
        res = self.send_message(KZNL_MSG_ADD_RULE, message_add_rule, assert_on_error = False)
        if 'errno' in rule:
          self.assertEqual(res, rule['errno'])
    self.end_transaction()

    #check if entry_nums < number of entry_values
    self.start_transaction()

    for i in range(len(error_num_rule_entries)):
      dispatcher = error_num_rule_entries[i]
      dispatcher_type = dispatcher['type']
      message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                                   dispatcher['flags'],       \
                                                                   dispatcher['proxy_port'],  \
                                                                   dispatcher['num_rules']    \
                                                                  )
      res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)

      for rule in dispatcher['rules']:
        _max = 2
        message_add_rule = create_add_n_dimension_rule_msg(dispatcher['name'], \
                                                             rule['rule_id'],    \
                                                             rule['service'],    \
                                                             rule['entry_nums']     \
                                                            )
        res = self.send_message(KZNL_MSG_ADD_RULE, message_add_rule, assert_on_error = False)
        if 'errno' in rule:
          self.assertEqual(res, rule['errno'])
        for i in range(_max):
          data = {}
          for dim_type in N_DIMENSION_ATTRS:
            if dim_type in rule['entry_nums']:
              if dim_type in [KZA_N_DIMENSION_SRC_IP, KZA_N_DIMENSION_DST_IP, KZA_N_DIMENSION_SRC_IP6, KZA_N_DIMENSION_DST_IP6]:
                data[dim_type] = (rule['entry_values'][dim_type][i].addr_packed(), rule['entry_values'][dim_type][i].netmask_packed())
              else:
                data[dim_type] = rule['entry_values'][dim_type][i]
          message_add_rule_entry = create_add_n_dimension_rule_entry_msg(dispatcher['name'], rule['rule_id'], data)
          res = self.send_message(KZNL_MSG_ADD_RULE_ENTRY, message_add_rule_entry, assert_on_error = False)
          self.assertEqual(res, rule['rule_entry_errnos'][i])

    self.end_transaction()

    self.start_transaction()
    #check zones exist
    for i in range(len(error_zones_exist)):
      dispatcher = error_zones_exist[i]
      dispatcher_type = dispatcher['type']
      message_add_dispatcher = create_add_dispatcher_n_dimension(dispatcher['name'],        \
                                                                   dispatcher['flags'],       \
                                                                   dispatcher['proxy_port'],  \
                                                                   dispatcher['num_rules']    \
                                                                  )
      res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)

      for rule in dispatcher['rules']:
        _max = 1
        message_add_rule = create_add_n_dimension_rule_msg(dispatcher['name'], \
                                                             rule['rule_id'],    \
                                                             rule['service'],    \
                                                             rule['entry_nums']     \
                                                            )
        res = self.send_message(KZNL_MSG_ADD_RULE, message_add_rule, assert_on_error = False)
        if 'errno' in rule:
          self.assertEqual(res, rule['errno'])
        for i in range(_max):
          data = {}
          for dim_type in N_DIMENSION_ATTRS:
            if dim_type in rule['entry_nums']:
              if dim_type == KZA_N_DIMENSION_SRC_IP or dim_type == KZA_N_DIMENSION_DST_IP:
                data[dim_type] = (struct.pack('I', rule['entry_values'][dim_type][i].ip), struct.pack('I', rule['entry_values'][dim_type][i].mask))
              else:
                data[dim_type] = rule['entry_values'][dim_type][i]
          message_add_rule_entry = create_add_n_dimension_rule_entry_msg(dispatcher['name'], rule['rule_id'], data)
          res = self.send_message(KZNL_MSG_ADD_RULE_ENTRY, message_add_rule_entry, assert_on_error = False)
          self.assertEqual(res, rule['rule_entry_errnos'][i])

    self.end_transaction()

    pass

  def test_add_dispatcher(self):
    #set up and ter down test the dispatcher addition
    num_rules = 0
    num_rule_entries = 0
    for dispatcher in self._dispatchers:
      if dispatcher['type'] == KZ_DPT_TYPE_N_DIMENSION:
        for rule in dispatcher['rules']:
          num_rules = num_rules + 1
          _max = 0
          for name, value in rule['entry_nums'].items():
            if _max < value:
              _max = value
          num_rule_entries = num_rule_entries + _max

    self.check_dispatcher_num(num_rules + num_rule_entries + len(self._dispatchers))

  def test_add_dispatcher_errors(self):
    error_dispatchers = [
                          { 'name' : 'tcp', 'flags' : KZF_DPT_TRANSPARENT, 'proto' : -1, 'proxy_port' : 1, 'rule_ports' : [ [10001, 10001] ], 'rule_addr' : '10.0.0.1', 'error' : -errno.EINVAL},
                          { 'name' : 'tcp', 'flags' : KZF_DPT_TRANSPARENT, 'proto' :  5, 'proxy_port' : 1, 'rule_ports' : [ [10001, 10001] ], 'rule_addr' : '10.0.0.1', 'error' : -errno.EINVAL},
                          { 'name' : 'tcp', 'flags' : KZF_DPT_TRANSPARENT, 'proto' :  7, 'proxy_port' : 1, 'rule_ports' : [ [10001, 10001] ], 'rule_addr' : '10.0.0.1', 'error' : -errno.EINVAL},
                          { 'name' : 'tcp', 'flags' : KZF_DPT_TRANSPARENT, 'proto' :  15, 'proxy_port' : 1, 'rule_ports' : [ [10001, 10001] ], 'rule_addr' : '10.0.0.1', 'error' : -errno.EINVAL},
                          { 'name' : 'tcp', 'flags' : KZF_DPT_TRANSPARENT, 'proto' :  17, 'proxy_port' : 1, 'rule_ports' : [ [10001, 10001] ], 'rule_addr' : '10.0.0.1', 'error' : -errno.EINVAL},
                        ]

    dispatcher = self._dispatchers[0]
    message_add_dispatcher = create_add_dispatcher_sabind_msg(dispatcher['name'],                               \
                                                              dispatcher['flags'],                              \
                                                              dispatcher['proto'],                              \
                                                              dispatcher['proxy_port'],                         \
                                                              inet_aton(dispatcher['rule_addr']),               \
                                                              dispatcher['rule_ports'])
    res = self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher, assert_on_error = False)
    self.assertEqual(res, -errno.ENOENT)

    #FIXME: unfinished unit test?
    """
    self.start_transaction(KZ_TR_TYPE_DISPATCHER)
    for dispatcher in self._dispatchers:
      message_add_dispatcher = create_add_dispatcher_sabind_msg(dispatcher['name'],                               \
                                                                dispatcher['flags'],                              \
                                                                dispatcher['proto'],                              \
                                                                dispatcher['proxy_port'],                         \
                                                                inet_aton(dispatcher['rule_addr']),               \
                                                                dispatcher['rule_ports'])
      self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher)
    self.end_transaction()
    """

  def _get_dispatcher_message_handler(self, msg):
    self._add_dispatcher_message = msg
    self._index += 1

    self._check_dispatcher_params(msg, self._dispatchers[self._index])

  def test_get_dispatcher_by_name(self):
    #get each created dispatcher
    for dispatcher in self._dispatchers:
      if dispatcher['type'] == KZ_DPT_TYPE_N_DIMENSION:
        continue
      dispatcher_name = dispatcher['name']
      self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg(dispatcher_name), message_handler = self._get_dispatcher_message_handler)
    self.assertNotEqual(self._index, len(self._dispatchers))

    #get a not existent dispatcher
    res = self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg('nonexistentdispatchername'), assert_on_error = False)
    self.assertEqual(res, -errno.ENOENT)

  def _get_dispatchers_message_handler(self, msg):
    self._add_dispatcher_messages.append(msg)

  def _check_ndim_params(self, dispatchers):
    rule_entry_dispatcher_name = ""
    for add_dispatcher_message in self._add_dispatcher_messages:
      attrs = add_dispatcher_message.get_nfmessage().get_attributes()

      message_type = add_dispatcher_message.type & 0xff
      if (message_type == KZNL_MSG_ADD_DISPATCHER or message_type == KZNL_MSG_ADD_RULE):
        dispatcher_name = parse_name_attr(attrs[KZA_DPT_NAME])

      for i in range(len(dispatchers)):
        if message_type == KZNL_MSG_ADD_DISPATCHER and dispatcher_name == dispatchers[i]['name']:
          if dispatchers[i]['type'] == KZ_DPT_TYPE_N_DIMENSION:
            rule_index = 0
          self._check_dispatcher_params(add_dispatcher_message, dispatchers[i])
          break;
        elif message_type == KZNL_MSG_ADD_RULE and dispatcher_name == dispatchers[i]['name']:
          self._check_add_rule_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index])
          rule_entry_dispatcher_name = dispatcher_name
          rule_index = rule_index + 1
          rule_entry_index = 0
          break;
        elif message_type == KZNL_MSG_ADD_RULE_ENTRY and dispatchers[i]['name'] == rule_entry_dispatcher_name:
          self._check_add_rule_entry_params(add_dispatcher_message, dispatchers[i]['rules'][rule_index - 1], rule_entry_index)
          rule_entry_index = rule_entry_index + 1
          break;
      else:
        self.assert_(True, "dispatcher with name %s could not find in the dump") #% self.get_dispatcher_name(add_dispatcher_message))


  def test_get_dispatcher_with_dump(self):
    #get the dump of dispatchers
    self.send_message(KZNL_MSG_GET_DISPATCHER, create_get_dispatcher_msg(None), message_handler = self._get_dispatchers_message_handler, dump = True)
    self._check_ndim_params(self._dispatchers)
    #self.assertEqual(len(self._add_dispatcher_messages), len(self._dispatchers))

class KZorpBaseTestCaseQuery(KZorpBaseTestCaseDispatchers, KZorpBaseTestCaseZones):

  _object_count = 0

  def __init__(self, *args):
    KZorpBaseTestCaseDispatchers.__init__(self, *args)
    KZorpBaseTestCaseZones.__init__(self, *args)

    self._initialized = False

    self._dumped_diszpancsers = []

    if (KZorpBaseTestCaseQuery._object_count == 0):
      self.initialize()
    KZorpBaseTestCaseQuery._object_count += 1

  def __del__(self):
    KZorpBaseTestCaseQuery._object_count -= 1
    if (KZorpBaseTestCaseQuery._object_count == 0):
      self.deinitialize()

  def initialize(self):
    os.system('modprobe dummy numdummies=6')
    os.system('ifconfig dummy0 10.99.201.1 netmask 255.255.255.0')
    os.system('ifconfig dummy1 10.99.202.2 netmask 255.255.255.0')
    os.system('ifconfig dummy2 10.99.203.3 netmask 255.255.255.0')
    os.system('ifconfig dummy3 10.99.204.4 netmask 255.255.255.0')
    os.system('ifconfig dummy4 10.99.205.5 netmask 255.255.255.0')
    os.system('ifconfig dummy5 10.99.205.6 netmask 255.255.255.0')
    os.system('echo 0x1 > /sys/class/net/dummy3/ifgroup')
    os.system('echo 0x1 > /sys/class/net/dummy4/ifgroup')

  def deinitialize(self):
    os.system('rmmod dummy')

  def get_dispatcher_attrs(self, message):
    attrs = message.get_nfmessage().get_attributes()
    return attrs

  def get_service_name(self, message):
    attrs = message.get_nfmessage().get_attributes()
    return parse_attr(KZA_SVC_NAME, attrs);

  def get_client_zone_name(self, message):
    attrs = message.get_nfmessage().get_attributes()
    client_zone = "not found"
    if attrs.has_key(KZA_QUERY_CLIENT_ZONE):
      client_zone = parse_name_attr(attrs[KZA_QUERY_CLIENT_ZONE])
    return client_zone

  def get_server_zone_name(self, message):
    attrs = message.get_nfmessage().get_attributes()
    server_zone = "not found"
    if attrs.has_key(KZA_QUERY_SERVER_ZONE):
      server_zone = parse_name_attr(attrs[KZA_QUERY_SERVER_ZONE])
    return server_zone

  def _query_message_handler(self, msg):
    self._dumped_diszpancsers.append(msg)


class KZorpTestCaseQuery(KZorpBaseTestCaseQuery):
  _dispatchers = [
                   { 'name' : 'tp_sockaddr',             'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'tp_sockaddr_ports',       'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'tp_sockaddr_udp',         'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'tp_sockaddr_ports_udp',   'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 10002), (30001, 30003), (40001, 40003) ],'rule_addr' : '10.99.201.1'},

                   { 'name' : 'non_tp_sockaddr',             'type' : KZ_DPT_TYPE_INET,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'non_tp_sockaddr_ports',       'type' : KZ_DPT_TYPE_INET,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'non_tp_sockaddr_udp',         'type' : KZ_DPT_TYPE_INET,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'non_tp_sockaddr_ports_udp',   'type' : KZ_DPT_TYPE_INET,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'rule_addr' : '10.99.201.1'},

                   { 'name' : 'tp_iface',             'type' : KZ_DPT_TYPE_IFACE,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifname' : 'dummy1'},
                   { 'name' : 'tp_iface_ports',       'type' : KZ_DPT_TYPE_IFACE,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifname' : 'dummy1'},
                   { 'name' : 'tp_iface_udp',         'type' : KZ_DPT_TYPE_IFACE,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifname' : 'dummy1'},
                   { 'name' : 'tp_iface_ports_udp',   'type' : KZ_DPT_TYPE_IFACE,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifname' : 'dummy1'},

                   { 'name' : 'non_tp_iface',             'type' : KZ_DPT_TYPE_IFACE,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifname' : 'dummy1'},
                   { 'name' : 'non_tp_iface_ports',       'type' : KZ_DPT_TYPE_IFACE,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifname' : 'dummy1'},
                   { 'name' : 'non_tp_iface_udp',         'type' : KZ_DPT_TYPE_IFACE,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifname' : 'dummy1'},
                   { 'name' : 'non_tp_iface_ports_udp',   'type' : KZ_DPT_TYPE_IFACE,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifname' : 'dummy1'},

                   { 'name' : 'tp_ifgroup',             'type' : KZ_DPT_TYPE_IFGROUP,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifgroup' : 1},
                   { 'name' : 'tp_ifgroup_ports',       'type' : KZ_DPT_TYPE_IFGROUP,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifgroup' : 1},
                   { 'name' : 'tp_ifgroup_udp',         'type' : KZ_DPT_TYPE_IFGROUP,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifgroup' : 1},
                   { 'name' : 'tp_ifgroup_ports_udp',   'type' : KZ_DPT_TYPE_IFGROUP,'flags' : KZF_DPT_TRANSPARENT, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifgroup' : 1},

                   { 'name' : 'non_tp_ifgroup',             'type' : KZ_DPT_TYPE_IFGROUP,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifgroup' : 1},
                   { 'name' : 'non_tp_ifgroup_ports',       'type' : KZ_DPT_TYPE_IFGROUP,'flags' : 0, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifgroup' : 1},
                   { 'name' : 'non_tp_ifgroup_udp',         'type' : KZ_DPT_TYPE_IFGROUP,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (10001, 10001) ],'ifgroup' : 1},
                   { 'name' : 'non_tp_ifgroup_ports_udp',   'type' : KZ_DPT_TYPE_IFGROUP,'flags' : 0, 'proto' : socket.IPPROTO_UDP,'proxy_port' : 1,'rule_ports' : [ (20001, 20001), (30001, 30003), (40001, 40003) ],'ifgroup' : 1}
                   ]

  _cszone_dispatchers = [
                   { 'name' : 'css_sockaddr',             'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT,   'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (50001, 50001) ],'rule_addr' : '10.99.201.1'},
                   { 'name' : 'css_fp_sockaddr',          'type' : KZ_DPT_TYPE_INET,'flags' : KZF_DPT_TRANSPARENT | KZF_DPT_FOLLOW_PARENT, 'proto' : socket.IPPROTO_TCP,'proxy_port' : 1,'rule_ports' : [ (50005, 50005) ],'rule_addr' : '10.99.201.1'}
                        ]

  _services = [
                {'dispatcher_name' : 'css_sockaddr',    'name' : 'AAA_ZAZ', 'czone' : 'AAA', 'szone' : 'ZAZ'},
                {'dispatcher_name' : 'css_sockaddr',    'name' : 'AY_ZYA', 'czone' : 'AY', 'szone' : 'ZYA'},
                {'dispatcher_name' : 'css_sockaddr',    'name' : 'ABZ_ZBA', 'czone' : 'ABZ', 'szone' : 'ZBA'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AA_ZBZ', 'czone' : 'AA', 'szone' : 'ZBZ'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AYZ_ZB', 'czone' : 'AYZ', 'szone' : 'ZB'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AB_ZZZ', 'czone' : 'AB', 'szone' : 'ZZZ'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AZZ_ZBZ', 'czone' : 'AZZ', 'szone' : 'ZBZ'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AZZ_ZAZ', 'czone' : 'AZZ', 'szone' : 'ZAZ'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AZ_ZYA', 'czone' : 'AZ', 'szone' : 'ZYA'},
                {'dispatcher_name' : 'css_fp_sockaddr', 'name' : 'AAZ_ZYZ', 'czone' : 'AAZ', 'szone' : 'ZYZ'}
              ]

  def __init__(self, *args):
    KZorpBaseTestCaseQuery.__init__(self, *args)

  def setUp(self):
    self.start_transaction()

    for zone in self._zones:
      self.send_add_zone_message(zone)

    self.end_transaction()

    self.start_transaction()

    for dispatcher in self._dispatchers:
      dispatcher_type = dispatcher['type']

      if dispatcher_type == KZ_DPT_TYPE_INET:
        message_add_dispatcher = create_add_dispatcher_sabind_msg(dispatcher['name'],                               \
                                                                  dispatcher['flags'],                              \
                                                                  dispatcher['proto'],                              \
                                                                  dispatcher['proxy_port'],                         \
                                                                  inet_aton(dispatcher['rule_addr']), \
                                                                  dispatcher['rule_ports'])
      elif dispatcher_type == KZ_DPT_TYPE_IFACE:
        message_add_dispatcher = create_add_dispatcher_ifacebind_msg(dispatcher['name'],                               \
                                                                     dispatcher['flags'],                              \
                                                                     dispatcher['proto'],                              \
                                                                     dispatcher['proxy_port'],                         \
                                                                     dispatcher['ifname'],
                                                                     dispatcher['rule_ports'])
      elif dispatcher_type == KZ_DPT_TYPE_IFGROUP:
        message_add_dispatcher = create_add_dispatcher_ifgroupbind_msg(dispatcher['name'],                               \
                                                                       dispatcher['flags'],                              \
                                                                       dispatcher['proto'],                              \
                                                                       dispatcher['proxy_port'],                         \
                                                                       dispatcher['ifgroup'],
                                                                       1,
                                                                       dispatcher['rule_ports'])
      self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher)

    self.end_transaction()

    self.start_transaction()

    for service in self._services:
      self.send_message(KZNL_MSG_ADD_SERVICE, create_add_proxyservice_msg(service['name']))

    self.end_transaction()

    self.start_transaction()
    for cszone_dispatcher in self._cszone_dispatchers:
      message_add_dispatcher = create_add_dispatcher_sabind_msg(cszone_dispatcher['name'],                               \
                                                                cszone_dispatcher['flags'],                              \
                                                                cszone_dispatcher['proto'],                              \
                                                                cszone_dispatcher['proxy_port'],                         \
                                                                inet_aton(cszone_dispatcher['rule_addr']), \
                                                                cszone_dispatcher['rule_ports'])
      self.send_message(KZNL_MSG_ADD_DISPATCHER, message_add_dispatcher)

    for service in self._services:
      self.send_message(KZNL_MSG_ADD_DISPATCHER_CSS, create_add_dispatcher_css_msg(service['dispatcher_name'], service['name'], service['czone'], service['szone']))
    self.end_transaction()

  def tearDown(self):
    self.flush_all()

  def test_dispatcher_query(self):
    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '8.4.2.1', 'iface' : 'eth1'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 40003, 'daddr' : '1.1.1.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 40002, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '8.4.2.1', 'iface' : 'eth1'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 40003, 'daddr' : '1.1.1.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 40002, 'daddr' : '10.99.201.1', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.202.2', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 20001, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 30002, 'daddr' : '10.99.202.2', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.202.2', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 20001, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 30002, 'daddr' : '10.99.202.2', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '1.1.1.1', 'iface' : 'dummy3'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.205.5', 'iface' : 'dummy4'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 20001, 'daddr' : '1.1.1.1', 'iface' : 'dummy4'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 30002, 'daddr' : '10.99.204.4', 'iface' : 'dummy3'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '1.1.1.1', 'iface' : 'dummy3'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 10001, 'daddr' : '10.99.205.5', 'iface' : 'dummy4'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 20001, 'daddr' : '1.1.1.1', 'iface' : 'dummy4'},
                 { 'proto' : socket.IPPROTO_UDP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '1.2.4.0', 'dport' : 30002, 'daddr' : '10.99.204.4', 'iface' : 'dummy3'},

                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.1' , 'dport' : 50001, 'daddr' : '10.99.201.133', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.94', 'dport' : 50001, 'daddr' : '10.99.201.208', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.69', 'dport' : 50001, 'daddr' : '10.99.201.193', 'iface' : 'dummy0'},

                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.5',  'dport' : 50005, 'daddr' : '10.99.201.197', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.85', 'dport' : 50005, 'daddr' : '10.99.201.193', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.65', 'dport' : 50005, 'daddr' : '10.99.201.149', 'iface' : 'dummy0'},

                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.21', 'dport' : 50005, 'daddr' : '10.99.201.209', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.5',  'dport' : 50005, 'daddr' : '10.99.201.213', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.5',  'dport' : 50005, 'daddr' : '10.99.201.197', 'iface' : 'dummy0'},

                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.1',  'dport' : 50001, 'daddr' : '10.99.201.129', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.81', 'dport' : 50001, 'daddr' : '10.99.201.197', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.17', 'dport' : 50001, 'daddr' : '10.99.201.213', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'family' : socket.AF_INET, 'sport' : 1, 'saddr' : '10.99.101.21', 'dport' : 50001, 'daddr' : '10.99.201.133', 'iface' : 'dummy0'},
               ]

    _dispatcher_answers = [ 'tp_sockaddr', 'non_tp_sockaddr', 'tp_sockaddr_ports', 'non_tp_sockaddr_ports',
                 'tp_sockaddr_udp', 'non_tp_sockaddr_udp', 'tp_sockaddr_ports_udp', 'non_tp_sockaddr_ports_udp',
                 'tp_iface', 'non_tp_iface', 'tp_iface_ports', 'non_tp_iface_ports',
                 'tp_iface_udp', 'non_tp_iface_udp', 'tp_iface_ports_udp', 'non_tp_iface_ports_udp',
                 'tp_ifgroup', 'non_tp_ifgroup', 'tp_ifgroup_ports', 'non_tp_ifgroup_ports',
                 'tp_ifgroup_udp', 'non_tp_ifgroup_udp', 'tp_ifgroup_ports_udp', 'non_tp_ifgroup_ports_udp'
               ]

    _css_answers = ['AAA_ZAZ', 'AY_ZYA', 'ABZ_ZBA',
                    'AA_ZBZ', 'AYZ_ZB', 'AB_ZZZ',
                    'AZ_ZYA', 'AAZ_ZYZ', 'AA_ZBZ'
                   ]

    _zone_answers = [ { 'client' : 'AAA', 'server' : 'ZAA'},
                      { 'client' : 'AYA', 'server' : 'ZBZ'},
                      { 'client' : 'AZA', 'server' : 'ZYZ'},
                      { 'client' : 'AZZ', 'server' : 'ZAZ'}
                    ]


    for query in _queries:
      family = query['family']
      message_query = create_query_msg(query['proto'],                           \
                                       family,                                   \
                                       socket.inet_pton(family, query['saddr']), \
                                       query['sport'],                           \
                                       socket.inet_pton(family, query['daddr']), \
                                       query['dport'],                           \
                                       query['iface'])
      self.send_message(KZNL_MSG_QUERY, message_query, message_handler = self._query_message_handler)

    for i in range(len(_dispatcher_answers)):
      self.assertEqual(self.get_dispatcher_name(self._dumped_diszpancsers[i]), _dispatcher_answers[i])

    for i in range(len(_css_answers)):
      self.assertEqual(self.get_service_name(self._dumped_diszpancsers[i + len(_dispatcher_answers)]), _css_answers[i])

    for i in range(len(_zone_answers)):
      self.assertEqual(self.get_client_zone_name(self._dumped_diszpancsers[i + len(_dispatcher_answers) + len(_css_answers)]), _zone_answers[i]['client'])
      self.assertEqual(self.get_server_zone_name(self._dumped_diszpancsers[i + len(_dispatcher_answers) + len(_css_answers)]), _zone_answers[i]['server'])

class KZorpTestCaseQueryNDim(KZorpBaseTestCaseQuery):

  def __init__(self, *args):
    KZorpBaseTestCaseQuery.__init__(self, *args)

  def tearDown(self):
    self.flush_all()

  def _run_query2(self, queries):
    for query in queries:
      family = query['family']
      message_query = create_query_msg(query['proto'],                           \
                                       query['family'],                          \
                                       socket.inet_pton(family, query['saddr']), \
                                       query['sport'],                           \
                                       socket.inet_pton(family, query['daddr']), \
                                       query['dport'],                           \
                                       query['iface'])
      self.send_message(KZNL_MSG_QUERY, message_query, message_handler = \
          lambda msg: self.assertEqual(self.get_service_name(msg), query['service'], str(query) + ' != ' + str(self.get_service_name(msg))))

  def _run_query(self, _queries, _answers):
    for query in _queries:
      family = query['family']
      message_query = create_query_msg(query['proto'],                           \
                                       query['family'],                          \
                                       socket.inet_pton(family, query['saddr']), \
                                       query['sport'],                           \
                                       socket.inet_pton(family, query['daddr']), \
                                       query['dport'],                           \
                                       query['iface'])
      self.send_message(KZNL_MSG_QUERY, message_query, message_handler = self._query_message_handler)

    for i in range(len(_answers)):
      self.assertEqual(self.get_service_name(self._dumped_diszpancsers[i]), _answers[i])

    pass

  def test_n_dim_dispatcher_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_with_ALL_rules', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                     'rules' : [ { 'rule_id'      : 1, 'service' : 'Z_Z',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFACE : 1, KZA_N_DIMENSION_PROTO : 1, KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_DST_PORT : 1, KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_SRC_ZONE : 3, KZA_N_DIMENSION_DST_IP : 2, KZA_N_DIMENSION_DST_ZONE : 1, KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFACE : ['dummy0'], KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZA_N_DIMENSION_SRC_PORT : [(2,3), (4,5)], KZA_N_DIMENSION_DST_PORT : [(5,6)], KZA_N_DIMENSION_SRC_IP : [InetDomain('10.99.201.5'), InetDomain('2.3.4.5/24')], KZA_N_DIMENSION_SRC_ZONE : ['AAZ', 'ZZ', 'Z'], KZA_N_DIMENSION_DST_IP : [InetDomain('10.99.101.149/16'), InetDomain('4.5.6.7/8')], KZA_N_DIMENSION_DST_ZONE : 'ZZZ', KZA_N_DIMENSION_IFGROUP : [1]},
                                 },
                                 { 'rule_id'      : 2, 'service' : 'Z_Z',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 2, KZA_N_DIMENSION_DST_IP : 3, KZA_N_DIMENSION_SRC_ZONE : 1, KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_DST_PORT : 2, KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_PROTO : 1, KZA_N_DIMENSION_IFACE : 3 },
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AZA', 'ZAZ'], KZA_N_DIMENSION_DST_IP : [InetDomain('8.7.6.5'), InetDomain('7.6.5.4/31'), InetDomain('9.8.7.6/25')], KZA_N_DIMENSION_SRC_ZONE : 'ZZ', KZA_N_DIMENSION_SRC_IP : [InetDomain('5.4.3.2/32'), InetDomain('6.5.4.3/30')], KZA_N_DIMENSION_DST_PORT : [(66,66),(100,200)], KZA_N_DIMENSION_SRC_PORT : [(23,24), (30, 40)], KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP], KZA_N_DIMENSION_IFACE : ['dummy0', 'dummy1', 'dummy2'] }
                                 }
                               ]
                   }
                 ]

    _services = ['Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.101.149', 'iface' : 'dummy0'},
               ]

    _answers = ['Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_backtrack_iface_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_backtrack', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFACE : 1, KZA_N_DIMENSION_DST_IP : 1, KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFACE : ['dummy0'], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.4/32')], KZA_N_DIMENSION_IFGROUP : [1]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZA_N_DIMENSION_IFACE : 1, KZA_N_DIMENSION_DST_IP : 1 },
                                     'entry_values' : { KZA_N_DIMENSION_IFACE : ['dummy3'], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.5')] }
                                   }
                               ]
                   }
                 ]

    _services = ['A_A', 'Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy3'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.5', 'iface' : 'dummy3'},
               ]

    _answers = ['A_A', 'A_A', 'Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_backtrack_src_port_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_backtrack', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 2, KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(10,10),(15,20)], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.4/32')]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 1, KZA_N_DIMENSION_DST_IP : 1 },
                                     'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(15,20)], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.5')] }
                                   }
                               ]
                   }
                 ]

    _services = ['A_A', 'Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 10, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 15, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 15, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.5', 'iface' : 'dummy0'},
               ]

    _answers = ['A_A', 'A_A', 'Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_backtrack_dst_port_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_backtrack', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 2, KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(10,10),(15,20)], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.4/32')]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 1, KZA_N_DIMENSION_DST_IP : 1 },
                                     'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(15,20)], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.5')] }
                                   }
                               ]
                   }
                 ]

    _services = ['A_A', 'Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 1, 'saddr' : '1.1.1.1', 'dport' : 10, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 1, 'saddr' : '1.1.1.1', 'dport' : 15, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 1, 'saddr' : '1.1.1.1', 'dport' : 15, 'family' : socket.AF_INET, 'daddr' : '1.2.3.5', 'iface' : 'dummy0'},
               ]

    _answers = ['A_A', 'A_A', 'Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_backtrack_src_ip_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_backtrack', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 2, KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.1.1.1/24'), InetDomain('1.1.1.1/32')], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.4/32')]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1, KZA_N_DIMENSION_DST_IP : 1 },
                                     'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.1.1.1/24')], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.5')] }
                                   }
                               ]
                   }
                 ]

    _services = ['A_A', 'Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '1.1.1.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '1.1.1.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.5', 'iface' : 'dummy0'},
               ]

    _answers = ['A_A', 'A_A', 'Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_backtrack_src_zone_query(self):
    _dispatchers = [ { 'name' : 'n_dimension_backtrack', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                       'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 2, KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['ABA', 'AB'], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.4/32')]},
                                   },
                                   { 'rule_id'      : 2, 'service' : 'Z_Z',
                                     'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1, KZA_N_DIMENSION_DST_IP : 1 },
                                     'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['AB'], KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.5')] }
                                   }
                               ]
                   }
                 ]

    _services = ['A_A', 'Z_Z']

    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.65', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 2, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.5', 'iface' : 'dummy0'},
               ]

    _answers = ['A_A', 'A_A', 'Z_Z']

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_iface_ifgroup_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                    'entry_nums'   : { KZA_N_DIMENSION_IFACE : 2},
                                    'entry_values' : { KZA_N_DIMENSION_IFACE : ['dummy0', 'dummy1'] }
                                  },
                                  { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFGROUP : [1] }
                                  },
                                ]
                    }]

    _services = ['A_A', 'AA_AA']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy0'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy2'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy3'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy4'},
               ]
    _answers = [ 'A_A', 'A_A', None, 'AA_AA', 'AA_AA',
               ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_iface_ifgroup_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 3,
                      'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                    'entry_nums'   : { KZA_N_DIMENSION_IFACE : 2},
                                    'entry_values' : { KZA_N_DIMENSION_IFACE : ['dummy0', 'dummy1'] }
                                  },
                                  { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_IFGROUP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_IFGROUP : [1] }
                                  },
                                  { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                    'entry_nums'   : { KZA_N_DIMENSION_IFACE : 0},
                                    'entry_values' : { KZA_N_DIMENSION_IFACE : [] }
                                  },

                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy2'},
               ]
    _answers = [ 'AAA_AAA',
               ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_proto_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                      'rules' : [ { 'rule_id'      : 2, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_PROTO : 1},
                                   'entry_values' : { KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP] }
                                  },
                                ]
                    }]

    _services = ['A_A']
    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', None
               ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_proto_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [ { 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_PROTO : 1},
                                   'entry_values' : { KZA_N_DIMENSION_PROTO : [socket.IPPROTO_TCP] }
                                  },
                                  {'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_PROTO : 0},
                                   'entry_values' : { KZA_N_DIMENSION_PROTO : [] }
                                  },

                                ]
                    }]

    _services = ['A_A', 'AA_AA']
    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'AA_AA'
               ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)


  def test_n_dim_src_port_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                      'rules' : [{ 'rule_id'      : 3, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 2},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(10,10), (60000, 65535)] }
                                 },
                                ]
                    }]

    _services = ['A_A']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 10, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 60000, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 63000, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 65535, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 59999, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 9, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 11, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'A_A', 'A_A', 'A_A', None, None, None ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_src_port_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 2},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [(10,10), (60000, 65535)] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_PORT : 0},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_PORT : [] }
                                 },

                                ]
                    }]

    _services = ['A_A', 'AA_AA']

    packet = dict(proto=socket.IPPROTO_UDP, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')

    queries = [
        update_dict(packet, sport=10, dport=10, service='A_A'),
        update_dict(packet, sport=60000, dport=60000, service='A_A'),
        update_dict(packet, sport=63000, dport=63000, service='A_A'),
        update_dict(packet, sport=65535, dport=65535, service='A_A'),
        update_dict(packet, sport=59999, dport=59999, service='AA_AA'),
        update_dict(packet, sport=9, dport=9, service='AA_AA'),
        update_dict(packet, sport=11, dport=11, service='AA_AA'),
        ]
    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(queries)

  def test_n_dim_dst_port_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 1,
                      'rules' : [{ 'rule_id'      : 3, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 2},
                                   'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(10,10), (60000, 65535)] }
                                 },
                                ]
                    }]

    _services = ['A_A']

    packet = dict(proto=socket.IPPROTO_UDP, sport=5, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')
    queries = [
        update_dict(packet, dport=10, service='A_A'),
        update_dict(packet, dport=60000, service='A_A'),
        update_dict(packet, dport=63000, service='A_A'),
        update_dict(packet, dport=65535, service='A_A'),
        update_dict(packet, dport=59999, service=None),
        update_dict(packet, dport=9, service=None),
        update_dict(packet, dport=11, service=None),
        ]
    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(queries)

  def test_n_dim_dst_port_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 2},
                                   'entry_values' : { KZA_N_DIMENSION_DST_PORT : [(10,10), (60000, 65535)] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_PORT : 0},
                                   'entry_values' : { KZA_N_DIMENSION_DST_PORT : [] }
                                 },

                                ]
                    }]

    _services = ['A_A', 'AA_AA']

    packet = dict(proto=socket.IPPROTO_UDP, saddr='1.1.1.1', family=socket.AF_INET, daddr='1.2.3.4', iface='dummy1')

    queries = [
        update_dict(packet, sport=10, dport=10, service='A_A'),
        update_dict(packet, sport=60000, dport=60000, service='A_A'),
        update_dict(packet, sport=63000, dport=63000, service='A_A'),
        update_dict(packet, sport=65535, dport=65535, service='A_A'),
        update_dict(packet, sport=59999, dport=59999, service='AA_AA'),
        update_dict(packet, sport=9, dport=9, service='AA_AA'),
        update_dict(packet, sport=11, dport=11, service='AA_AA'),
        ]
    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(queries)

  def test_n_dim_src_ip_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 7,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/24')] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/30')] }
                                 },
                                 { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/31')] }
                                 },
                                 { 'rule_id'      : 4, 'service' : 'B_B',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.200')] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'C',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1,
                                                      KZA_N_DIMENSION_SRC_IP6 : 1
                                                    },
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetSubnet('2.0.0.0/8')],
                                                      KZA_N_DIMENSION_SRC_IP6 : [Inet6Subnet('ffc0::1/127')]
                                                    }
                                 },
                                 { 'rule_id'      : 6, 'service' : 'D',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1,
                                                      KZA_N_DIMENSION_SRC_IP6 : 2
                                                    },
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetSubnet('2.3.4.5/32')],
                                                      KZA_N_DIMENSION_SRC_IP6 : [Inet6Subnet('ffc0::0/10'), Inet6Subnet('ffc0::3/128')]
                                                    }
                                 },
                                 { 'rule_id'      : 7, 'service' : 'E',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP6 : 1 },
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP6 : [Inet6Subnet('ffc0::2/127')] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'C', 'D', 'E']

    ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, daddr='1.1.1.1')
    ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, daddr='::')

    _queries = [
        update_dict(ipv4_packet, saddr='1.2.3.4', service='A_A'),
        update_dict(ipv4_packet, saddr='1.2.3.2', service='AA_AA'),
        update_dict(ipv4_packet, saddr='1.2.3.1', service='AAA_AAA'),
        update_dict(ipv4_packet, saddr='1.2.3.200', service='B_B'),
        update_dict(ipv4_packet, saddr='1.2.2.5', service=None),
        update_dict(ipv6_packet, saddr='1234::', service=None),
        update_dict(ipv6_packet, saddr='ffc0::1', service="C"),
        update_dict(ipv4_packet, saddr='2.3.4.5', service="D"),
        update_dict(ipv4_packet, saddr='2.3.4.6', service="C"),
        update_dict(ipv6_packet, saddr='ffc0::2', service="E"),
        update_dict(ipv6_packet, saddr='ffc0::3', service="D"),
        ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(_queries)

  def test_n_dim_src_ip_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 5,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/24')] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/30')] }
                                 },
                                 { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.0/31')] }
                                 },
                                 { 'rule_id'      : 4, 'service' : 'B_B',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [InetDomain('1.2.3.200')] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'BB_BB',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_IP : 0},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_IP : [] }
                                 },

                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB']
    _queries = [
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.4', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.2', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.3.200', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_TCP, 'sport' : 5, 'saddr' : '1.2.2.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB' ]

    ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, daddr='1.1.1.1')
    ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, daddr='::')

    _queries = [
        update_dict(ipv4_packet, saddr='1.2.3.4', service='A_A'),
        update_dict(ipv4_packet, saddr='1.2.3.2', service='AA_AA'),
        update_dict(ipv4_packet, saddr='1.2.3.1', service='AAA_AAA'),
        update_dict(ipv4_packet, saddr='1.2.3.200', service='B_B'),
        update_dict(ipv4_packet, saddr='1.2.2.5', service='BB_BB'),
        update_dict(ipv6_packet, saddr='1234::', service='BB_BB'),
        ]
    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(_queries)

  def test_n_dim_src_zone_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 5,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['ABA'] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['AB'] }
                                 },
                                 { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['A'] }
                                 },
                                 { 'rule_id'      : 4, 'service' : 'B_B',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['AAZ'] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'BB_BB',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['AY'] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.65', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.85', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.21', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'B_B', 'BB_BB', 'AAA_AAA', 'AA_AA', None ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_src_zone_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : ['ABA'] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_SRC_ZONE : 0},
                                   'entry_values' : { KZA_N_DIMENSION_SRC_ZONE : [] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.65', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.5', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.85', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.21', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '10.99.201.69', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.2.3.4', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA' ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_dst_ip_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 7,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.0/24')] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.0/30')] }
                                 },
                                 { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.0/31')] }
                                 },
                                 { 'rule_id'      : 4, 'service' : 'B_B',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetDomain('1.2.3.200')] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'C',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1,
                                                      KZA_N_DIMENSION_DST_IP6 : 1
                                                    },
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetSubnet('2.0.0.0/8')],
                                                      KZA_N_DIMENSION_DST_IP6 : [Inet6Subnet('ffc0::1/127')]
                                                    }
                                 },
                                 { 'rule_id'      : 6, 'service' : 'D',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 1,
                                                      KZA_N_DIMENSION_DST_IP6 : 2
                                                    },
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [InetSubnet('2.3.4.5/32')],
                                                      KZA_N_DIMENSION_DST_IP6 : [Inet6Subnet('ffc0::0/10'), Inet6Subnet('ffc0::3/128')]
                                                    }
                                 },
                                 { 'rule_id'      : 7, 'service' : 'E',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP6 : 1 },
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP6 : [Inet6Subnet('ffc0::2/127')] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'C', 'D', 'E']

    ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, saddr='1.1.1.1')
    ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, saddr='::')

    _queries = [
        update_dict(ipv4_packet, daddr='1.2.3.4', service='A_A'),
        update_dict(ipv4_packet, daddr='1.2.3.2', service='AA_AA'),
        update_dict(ipv4_packet, daddr='1.2.3.1', service='AAA_AAA'),
        update_dict(ipv4_packet, daddr='1.2.3.200', service='B_B'),
        update_dict(ipv4_packet, daddr='1.2.2.5', service=None),
        update_dict(ipv6_packet, daddr='1234::', service=None),
        update_dict(ipv6_packet, daddr='ffc0::1', service="C"),
        update_dict(ipv4_packet, daddr='2.3.4.5', service="D"),
        update_dict(ipv4_packet, daddr='2.3.4.6', service="C"),
        update_dict(ipv6_packet, daddr='ffc0::2', service="E"),
        update_dict(ipv6_packet, daddr='ffc0::3', service="D"),
        ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(_queries)

  def test_n_dim_dst_ip_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'Non-empty',
                                   'entry_nums'   : {
                                     KZA_N_DIMENSION_DST_IP : 1,
                                     KZA_N_DIMENSION_DST_IP6 : 1,
                                     },
                                   'entry_values' : {
                                     KZA_N_DIMENSION_DST_IP : [InetSubnet('1.2.3.0/24')],
                                     KZA_N_DIMENSION_DST_IP6 : [Inet6Subnet('1234::/128')],
                                     }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'Empty',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_IP : 0},
                                   'entry_values' : { KZA_N_DIMENSION_DST_IP : [] }
                                 },
                                ]
                    }]

    _services = ['Non-empty', 'Empty']
    ipv4_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET, saddr='1.1.1.1')
    ipv6_packet = dict(proto=socket.IPPROTO_TCP, sport=5, dport=5, iface='dummy1', family=socket.AF_INET6, saddr='::')

    queries = [
        update_dict(ipv4_packet, daddr='1.2.3.4', service='Non-empty'),
        update_dict(ipv4_packet, daddr='1.2.2.5', service='Empty'),
        update_dict(ipv6_packet, daddr='1234::', service='Non-empty'),
        update_dict(ipv6_packet, daddr='1235::', service='Empty'),
        ]
    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query2(queries)

  def test_n_dim_dst_zone_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 5,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['ABA'] }
                                 },
                                 { 'rule_id'      : 2, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AB'] }
                                 },
                                 { 'rule_id'      : 3, 'service' : 'AAA_AAA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['A'] }
                                 },
                                 { 'rule_id'      : 4, 'service' : 'B_B',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AAZ'] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'BB_BB',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['AY'] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA', 'AAA_AAA', 'B_B', 'BB_BB']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.65', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.5', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.85', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.21', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.69', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'B_B', 'BB_BB', 'AAA_AAA', 'AA_AA', None ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

  def test_n_dim_dst_zone_empty_query(self):
    _dispatchers = [{ 'name' : 'n_dimension_specific', 'type' : KZ_DPT_TYPE_N_DIMENSION, 'flags' : KZF_DPT_TRANSPARENT, 'proxy_port' : 1, 'num_rules' : 2,
                      'rules' : [{ 'rule_id'      : 1, 'service' : 'A_A',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 1},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : ['ABA'] }
                                 },
                                 { 'rule_id'      : 5, 'service' : 'AA_AA',
                                   'entry_nums'   : { KZA_N_DIMENSION_DST_ZONE : 0},
                                   'entry_values' : { KZA_N_DIMENSION_DST_ZONE : [] }
                                 },
                                ]
                    }]

    _services = ['A_A', 'AA_AA']
    _queries = [
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.65', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.5', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.85', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.21', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '10.99.201.69', 'iface' : 'dummy1'},
                 { 'proto' : socket.IPPROTO_UDP, 'sport' : 5, 'saddr' : '1.1.1.1', 'dport' : 5, 'family' : socket.AF_INET, 'daddr' : '1.1.1.1', 'iface' : 'dummy1'},
               ]
    _answers = [ 'A_A', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA', 'AA_AA' ]

    self.setup_service_dispatcher(_services, _dispatchers)
    self._run_query(_queries, _answers)

class KZorpBaseTestCaseBind(KZorpComm):
  _bind_addrs = [
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.2'), 'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::1'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET6, 'addr' : socket.inet_pton(socket.AF_INET6, 'fec0::2'),   'port' : 50080, 'proto' : socket.IPPROTO_TCP },
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50081, 'proto' : socket.IPPROTO_TCP },
                  { 'instance' : KZ_INSTANCE_GLOBAL, 'family' : socket.AF_INET,  'addr' : socket.inet_pton(socket.AF_INET,  '127.0.0.1'), 'port' : 50080, 'proto' : socket.IPPROTO_UDP },
                ]
  _dumped_bind_addrs = []

  def __init__(self, *args):
    KZorpComm.__init__(self, *args)

  def setUp(self):
    self.start_transaction()
    for bind_addr in self._bind_addrs:
      msg_add_bind = NfnetlinkMessageAddBind(**bind_addr)
      self.send_message(KZNL_MSG_ADD_BIND, msg_add_bind)
    self.end_transaction()

  def tearDown(self):
    self.flush_all()

class KZorpTestCaseBind(KZorpBaseTestCaseBind):
  _dumped_binds = []

  def __init__(self, *args):
    KZorpBaseTestCaseBind.__init__(self, *args)

  def test_unicity_check_at_transaction(self):
    self.flush_all()
    self.start_transaction()
    for bind_addr in self._bind_addrs:
      msg_add_bind = NfnetlinkMessageAddBind(**bind_addr)
      self.send_message(KZNL_MSG_ADD_BIND, msg_add_bind)

      try:
        msg_add_bind = NfnetlinkMessageAddBind(**bind_addr)
        self.send_message(KZNL_MSG_ADD_BIND, msg_add_bind)
      except AssertionError as e:
        if e.args[0] != "talk with KZorp failed: result='-17' error='File exists'":
          raise e

    self.end_transaction()

  def test_unicity_check_at_instance(self):
    self.flush_all()
    self.start_transaction()
    for bind_addr in self._bind_addrs:
      msg_add_bind = NfnetlinkMessageAddBind(**bind_addr)
      self.send_message(KZNL_MSG_ADD_BIND, msg_add_bind)

    for bind_addr in self._bind_addrs:
      try:
        msg_add_bind = NfnetlinkMessageAddBind(**bind_addr)
        self.send_message(KZNL_MSG_ADD_BIND, msg_add_bind)
      except AssertionError as e:
        if e.args[0] != "talk with KZorp failed: result='-17' error='File exists'":
          raise e

    self.end_transaction()

  def _dump_bind_handler(self, message):
    self._dumped_binds.append(message)

  def get_bind(self):
    self.start_transaction()
    msg_get_bind = NfnetlinkMessageGetBind()
    self.send_message(KZNL_MSG_GET_BIND, msg_get_bind, message_handler = self._dump_bind_handler, dump = True)
    self.end_transaction()

  def test_flush(self):
    self.flush_all()

    self._dumped_binds = []
    self.get_bind()

    self.assertEqual(len(self._dumped_binds), 0, "bind list not empty after flush; bind_num='%d'" % len(self._dumped_binds))

  def test_add(self):
    self._dumped_binds = []
    self.get_bind()

    self.assertEqual(len(self._dumped_binds), len(self._bind_addrs),
                     "bind list not empty after flush; added_bind_num='%d' dumped_bind_num='%d'" % (len(self._dumped_binds), len(self._dumped_binds)))

    for i in range(len(self._bind_addrs)):
      msg_add_bind = NfnetlinkMessageAddBind(**self._bind_addrs[i])
      self.assertEqual(msg_add_bind, self._dumped_binds[i].get_nfmessage())

  def test_auto_flush(self):
    bind_addr_num = len(self._bind_addrs)
    orig_handle = self.handle
    self.handle = None

    self.create_handle()

    self._dumped_binds = []
    self.get_bind()

    self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
    for i in range(bind_addr_num):
      msg_add_bind = NfnetlinkMessageAddBind(**self._bind_addrs[i])
      self.assertEqual(msg_add_bind, self._dumped_binds[i].get_nfmessage())

    for bind_addr in self._bind_addrs:
      bind_addr['port'] = bind_addr['port'] + 10000

    self.setUp()

    self._dumped_binds = []
    self.get_bind()

    self.assertEqual(len(self._dumped_binds), len(self._bind_addrs) * 2)
    for i in range(bind_addr_num):
      msg_add_bind = NfnetlinkMessageAddBind(**self._bind_addrs[i])
      self.assertEqual(msg_add_bind, self._dumped_binds[i].get_nfmessage())
    for i in range(bind_addr_num):
      self._bind_addrs[i]['port'] = self._bind_addrs[i]['port'] - 10000
      msg_add_bind = NfnetlinkMessageAddBind(**self._bind_addrs[i])
      self.assertEqual(msg_add_bind, self._dumped_binds[i + bind_addr_num].get_nfmessage())

    self.close_handle()
    self.handle = orig_handle

    self._dumped_binds = []
    self.get_bind()

    self.assertEqual(len(self._dumped_binds), len(self._bind_addrs))
    for i in range(bind_addr_num):
      msg_add_bind = NfnetlinkMessageAddBind(**self._bind_addrs[i])
      self.assertEqual(msg_add_bind, self._dumped_binds[i].get_nfmessage())

    self.reopen_handle()

    self._dumped_binds = []
    self.get_bind()
    self.assertEqual(len(self._dumped_binds), 0)

class KZorpTestResult(unittest.TextTestResult):
  def __init__(self, stream, descriptions, verbosity):
    super(KZorpTestResult, self).__init__(stream, descriptions, verbosity)

  def addFailure(self, test, err):
    super(KZorpTestResult, self).addFailure(test, err)

  def addError(self, test, err):
    super(KZorpTestResult, self).addError(test, err)

class KZorpTestRunner(unittest.TextTestRunner):
  def __init__(self, stream=sys.stderr, descriptions=True, verbosity=1,
               failfast=False, buffer=False, resultclass=None):
    super(KZorpTestRunner, self).__init__(stream=stream, descriptions=descriptions, verbosity=verbosity,
                                          failfast=failfast, buffer=buffer, resultclass=KZorpTestResult)

  def _makeResult(self):
    return super(KZorpTestRunner, self)._makeResult()

if __name__ == "__main__":

  if os.getenv("USER") != "root":
    print "ERROR: You need to be root to run the unit test"
    sys.exit(1)

  if glob.glob('/var/run/zorp/*.pid'):
    print "ERROR: pidfile(s) exist in /var/run/zorp directory. Zorp is running?"
    print "       You should stop Zorp and/or delete pid files from /var/run/zorp"
    print "       in order to run this test."
    sys.exit(1)

  unittest.main(testRunner=KZorpTestRunner)
