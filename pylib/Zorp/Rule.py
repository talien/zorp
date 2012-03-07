############################################################################
##
## Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
## 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
##
##
############################################################################
"""
"""

from Util import makeSequence
from Subnet import Subnet
from Zone import Zone
import kznf.kznfnetlink as kznf
import Globals
import Dispatch

class RuleSet(object):

        def __init__(self):
                self._rules = []
                self._rule_id_index = 1
                self._rule_id_set = set()

        def _getNextId(self):
                while (self._rule_id_index in self._rule_id_set):
                        self._rule_id_index += 1

                return self._rule_id_index

        def add(self, rule):
                rule_id = rule.getId()
                if not rule_id:
                        # generate a unique id
                        rule_id = self._getNextId()
                        rule.setId(rule_id)
                elif rule_id in self._rule_id_set:
                        # the specified id is not unique
                        raise ValueError, "Duplicate rule id found; id='%d'" % (rule_id,)

                self._rule_id_set.add(rule_id)
                self._rules.append(rule)

        def _sortRules(self):
                self._rules.sort(lambda a, b: cmp(a.getId(), b.getId()))

        def __iter__(self):
                self._sortRules()
                return iter(self._rules)

        @property
        def length(self):
                return len(self._rules)

class PortRange(object):
        def __init__(self, low, high):
                self._low = low
                self._high = high

        def getTuple(self):
                return (self._low, self._high)

class Rule(object):
        valid_dimensions = { 'iface'       : kznf.KZA_N_DIMENSION_IFACE, \
                             'ifgroup'     : kznf.KZA_N_DIMENSION_IFGROUP, \
                             'proto'       : kznf.KZA_N_DIMENSION_PROTO, \
                             'src_port'    : kznf.KZA_N_DIMENSION_SRC_PORT, \
                             'dst_port'    : kznf.KZA_N_DIMENSION_DST_PORT, \
                             'src_subnet'  : kznf.KZA_N_DIMENSION_SRC_IP, \
                             'src_subnet6' : kznf.KZA_N_DIMENSION_SRC_IP6, \
                             'src_zone'    : kznf.KZA_N_DIMENSION_SRC_ZONE, \
                             'dst_subnet'  : kznf.KZA_N_DIMENSION_DST_IP, \
                             'dst_subnet6' : kznf.KZA_N_DIMENSION_DST_IP6, \
                             'dst_zone'    : kznf.KZA_N_DIMENSION_DST_ZONE }

        def __init__(self, **kw):

                def parseSubnets(subnet_list):
                        """
                        Helper function to convert a string-based
                        subnet list to two tuples consisting of
                        InetSubnet and InetSubnet6 instances.
                        """
                        import socket
                        subnets = { socket.AF_INET: [], socket.AF_INET6: [] }

                        subnet_list = makeSequence(subnet_list)

                        for item in subnet_list:
                                if isinstance(item, basestring):
                                        subnet = Subnet.create(item)
                                elif isinstance(item, Subnet):
                                        subnet = item
                                else:
                                        raise ValueError, "Invalid subnet specification: value='%s'" % (item,)

                                subnets[subnet.get_family()].append((subnet.addr_packed(), subnet.netmask_packed()))

                        return (tuple(subnets[socket.AF_INET]), tuple(subnets[socket.AF_INET6]))

                def resolveZones(name_list):
                        """
                        Helper function to convert a list of zone
                        names to a list of Zone instnaces
                        """
                        name_list = makeSequence(name_list)

                        for name in name_list:
                                if Zone.lookup_by_name(name) == None:
                                        raise ValueError, "No zone was defined with that name; zone='%s'" % (name,)

                def parsePorts(port_list):
                        """
                        Helper function to convert a port or port
                        range list to a list of port ranges. Accepted
                        input formats are:

                        (port1, port2, port3) - list of ports
                        (port1, (begin, end), port3) - list of ports mixed with ranges
                        """
                        ports = []
                        port_list = makeSequence(port_list)

                        for item in port_list:
                                if isinstance(item, PortRange):
                                        ports.append(item.getTuple())
                                else:
                                        if isinstance(item, basestring):
                                                item = int(item)

                                        if not isinstance(item, int):
                                                raise ValueError, "Integer port value expected; value='%s'" % (item,)

                                        ports.append((item, item))

                        return ports

                # store id
                self._id = kw.pop('rule_id', None)

                # store service
                service_name = kw.pop('service', None)
                self._service = Globals.services.get(service_name, None)
                if not self._service:
                        raise ValueError, "No valid service was specified for the rule; service='%s'" % (service_name,)

                # convert and check special dimensions: subnets, ports and zones at the moment
                (kw['src_subnet'], kw['src_subnet6']) = parseSubnets(kw.get('src_subnet', []))
                (kw['dst_subnet'], kw['dst_subnet6']) = parseSubnets(kw.get('dst_subnet', []))
                kw['src_port'] = parsePorts(kw.get('src_port', []))
                kw['dst_port'] = parsePorts(kw.get('dst_port', []))
                resolveZones(kw.get('src_zone', []))
                resolveZones(kw.get('dst_zone', []))

                # store values specified
                self._dimensions = {}
                for key, value in kw.items():
                        if key not in self.valid_dimensions:
                                raise ValueError, "Unknown dimension '%s'" % (key,)

                        self._dimensions[key] = makeSequence(value)

                Globals.rules.add(self)
                Dispatch.RuleDispatcher.createOneInstance()

        def getId(self):
                return self._id

        def setId(self, rule_id):
                self._id = rule_id

        def buildKZorpMessage(self, dispatcher_name):
                messages = []

                # determine maximum dimension length

                kzorp_dimensions = {}
                for (key, value) in self._dimensions.items():
                        kzorp_dimensions[self.valid_dimensions[key]] = value

                kzorp_dimension_sizes = dict(map(lambda (key, value): (key, len(value)), kzorp_dimensions.items()))
                max_dimension_length = max(kzorp_dimension_sizes.values()) if len(kzorp_dimension_sizes) > 0 else 0

                messages.append((kznf.KZNL_MSG_ADD_RULE,
                                 kznf.create_add_n_dimension_rule_msg(dispatcher_name,
                                                                      self.getId(),
                                                                      self._service.name,
                                                                      kzorp_dimension_sizes)))

                for i in xrange(max_dimension_length):
                        data = {}

                        for dimension, values in kzorp_dimensions.items():
                                if len(values) > i:
                                        data[dimension] = values[i]

                        messages.append((kznf.KZNL_MSG_ADD_RULE_ENTRY,
                                         kznf.create_add_n_dimension_rule_entry_msg(dispatcher_name,
                                                                                    self.getId(),
                                                                                    data)))
                return messages
