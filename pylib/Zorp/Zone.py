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
<module maturity="stable">
  <summary>
    Module defining interface to the Zones.
  </summary>
  <description>
    <para>
      This module defines the <parameter>Zone</parameter> class.
    </para>
    <para>
              Zones are the basis of access control in Zorp. A zone consists of a
              set of IP addresses or address ranges. For example, a zone can
              contain an IPv4 subnet.
            </para>
            <para>
              Zones are organized into a hierarchy created by the
              Zorp administrator. Children zones inherit the
              security attributes (set of permitted services etc.) from their
              parents. The administrative hierarchy often reflects the organization of
              the company, with zones assigned to the different departments.</para>
              <para>Zone definitions also determine which Zorp services can
              be started from the zone (<parameter>outbound_services</parameter>)
              and which services can enter the zone (<parameter>inbound_services</parameter>).</para>
              <para>
              When Zorp has to determine which zone a client belongs to,
              it selects the most specific zone containing the searched IP address.
              If an IP address belongs to two different zones, the straitest
              match is the most specific zone.
              </para>
        <example>
        <title>Finding IP networks</title>
        <para>Suppose there are three zones configured: <parameter>Zone_A</parameter> containing the
            <parameter>10.0.0.0/8</parameter> network, <parameter>Zone_B</parameter> containing the
            <parameter>10.0.0.0/16</parameter> network, and <parameter>Zone_C</parameter> containing
          the <parameter>10.0.0.25</parameter> IP address. Searching for the
          <parameter>10.0.44.0</parameter> network returns <parameter>Zone_B</parameter>, because
          that is the most specific zone matching the searched IP address. Similarly, searching for
            <parameter>10.0.0.25</parameter> returns only <parameter>Zone_C</parameter>.</para>
        <para>This approach is used in the service definitions as well: when a client sends a
          connection request, Zorp looks for the most specific zone containing the IP address of the
          client. Suppose that the clients in <parameter>Zone_A</parameter> are allowed to use HTTP.
          If a client with IP <parameter>10.0.0.50</parameter> (thus belonging to
          <parameter>Zone_B</parameter>) can only use HTTP if <parameter>Zone_B</parameter> is the
          child of <parameter>Zone_A</parameter>, or if a service definition explicitly permits
            <parameter>Zone_B</parameter> to use HTTP.</para>
      </example>
     <example id="inetzone_example">
     <title>Zone examples</title>
     <para>The following example defines a simple zone hierarchy. The following
     zones are defined:</para>
     <itemizedlist>
     <listitem>
     <para><emphasis>internet</emphasis>: This zone contains every possible IP
     addresses, if an IP address does not belong to another zone, than it belongs
     to the <emphasis>internet</emphasis> zone. This zone accepts HTTP requests
     coming from the <emphasis>office</emphasis> zone, and can access the public
     HTTP and FTP services of the <emphasis>DMZ</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>office</emphasis>: This zone contains the <parameter>192.168.1.0/32
     </parameter> and <parameter>192.168.2.0/32
     </parameter> networks. The <emphasis>office</emphasis> zone can access the
     HTTP services of the <emphasis>internet</emphasis> zone, and use FTP to
     access the <emphasis>DMZ</emphasis> zone. External connections are not
     permitted to enter the zone (no <parameter>inbound_services</parameter> are defined).</para>
     </listitem>
     <listitem>
     <para><emphasis>management</emphasis>: This zone is separated from the
     <emphasis>office</emphasis> zone, because it contans an independent subnet <parameter>192.168.3.0/32
     </parameter>. But from the Zorp administrator's view, it is the child zone of
     the <emphasis>office</emphasis> zone, meaning that it can use (and accept)
      the same services as the <emphasis>office</emphasis> zone: HTTP to the
       <emphasis>internet</emphasis> zone, and FTP to the <emphasis>DMZ</emphasis> zone.</para>
     </listitem>
     <listitem>
     <para><emphasis>DMZ</emphasis>: This zone can accept connections HTTP
     and FTP connections from other zones, but cannot start external connections.</para>
     </listitem>
     </itemizedlist>
     <synopsis>
Zone('internet', ['0.0.0.0/0', '::/0'],
    inbound_services=[
        "office_http_inter"],
    outbound_services=[
        "inter_http_dmz",
        "inter_ftp_dmz"])

Zone('office', ['192.168.1.0/32', '192.168.2.0/32'],
    outbound_services=[
        "office_http_inter",
        "office_ftp_dmz"])

Zone('management', ['192.168.3.0/32'],
    admin_parent='office')

Zone('DMZ', ['10.50.0.0/32'],
    inbound_services=[
        "office_ftp_dmz",
        "inter_http_dmz",
        "inter_ftp_dmz"])</synopsis>
     </example>
  </description>
</module>
"""

from Zorp import *
from Subnet import Subnet, InetSubnet, Inet6Subnet
from socket import htonl, ntohl
from traceback import print_exc
from Exceptions import ZoneException
import types
import radix
import struct

import kznf.kznfnetlink

class Zone(object):
  """
        <class maturity="stable">
          <summary>
            Class encapsulating IP zones.
          </summary>
          <description>
            <para>
              This class encapsulates IPv4 and IPv6 zones;
            </para>
      <example>
    <title>Determining the zone of an IP address</title>
    <para>
    An IP address always belongs to the most specific zone.
    Suppose that <parameter>Zone A</parameter> includes the IP network <parameter>10.0.0.0/8</parameter>
    and <parameter>Zone B</parameter> includes the network <parameter>10.0.1.0/24</parameter>.
    In this case, a client machine with the <parameter>10.0.1.100/32</parameter> IP address
    belongs to both zones from an IP addressing point of view. But <parameter>Zone B</parameter> is more
    specific (in CIDR terms), so the client machine belongs to <parameter>Zone B</parameter> in Zorp.
    </para>
      </example>
          </description>
          <metainfo>
            <attributes/>
          </metainfo>
        </class>
  """
  zone_subnet_tree = radix.Radix()
  zones = {}
  def __init__(self, name, addrs=(), inbound_services=None, outbound_services=None, admin_parent=None, umbrella=0):
    """
                <method maturity="stable">
                  <summary>
                    Constructor to initialize a Zone instance
                  </summary>
                  <description>
                    <para>
                      This constructor initializes a Zone object.
                    </para>
                  </description>
                  <metainfo>
                    <arguments>
                      <argument maturity="stable">
                        <name>name</name>
                        <type><string/></type>
                        <description>Name of the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>addr</name>
                        <type><list><string/></list></type>
                        <description>
                          A string representing an address range interpreted
                          by the domain class (last argument), *or* a list of
                          strings representing multiple address ranges. <!--FIXME-->
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>inbound_services</name>
                        <type><list><string/></list></type>
                        <description>
                          A comma-separated list of services permitted to enter the zone.
                        </description>
                      </argument>
                      <argument maturity="stable">
                        <name>outbound_services</name>
                        <type><list><string/></list></type>
                        <description>A comma-separated list of services permitted to leave the zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>admin_parent</name>
                        <type><string/></type>
                        <description>Name of the administrative parent zone. If set, the current zone
                         inherits the lists of permitted inbound and outbound
                         services from its administrative parent zone.</description>
                      </argument>
                      <argument maturity="stable">
                        <name>umbrella</name>
                        <type><boolean/></type>
                        <description>
                        Enable this option for umbrella zones. Umbrella zones do
                        not inherit the security attributes (list of permitted
                        services) of their administrative parents. </description>
                      </argument>
                    </arguments>
                  </metainfo>
                </method>
    """
    self.name = name
    self.admin_children = []
    self.umbrella = umbrella
    self.inbound_services = set()
    self.outbound_services = set()

    if admin_parent is not None:
      self.admin_parent = self.zones[admin_parent]
    else:
      self.admin_parent = None

    self.zones[name] = self

    if isinstance(addrs, basestring):
      addrs = (addrs, )

    self.subnets = map(Subnet.create, addrs)

    if inbound_services is not None:
      self.inbound_services = set(inbound_services)
    if outbound_services is not None:
      self.outbound_services = set(outbound_services)

    map(lambda i: log(None, CORE_DEBUG, 5, "Outbound service; zone='%s', service='%s'", (self.name, i)), self.outbound_services)
    map(lambda i: log(None, CORE_DEBUG, 5, "Inbound service; zone='%s', service='%s'", (self.name, i)), self.inbound_services)

    zone = reduce(lambda res, subnet: res or self.zone_subnet_tree.search_exact(packed=subnet.addr_packed()), self.subnets, None)
    if zone is not None:
      raise ZoneException, "Zone with duplicate IP range; zone=%s" % zone.data["zone"]

    for subnet in self.subnets:
      self.zone_subnet_tree.add(packed=subnet.addr_packed(), masklen=subnet.netmask_bits()).data["zone"] = self

  def __str__(self):
    """
    <method internal="yes"/>
    """
    return "Zone(%s)" % self.name

  def isInboundServicePermitted(self, service):
    """
    <method internal="yes"/>
    """
    if service.name in self.inbound_services or "*" in self.inbound_services:
      return ZV_ACCEPT
    elif self.admin_parent and not self.umbrella:
      return self.admin_parent.isInboundServicePermitted(service)
    return ZV_REJECT

  def isOutboundServicePermitted(self, service):
    """
    <method internal="yes"/>
    """
    if service.name in self.outbound_services or "*" in self.outbound_services:
      return ZV_ACCEPT
    elif self.admin_parent and not self.umbrella:
      return self.admin_parent.isOutboundServicePermitted(service)
    return ZV_REJECT

  def getName(self):
    """
    <method internal="yes"/>
    """
    return self.name

  def buildKZorpMessage(self):
    """
    <method internal="yes"/>
    """
    messages = []
    flags = 0
    if self.umbrella:
            flags = kznf.kznfnetlink.KZF_ZONE_UMBRELLA

    parent_name = None
    if self.admin_parent:
            parent_name = self.admin_parent.name

    # Zones with at most one subnet are serialized as is
    if len(self.subnets) == 0:
      messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE,
                       kznf.kznfnetlink.create_add_zone_msg(self.name, flags, uname=self.name, pname=parent_name)))
    elif len(self.subnets) == 1:
      messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE,
                       kznf.kznfnetlink.create_add_zone_msg(self.name, flags,
                                                            self.subnets[0].get_family(),
                                                            self.subnets[0].addr_packed(),
                                                            self.subnets[0].netmask_packed(),
                                                            uname=self.name, pname=parent_name)))
    else:
      # Zones with more than one subnet are exploded: first we send
      # the actual zone without any subnet addresses, then generate a
      # sub-zone for each subnet
      messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE,
                       kznf.kznfnetlink.create_add_zone_msg(self.name, flags, uname=self.name, pname=parent_name)))

      # We send 'subzones' whose parents are the actual zones, and each
      # contains a subnet of the zone These 'subzones' do not have
      # umbrellas, so they inherit the DAC policy of the actual zone
      for index, subnet in enumerate(self.subnets):
        messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE,
                         kznf.kznfnetlink.create_add_zone_msg(self.name, 0,
                                                              subnet.get_family(),
                                                              subnet.addr_packed(),
                                                              subnet.netmask_packed(),
                                                              uname="%s-#%u" % (self.name, index + 1),
                                                              pname=self.name)))

    # Add DAC policy
    for i in self.inbound_services:
      messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE_SVC_IN, kznf.kznfnetlink.create_add_zone_svc_msg(self.name, i)))
    for i in self.outbound_services:
      messages.append((kznf.kznfnetlink.KZNL_MSG_ADD_ZONE_SVC_OUT, kznf.kznfnetlink.create_add_zone_svc_msg(self.name, i)))

    return messages

  @staticmethod
  def lookup(addr):
    """
    <method internal="yes"/>
    """
    if isinstance(addr, InetSubnet):
      addr_packed = addr.addr_packed()()
    elif isinstance(addr, Inet6Subnet):
      addr_packed = addr.addr_packed()()
    else:
      addr_packed = addr.pack()

    rnode = Zone.zone_subnet_tree.search_best(packed = addr_packed)
    if rnode:
      return rnode.data["zone"]
    else:
      return None

  @staticmethod
  def lookup_by_name(name):
    if name in Zone.zones:
      return Zone.zones[name]

    return None

InetZone = Zone
