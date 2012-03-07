import socket
import struct
import ctypes

class NfRootException(Exception):
    def __init__(self, detail):
        self.what = ''
        self.detail = detail

    def __str__(self):
        return '%s: %s' % (self.what, self.detail)

class NfnetlinkException(NfRootException):
    def __init__(self, detail):
        super(NfnetlinkException, self).__init__(detail)
        self.what = 'nfnetlink error'

class NfnetlinkAttributeException(NfRootException):
    def __init__(self, detail):
        super(NfnetlinkAttributeException, self).__init__(detail)
        self.what = 'nfnetlink attribute error'
        self.detail = detail

class PacketException(NfRootException):
    def __init__(self, detail):
        super(PacketException, self).__init__(detail)
        self.what = 'packet parsing error'

# netlink message type values
NLM_F_REQUEST = 1
NLM_F_MULTI   = 2
NLM_F_ACK     = 4
NLM_F_ECHO    = 8

# modifiers to GET request
NLM_F_ROOT   = 0x100
NLM_F_MATCH  = 0x200
NLM_F_ATOMIC = 0x400
NLM_F_DUMP   = NLM_F_ROOT | NLM_F_MATCH

# modifiers to NEW request
NLM_F_REPLACE = 0x100
NLM_F_EXCL    = 0x200
NLM_F_CREATE  = 0x400
NLM_F_APPEND  = 0x800

# netlink generic message types
NLMSG_NOOP    = 1
NLMSG_ERROR   = 2
NLMSG_DONE    = 3
NLMSG_OVERRUN = 4

# nfnetlink subsystems
NFNL_SUBSYS_NONE          = 0
NFNL_SUBSYS_CTNETLINK     = 1
NFNL_SUBSYS_CTNETLINK_EXP = 2
NFNL_SUBSYS_QUEUE         = 3
NFNL_SUBSYS_ULOG          = 4
NFNL_SUBSYS_CTHELPER      = 5
NFNL_SUBSYS_KZORP         = 6

NETLINK_NETFILTER         = 12

NLA_F_NESTED          = (1 << 15)
NLA_F_NET_BYTEORDER   = (1 << 14)
NLA_TYPE_MASK         = ctypes.c_uint(~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)).value

# attribute alignment
NFA_ALIGNTO = 4

MAX_NLMSGSIZE = 65535

def nfa_align(len):
        return (len + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1)

class NfnetlinkAttribute(object):
        def __init__(self, type, data = None, attrs = None):
                if data == None and attrs == None:
                        raise NfnetlinkAttributeException, "either data or attr must be set"
                if data != None and attrs != None:
                        raise NfnetlinkAttributeException, "only data or attr should be set"
                self.type = type
                self.nested = attrs != None
		if self.nested:
			self.type |= NLA_F_NESTED
                self.__buf = data
                self.__attrs = attrs

	def __eq__(self, other):
		if self.type != other.type:
			return False
		if self.nested != other.nested:
			return False

		if self.nested:
			res = self.__attrs == other.__attrs
		else:
			res = str(self.__buf) == str(other.__buf)
		return res

        def get_data(self):
                if self.nested == True:
                        raise NfnetlinkAttributeException, "get data of nested attribute"

                return self.__buf

        def get_attributes(self):
                if self.nested == False:
                        raise NfnetlinkAttributeException, "get nested attribute of normal attribute"

                return self.__attrs

        def dump(self):
                if self.nested == True:
                        data = ""
                        for attr in self.__attrs:
                                data += attr.dump()
                else:
                        data = self.__buf

                alen = nfa_align(len(data))
                flen = alen - len(data)
                header = struct.pack('HH', alen + 4, self.type)
                data = "".join((header, data, '\0' * flen))

                return data

        @staticmethod
        def __parse_impl(buf, index):
                attrs = {}
                while index < len(buf):
                        header = buf[index:index + 4]
                        if len(header) < 4:
                                raise PacketException, "message too short to contain an attribute header"
                        (length, type) = struct.unpack('HH', header)
                        if length < 4:
                                raise PacketException, "invalid attribute length specified in attribute header: too short to contain the header itself"
                        data = buf[index + 4:index + length]
                        if len(data) + 4 != length:
                                raise PacketException, "message too short to contain an attribute of the specified size"
                        nla_type = type & ctypes.c_uint(~NLA_TYPE_MASK).value
                        type = type & NLA_TYPE_MASK
                        if nla_type & NLA_F_NESTED:
                                #pdb.set_trace()
                                nested_attrs = NfnetlinkAttribute.__parse_impl(data, 0)
                                attr = NfnetlinkAttribute(type, attrs=nested_attrs.values())
                                index = index + nfa_align(length)
                        else:
                                data = data.ljust(nfa_align(length), chr(0))
                                attr = NfnetlinkAttribute(type, data=data)
                                index = index + nfa_align(length)
                        if attrs.has_key(type):
                                raise PacketException, "message contains multiple attributes of the same type"
                        attrs[type] = attr
                return attrs

        @staticmethod
        def parse(buf):
                return NfnetlinkAttribute.__parse_impl(buf, 0)

        @staticmethod
        def create_inet_addr_attr(type, family, address):
                """Create an nfnetlink attribute which stores an IP address.

                Keyword arguments:
                addr -- an IP address in binary format (returned by inet_pton)

                """
                if family != socket.AF_INET and family != socket.AF_INET6:
                        raise NfnetlinkException, "protocol family not supported"

                if (family == socket.AF_INET):
                        data = struct.pack('4s',  address)
                else:
                        data = struct.pack('16s',  address)

                return NfnetlinkAttribute(type, data)

        def parse_inet_addr_attr(self, family):
               """Parse an nfnetlink attribute which stores an IP address.

               Return list of protocol family and address

               """
               if (family != socket.AF_INET and family != socket.AF_INET6):
                       raise NfnetlinkException, "protocol family not supported"

               if family == socket.AF_INET:
                       data = struct.unpack('4s', self.__buf[0:4])
               else:
                       data = struct.unpack('16s', self.__buf[0:16])

               return data[0]

        @staticmethod
        def create_inet_subnet_attr(type, family, address, mask):
                """Create an nfnetlink attribute which stores an IP subnet.

                Keyword arguments:
                addr -- an IP address in binary format (returned by inet_pton)
                mask -- an IP netmask in binary format (returned by inet_pton)

                """
                if family != socket.AF_INET and family != socket.AF_INET6:
                        raise NfnetlinkException, "protocol family not supported"

                #pdb.set_trace()
                if (family == socket.AF_INET):
                        data = struct.pack('4s',  address) + struct.pack('4s',  mask)
                else:
                        data = struct.pack('16s',  address) + struct.pack('16s',  mask)

                return NfnetlinkAttribute(type, data)

        def parse_inet_subnet_attr(self, family):
                """Parse an nfnetlink attribute which stores an IP subnet.
 
                Return list of protocol family, address and netmask
 
                """
                if family != socket.AF_INET and family != socket.AF_INET6:
                        raise NfnetlinkException, "protocol family not supported"

                if family == socket.AF_INET:
                        data = struct.unpack('4s', self.__buf[0:4]) + struct.unpack('4s', self.__buf[4:8])
                else:
                        data = struct.unpack('16s', self.__buf[0:16]) + struct.unpack('16s', self.__buf[16:32])

                return data

class NfnetlinkMessage(object):

        def __init__(self, family, version, res_id, data="", parent = None):
                self.family = family
                self.version = version
                self.res_id = res_id
                self.__buf = data
                self.__attrs = None

        def __eq__(self, other):
                return self.get_attributes() == other.get_attributes()

        def get_attributes(self):
                return NfnetlinkAttribute.parse(self.__buf)

        def append_attribute(self, attribute):
                self.__buf = "".join((self.__buf, attribute.dump()))

        def dump(self):
                header = struct.pack('BBH', self.family, self.version, self.res_id)
                return "".join((header, self.__buf))

class NetlinkMessage(object):

        def __init__(self, type, flags, seq, pid, data):
                self.type = type
                self.flags = flags
                self.seq = seq
                self.pid = pid
                self.__buf = data

        def get_nfmessage(self):
                if len(self.__buf) < 4:
                        raise PacketException, "message too short to contain an nfnetlink header"
                (family, version, res_id) = struct.unpack('BBH', self.__buf[:4])
                return NfnetlinkMessage(family, version, res_id, self.__buf[4:], self)

        def get_errorcode(self):
                # the error message consists of an error code plus the header of the
                # message triggering the error
                if len(self.__buf) < (4 + 16):
                        raise PacketException, "message too short to contain an error header"
                (error,) = struct.unpack('i', self.__buf[:4])
                return error

        def set_nfmessage(self, nfmessage):
                self.child = nfmessage
                self.__buf = nfmessage.dump()

        def dump(self):
                if not self.child:
                        raise PacketException, "cannot dump an incomplete netlink message"
                nfmsg = self.child.dump()
                # length of generic netlink message header is 16 bytes
                length = len(nfmsg) + 16
                header = struct.pack('IHHII', length, self.type, self.flags, self.seq, self.pid)
                return "".join((header, nfmsg))

class PacketIn(object):

        def __init__(self, s):
                self.set_contents(s)

        def dump(self):
                return self.__buf

        def set_contents(self, s):
                self.__buf = s

        def get_messages(self):
                i = 0
                messages = []
                while i < len(self.__buf):
                        header = self.__buf[i:i + 16]
                        i = i + 16
                        if len(header) < 16:
                                raise PacketException, "packet too short to contain a netlink message header"
                        (length, type, flags, seq, pid) = struct.unpack('IHHII', header)
                        if (length < 16):
                                raise PacketException, "invalid length specified in netlink header: too short to contain a netlink message header"
                        length = length - 16
                        data = self.__buf[i:i + length]
                        i = i + length

                        # length check
                        if len(data) < length:
                                raise PacketException, "packet too short to contain a message of the specified size"
                        messages.append(NetlinkMessage(type, flags, seq, pid, data))
                return messages

class Subsystem(object):

        def __init__(self, id):
                self.id = id
                self.handle = None
                self.seq = 0
                self.__callbacks = {}

        def next_seq(self):
                s = self.seq
                self.seq = self.seq + 1
                return s

        def register_callback(self, type, callback):
                if not callable(callback):
                        raise ValueError, "nfnetlink subsystem callback must be callable"
                self.__callbacks[type] = callback

        def unregister_callback(self, type):
                if self.__callbacks.has_key(type):
                        del self.__callbacks[type]

        def dispatch(self, message):
                m_type = message.type & 255
                if self.__callbacks.has_key(m_type):
                        self.__callbacks[m_type](message)

class Handle(object):
        def __init__(self):
                # subsystems
                self.__subsystems = {}
                # socket
                fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
                fd.bind((0, 0))
                self.fd = fd
                # local address
                self.local = fd.getsockname()

        def close(self):
                self.fd.close()

        def register_subsystem(self, s):
                if self.__subsystems.has_key(s.id):
                        raise NfnetlinkException, "subsystem already registered"
                self.__subsystems[s.id] = s
                s.handle = self

        def unregister_subsystem(self, s):
                if self.__subsystems.has_key(s.id):
                        self.__subsystems[s.id].handle = None
                        del self.__subsystems[s.id]
                else:
                        raise NfnetlinkException, "subsystem has not been registered"

        def process_packet(self, packet):
                messages = packet.get_messages()
                for m in messages:
                        self.dispatch(m)

        def dispatch(self, message):
                m_subsys = message.type >> 8
                m_type = message.type & 0xff
                if self.__subsystems.has_key(m_subsys):
                        self.__subsystems[m_subsys].dispatch(message)

        def create_message(self, subsys, type, flags = 0, data = ''):
                if not self.__subsystems.has_key(subsys):
                        raise NfnetlinkException, "no such subsystem registered"
                s = self.__subsystems[subsys]
                return NetlinkMessage((subsys << 8) + type, flags, s.next_seq(), self.local[0], data)

        def send(self, message, to):
                self.fd.sendto(message.dump(), to)

        def listen(self, handler):
                quit = False
                status = 0
                while not quit:
                        (answer, peer) = self.fd.recvfrom(MAX_NLMSGSIZE)
                        packet = PacketIn(answer)
                        messages = packet.get_messages()
                        for m in messages:
                                # check for special messages
                                if m.type == NLMSG_DONE:
                                        quit = True
                                        break
                                if m.type == NLMSG_ERROR:
                                        quit = True
                                        status = m.get_errorcode()
                                        break
                                # call handler
                                if callable(handler):
                                        handler(m)
                return status

        def talk(self, message, to, handler):
                self.fd.sendto(message.dump(), to)
                return self.listen(handler)

