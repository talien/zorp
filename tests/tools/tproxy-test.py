#!/usr/bin/python
import os, sys, socket, traceback, time, getopt, subprocess

# global params
zero_ip4 = '0.0.0.0'
zero_ip6 = '::'

#Host used as a proxy (needs passwordless root ssh access)
proxy_ip4 = '10.30.8.130'
proxy_ip6 = 'dead:1::2'
proxy_port = 50080

#Nonexistent addres, we just need a host route on the client through the proxy for this address
target_ip4 = '5.6.7.8'
target_ip6 = 'dead:2::1'
target_port = 80

def connect_agent():
    from Agent import TestAgentStub
    ssh_options="-o UserKnownHostsFile=/dev/null -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=no -o LogLevel=ERROR"

    if os.system("rsync -e 'ssh %s' -a Agent root@%s:" % (ssh_options, proxy_ip4)) != 0:
        raise Exception, "Error syncing agent"
    return TestAgentStub.TestAgentStub("ssh %s root@%s Agent/test-agent.py" % (ssh_options, proxy_ip4,), 'tproxy')


def testcases():
    # IPv4

    tproxy_rule_only_ipv4_sockets = (
    # sockets that are irrelevant to our redirection, their existance should not
    # cause any connections to be established
     (
      # irrelevant, because of port number
      (zero_ip4, 5678, True), (proxy_ip4, 5678),
      # redirect should override even those listeners that are bound explicitly
      (zero_ip4, 80, True), (proxy_ip4, 80), (target_ip4, 80),
      (target_ip4, 50080, True)
     ),
    # sockets that should match, in reverse-preference order, e.g. the
    # connection should always establish to the last one
     ((zero_ip4, 50080, True), (proxy_ip4, 50080))
    )

    tproxy_plus_socket_rules_ipv4_sockets = (
    # sockets that are irrelevant to our redirection, their existance should not
    # cause any connections to be established
     (
      # irrelevant, because of port number
      (zero_ip4, 5678, True), (proxy_ip4, 5678),
      # redirect should override even those listeners that are bound explicitly
      (zero_ip4, 80, True), (proxy_ip4, 80),
      (target_ip4, 50080, True)
     ),
    # sockets that should match, in reverse-preference order, e.g. the
    # connection should always establish to the last one
     (
      # because of the socket match, we get a connection on the target address
      # this is when the proxy opens a dynamic listener
      (target_ip4, 80, True),
      (zero_ip4, 50080, True), (proxy_ip4, 50080)
     )
    )

    # ipv6

    tproxy_rule_only_ipv6_sockets = (
    # sockets that are irrelevant to our redirection, their existance should not
    # cause any connections to be established
     (
      # irrelevant, because of port number
      (zero_ip6, 5678, True), (proxy_ip6, 5678),
      # redirect should override even those listeners that are bound explicitly
      (zero_ip6, 80, True), (proxy_ip6, 80), (target_ip6, 80),
      (target_ip6, 50080, True)
     ),
    # sockets that should match, in reverse-preference order, e.g. the
    # connection should always establish to the last one
     ((zero_ip6, 50080, True), (proxy_ip6, 50080))
    )

    tproxy_plus_socket_rules_ipv6_sockets = (
    # sockets that are irrelevant to our redirection, their existance should not
    # cause any connections to be established
     (
      # irrelevant, because of port number
      (zero_ip6, 5678, True), (proxy_ip6, 5678),
      # redirect should override even those listeners that are bound explicitly
      (zero_ip6, 80, True), (proxy_ip6, 80),
      (target_ip6, 50080, True)
     ),
    # sockets that should match, in reverse-preference order, e.g. the
    # connection should always establish to the last one
     (
      # because of the socket match, we get a connection on the target address
      # this is when the proxy opens a dynamic listener
      (target_ip6, 80, True),
      (zero_ip6, 50080, True), (proxy_ip6, 50080)
     )
    )

    tproxy_sockets = {
      (socket.AF_INET, False): tproxy_rule_only_ipv4_sockets,
      (socket.AF_INET, True): tproxy_plus_socket_rules_ipv4_sockets,
      (socket.AF_INET6, False): tproxy_rule_only_ipv6_sockets,
      (socket.AF_INET6, True): tproxy_plus_socket_rules_ipv6_sockets,
    }

    return tproxy_sockets

def load_iptables(a, family=socket.AF_INET, socket_type=socket.SOCK_STREAM, socket_rule=False, explicit_on_ip=False):

    header = """
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p icmpv6 -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -m mark --mark 0x80000000/0x80000000 -j ACCEPT
-A INPUT -j LOG --log-prefix "PF/INPUT: DROP "
-A INPUT -j DROP
-A FORWARD -j LOG --log-prefix "PF/FORWARD: DROP "
-A FORWARD -j DROP
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DIVERT - [0:0]
"""
    subst = {}

    if socket_type == socket.SOCK_STREAM:
        subst['proto'] = 'tcp'
    else:
        subst['proto'] = 'udp'

    subst['target_port'] = target_port
    subst['proxy_port'] = proxy_port
    if family == socket.AF_INET:
        subst['proxy_ip'] = proxy_ip4
    else:
        subst['proxy_ip'] = proxy_ip6
    rules = header
    if socket_rule:
        rules += """-A PREROUTING -m socket --transparent -j DIVERT\n"""

    if explicit_on_ip:
        rules += """
-A PREROUTING -p %(proto)s -m %(proto)s --dport %(target_port)d -j TPROXY --on-port %(proxy_port)d --on-ip %(proxy_ip)s --tproxy-mark 0x80000000/0x80000000""" % subst
    else:
        rules += """
-A PREROUTING -p %(proto)s -m %(proto)s --dport %(target_port)d -j TPROXY --on-port %(proxy_port)d --tproxy-mark 0x80000000/0x80000000""" % subst

    rules += """
-A DIVERT -j MARK --set-xmark 0x80000000/0x80000000
-A DIVERT -j ACCEPT
COMMIT
""" % subst

    print rules
    a.iptables_restore(family, rules)

def open_listener(a, family, socket_type, addr):
    s = a.socket(family, socket_type)
    s.bind(addr[0:2])
    if socket_type == socket.SOCK_STREAM:
        s.listen(255)

    return s

def run_sockets(a, family=socket.AF_INET, socket_type=socket.SOCK_STREAM, socket_rule=False, explicit_on_ip=False, sockets=()):

    skip_irrelevant = False
    load_iptables(a, family, socket_type, socket_rule, explicit_on_ip)

    open_sockets = []

    relevant = False
    success = True
    for addrs in sockets:
        for addr in addrs:

            print "### Opening listener %s" % (addr,)

            l_sock = open_listener(a, family, socket_type, addr)
            open_sockets.append(l_sock)

            c_sock = socket.socket(family, socket_type)
            c_sock.settimeout(2)

            if family == socket.AF_INET:
                target_ip = target_ip4
            elif family == socket.AF_INET6:
                target_ip = target_ip6
            else:
                raise Exception, "Unsupported protocol family; family='%d'" % family

            print "### Connecting to %s" % ((target_ip, target_port),)
            try:
                if relevant or not skip_irrelevant:
                    c_sock.connect((target_ip, target_port))
                    if socket_type == socket.SOCK_DGRAM:
                        c_sock.send("almafa")
                    print "### Connected to %s" % ((target_ip, target_port),)
                else:
                    print "### Skipped connection to %s" % ((target_ip, target_port),)
                    c_sock = None
            except socket.error:
                # connection failed
                c_sock = None
                print "### Connection failed to %s" % ((target_ip, target_port),)

            if relevant or not skip_irrelevant:
                print "### Waiting for connection %s" % (addr,)
                (r, w, x) = a.select(open_sockets, [], [], timeout=2)
            else:
                (r, w, x) = ([], [], [])

            if socket_type == socket.SOCK_DGRAM and (len(r) + len(w) + len(x)) == 0:
                print "### Datagram read failed on %s" % (addr,)
                c_sock = None

            if socket_type == socket.SOCK_STREAM and c_sock != None and (len(r) + len(w) + len(x)) != 1:
                print r, w, x
                print "FAILED: connected and select returned no connection?"
                success = False
            elif c_sock == None:
                # timed out
                if not relevant:
                    print "PASSED: %s, didn't get a connection on irrelevant address" % (addr,)
                else:
                    print "FAILED: %s, didn't get a connection but we should have" % (addr,)
                    success = False
            else:
                if len(r) != 1:
                    print "FAILED: uhh, we got a connection on multiple fds?"
                    success = False
                else:
                    if not relevant:
                        print "FAILED: %s, we got a connection but we shouldn't have" % (addr,)
                        success = False
                    else:
                        if r[0] == l_sock:
                            print "PASSED: %s, we got a connection as we deserved" % (addr,)
                            if socket_type == socket.SOCK_STREAM:
                                a_sock = l_sock.accept()
                        else:
                            print "FAILED: %s, we got the connection on the wrong listener" % (addr,)
                            success = False
            if len(addr) == 3:

                # we close the socket if it refers to the zero address as
                # otherwise we'd have a bind conflict, as the upcoming bind
                # address will contain a more specific version of this
                # listener
                l_sock = None
                open_sockets = open_sockets[:-1]
            r, w, x = ([], [], [])
        relevant = True
    return success

def run_testcases(a, all_sockets):
    result = True
    for family in (socket.AF_INET, socket.AF_INET6):
        for socket_type in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            for socket_rule in (False, True):
                for explicit_on_ip in (False, True):
                    if not run_sockets(a, family, socket_type, socket_rule, explicit_on_ip, all_sockets[(family, socket_rule)]):
                        result = False

    print "========================="

    if result:
        print "All tests PASSED"
    else:
        print "Some tests FAILED"

    return result
# testcases
#   TPROXY rule only, no "socket" match
#      80 -> 50080 redirection rule
#           TCP listener on redirect-ip:50080, connection establishes
#           TCP listener on redirect-ip:80, connection does not establish
#           TCP listener on redirect-ip:80 & redirect-ip:50080, connection goes to the latter
#           TCP listener on 0.0.0.0:50080, connection establishes
#           TCP listener on 0.0.0.0:50080 & redirect-ip:50080, connection establishes to the latter
#           TCP listener on 0.0.0.0:80, connection does not establish
#           TCP listener on 0.0.0.0:80 & 0.0.0.0:50080, connection goes to the latter
#           TCP listener on target-ip:80, connection does not establish
#           TCP listener on target-ip:50080, connection does not establish


def parse_parameters():
    global proxy_ip4, target_ip4, proxy_ip6, target_ip6

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:t:P:T:", ["proxy=", "target=", "proxy6=", "target6="])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        sys.exit(2)
    output = None
    verbose = False
    for o, a in opts:
        if o in ("-p", "--proxy"):
            proxy_ip4 = a
        elif o in ("-t", "--target"):
            target_ip4 = a
        elif o in ("-P", "--proxy6"):
            proxy_ip6 = a
        elif o in ("-T", "--target6"):
            target_ip6 = a

        else:
            assert False, "unhandled option"

def setup_route():
    retcode = 0

    print "Setting up IPv4 route"

    subprocess.call(["ip", "route" , "del", "%s/32" % target_ip4])
    retcode = retcode + subprocess.call(["ip", "route" , "add", "%s/32" % target_ip4, "via", proxy_ip4])

    print "Setting up IPv6 route"
    subprocess.call(["ip", "-6", "route" , "del", "%s/64" % target_ip6])
    retcode = retcode + subprocess.call(["ip", "-6", "route" , "add", "%s/64" % target_ip6, "via", proxy_ip6])

    return retcode

def main():
    parse_parameters()
    print ("Started with addresses:\n%s\n%s\n%s\n%s\n" % (proxy_ip4, target_ip4, proxy_ip6, target_ip6))

    route_status = setup_route()

    try:
        a = connect_agent()
        #print a.iptables_save(family=socket.AF_INET)
        run_testcases(a, testcases())
        if route_status != 0:
            print ("Route setup was not completely succesful")

        a.quit()
        return 0
    except Exception, e:
        traceback.print_exc()
        print e
        return 1

sys.exit(main())
