############################################################################
##
##
############################################################################

import Globals
import random, time, socket, errno
import kznf.kznfnetlink
from Zorp import *
from Zone import Zone

def netlinkmsg_handler(msg):
        pass

def openHandle():
        h = kznf.nfnetlink.Handle()
        s = kznf.nfnetlink.Subsystem(kznf.nfnetlink.NFNL_SUBSYS_KZORP)
        h.register_subsystem(s)
        return h

def exchangeMessage(h, msg, payload):
        m = h.create_message(kznf.nfnetlink.NFNL_SUBSYS_KZORP, msg, kznf.nfnetlink.NLM_F_REQUEST | kznf.nfnetlink.NLM_F_ACK)
        m.set_nfmessage(payload)
        result = h.talk(m, (0, 0), netlinkmsg_handler)
        if result != 0:
                raise kznf.nfnetlink.NfnetlinkException, "Error while talking to kernel; result='%d'" % (result)

def exchangeMessages(h, messages):
        for (msg, payload) in messages:
                exchangeMessage(h, msg, payload)

def startTransaction(h, instance_name):
        tries = 7
        wait = 0.1
        while tries > 0:
                try:
                        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_START, \
                                        kznf.kznfnetlink.create_start_msg(instance_name))
                except socket.error, e:
                        if e[0] == errno.ECONNREFUSED:
                                raise
                except:
                        tries = tries - 1
                        if tries == 0:
                                raise
                        wait = 2 * wait
                        time.sleep(wait * random.random())
                        continue

                break

def commitTransaction(h):
        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_COMMIT, \
                        kznf.kznfnetlink.create_commit_msg())

def downloadServices(h):
        # download services
        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_SERVICE, \
                        kznf.kznfnetlink.create_flush_msg())

        for service in Globals.services.values():
                messages = service.buildKZorpMessage()
                exchangeMessages(h, messages)

def downloadZones(h):
        def walkZones(messages, zone, children):
                messages.extend(zone.buildKZorpMessage())
                for child in children.get(zone.name, []):
                        walkZones(messages, child, children)

        # download zones
        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_ZONE, \
                        kznf.kznfnetlink.create_flush_msg())

        # build children hash
        children = {}
        for zone in Zone.zones.values():
                if zone.admin_parent:
                        children.setdefault(zone.admin_parent.name, []).append(zone)

        for zone in Zone.zones.values():
                if not zone.admin_parent:
                        # tree root
                        messages = []
                        walkZones(messages, zone, children)
                        exchangeMessages(h, messages)

def downloadDispatchers(h):
        exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_DISPATCHER, \
                        kznf.kznfnetlink.create_flush_msg())

        for dispatch in Globals.dispatches:
                try:
                        messages = dispatch.buildKZorpMessage()
                        exchangeMessages(h, messages)
                except:
                        log(None, CORE_ERROR, 0, "Error occured during Dispatcher upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
                        raise


def downloadBindAddresses(h):
        for dispatch in Globals.dispatches:
                try:
                        messages = dispatch.buildKZorpBindMessage()
                        exchangeMessages(h, messages)
                except:
                        log(None, CORE_ERROR, 0, "Error occured during bind address upload to KZorp; dispatcher='%s', error='%s'" % (dispatch.bindto[0].format(), sys.exc_value))
                        raise

def downloadKZorpConfig(instance_name, is_master):

        random.seed()
        h = openHandle()

        # start transaction
        startTransaction(h, instance_name)

        try:
                if is_master:
                        downloadServices(h)
                        downloadZones(h)
                        downloadDispatchers(h)
                downloadBindAddresses(h)
                commitTransaction(h)
        except:
                h.close()
                raise

        Globals.kzorp_netlink_handle = h

def flushKZorpConfig(instance_name):

        random.seed()

        h = getattr(Globals, "kzorp_netlink_handle", None)
        if not h:
                h = openHandle()

        # flush dispatchers and services
        startTransaction(h, instance_name)
        try:
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_DISPATCHER, \
                                kznf.kznfnetlink.create_flush_msg())
                exchangeMessage(h, kznf.kznfnetlink.KZNL_MSG_FLUSH_SERVICE, \
                                kznf.kznfnetlink.create_flush_msg())
                commitTransaction(h)
        except:
                h.close()
                raise

        h.close()
