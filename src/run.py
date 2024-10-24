#!python3

import sys
import os.path
import errno
import pyroute2
import pyroute2.ipdb
import signal
from . import config
from .dispatcher import Dispatcher
from threading import Event

import logging
logging.basicConfig(level=logging.INFO)


def service_comcast(cfg: config.ComcastConfig, state_dir: str) -> Dispatcher:
    from . import dispatcher_comcast
    return dispatcher_comcast.Dispatcher(
        wan_interface=cfg.wan_interface,
        lan_interface=cfg.lan_interface,
        state_dir=state_dir
    )


def service_centurylink(cfg: config.CenturyLinkConfig, state_dir: str) -> Dispatcher:
    from . import dispatcher_centurylink
    return dispatcher_centurylink.Dispatcher(
        ip6rd_subnet=cfg.ip6rd_subnet,
        ip6rd_gateway=cfg.ip6rd_gateway,
        link_interface=cfg.link_interface,
        ppp_peer=cfg.ppp_peer,
        lan_interface=cfg.lan_interface,
        wan_v4_interface=cfg.wan_v4_interface,
        wan_v6_interface=cfg.wan_v6_interface,
        state_dir=state_dir
    )


def service():
    state_dir = sys.argv[1]

    logging.info('Running as a service')

    cfg = config.Config.from_file(open(os.path.join(state_dir, 'config.txt'), 'rt'))
    if cfg.mode == cfg.MODE_COMCAST:
        dispatcher = service_comcast(cfg.comcast, state_dir)
    elif cfg.mode == cfg.MODE_CENTURYLINK:
        dispatcher = service_centurylink(cfg.centurylink, state_dir)
    else:
        return errno.EINVAL

    with pyroute2.IPRoute() as netlink_route:
        for iface in netlink_route.get_links():
            if iface.get_attr('IFLA_OPERSTATE') == 'UP':
                dispatcher.add_interface(iface['index'], iface.get_attr('IFLA_IFNAME'))

    def ipdb_callback(ipdb, msg, action):
        logging.debug('NETLINK event: %s, %s' % (repr(msg), action))

        if action == 'RTM_NEWLINK':
            ifindex = msg['index']
            try:
                interface = ipdb.interfaces[ifindex]
            except KeyError:
                logging.warning('NETLINK warning. Interface does not exist, skipping')
                return
            ifname = interface['ifname']
            if msg.get_attr('IFLA_OPERSTATE') == 'UP':
                dispatcher.add_interface(ifindex, ifname)
            else:
                dispatcher.remove_interface(ifindex, ifname)
            return

        if action == 'RTM_DELLINK':
            ifindex = msg['index']
            try:
                interface = ipdb.interfaces[ifindex]
            except KeyError:
                logging.warning('NETLINK warning. Interface does not exist, skipping')
                return
            ifname = interface['ifname']
            dispatcher.remove_interface(ifindex, ifname)
            return

    global_ipdb = pyroute2.IPDB()
    ipdb_cb = global_ipdb.register_callback(ipdb_callback)

    termination_event = Event()

    def signal_handler(signum, frame):
        logging.warning('Received signal %s. Exiting' % signum)
        termination_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)

    while True:
        try:
            if termination_event.wait(60):
                logging.info('Event triggered. Shutting down ...')
                break
            dispatcher.status()
        except (InterruptedError, KeyboardInterrupt):
            logging.info('Interrupt received. Shutting down ...')
            break

    global_ipdb.unregister_callback(ipdb_cb)
    global_ipdb.release()
    dispatcher.shutdown()


if __name__ == '__main__':
    exit(service())
