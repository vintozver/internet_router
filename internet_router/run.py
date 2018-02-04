#!python3

import sys
import os
import os.path
import pyroute2
import pyroute2.ipdb
import subprocess
import signal
# from . import service
from threading import Thread, Event, Lock

import logging
logging.basicConfig(level=logging.INFO)


class Dispatcher(object):
    def __init__(self, wan_interface, lan_interface, state_dir):
        self.wan_interface = wan_interface
        self.lan_interface = lan_interface
        self.state_dir = state_dir

        self.shutdown_event = Event()

        self.lock = Lock()
        self.wan_dhcpv6_client_process = None  # DHCPv6 client on the WAN interface (process)
        self.wan_dhcpv6_client_thread_stdout = None  # DHCPv6 client on the WAN interface (stdout thread poll)
        self.wan_dhcpv6_client_thread_stderr = None  # DHCPv6 client on the WAN interface (stderr thread poll)
        self.lan_radvd_process = None  # radvd on the LAN interface (process)
        self.lan_radvd_thread_stdout = None  # radvd on the LAN interface (stdout thread poll)
        self.wan_dhcpv6_client_thread_stderr = None  # radvd on the LAN interface (stderr thread poll)

    def add_interface(self, index, name):
        logging.info('Adding interface to the topology %d:%s' % (index, name))

        if name == self.wan_interface:
            self.start_wan_dhcpv6_client()
        elif name == self.lan_interface:
            self.start_lan_radvd()
        else:
            pass

    def remove_interface(self, index, name):
        logging.info('Trying to remove interface %d:%s' % (index, name))

        if name == self.wan_interface:
            self.stop_wan_dhcpv6_client()
        elif name == self.lan_interface:
            self.stop_lan_radvd()

    def start_wan_dhcpv6_client(self):
        if self.wan_dhcpv6_client_process is not None:
            return

        self.wan_dhcpv6_client_process = subprocess.Popen(
            ['dhclient', '--no-pid', '-d', '-v', '-6', '-P', '-N', '-sf', '/bin/true', self.wan_interface],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.wan_dhcpv6_client_thread_stdout = Thread(
            target=self.std_stream_dup,
            args=('WAN DHCPv6 client stdout: ', self.wan_dhcpv6_client_process.stdout),
            name='WAN_DHCPv6_client_stdout',
        )
        self.wan_dhcpv6_client_thread_stdout.start()
        self.wan_dhcpv6_client_thread_stderr = Thread(
            target=self.std_stream_dup,
            args=('WAN DHCPv6 client stderr: ', self.wan_dhcpv6_client_process.stderr),
            name='WAN_DHCPv6_client_stderr',
        )
        self.wan_dhcpv6_client_thread_stderr.start()

    def stop_wan_dhcpv6_client(self):
        if self.wan_dhcpv6_client_process is None:
            return

        self.wan_dhcpv6_client_process.send_signal(signal.SIGTERM)
        self.wan_dhcpv6_client_thread_stdout.join()
        self.wan_dhcpv6_client_thread_stdout = None
        self.wan_dhcpv6_client_thread_stderr.join()
        self.wan_dhcpv6_client_thread_stderr = None
        self.wan_dhcpv6_client_process.wait()
        self.wan_dhcpv6_client_process = None

    def start_lan_radvd(self):
        if self.lan_radvd_process is not None:
            return

        radvd_conf_filename = os.path.join(self.state_dir, 'radvd.conf')
        open(radvd_conf_filename, 'w').write('\
interface %(iface)s {\n\
};\n\
' % {
            'iface': self.lan_interface
        })

        self.lan_radvd_process = subprocess.Popen(
            [
                'radvd', '--nodaemon',
                '--logmethod', 'stderr', '--debug', '1',
                '--config=%s' % radvd_conf_filename,
                '--pidfile=%s' % os.path.join(self.state_dir, 'radvd.pid'),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.lan_radvd_thread_stdout = Thread(
            target=self.std_stream_dup,
            args=('LAN radvd stdout: ', self.lan_radvd_process.stdout),
            name='LAN_radvd_stdout',
        )
        self.lan_radvd_thread_stdout.start()
        self.lan_radvd_thread_stderr = Thread(
            target=self.std_stream_dup,
            args=('LAN radvd stderr: ', self.lan_radvd_process.stderr),
            name='LAN_radvd_stderr',
        )
        self.lan_radvd_thread_stderr.start()

    def stop_lan_radvd(self):
        if self.lan_radvd_process is None:
            return

        self.lan_radvd_process.send_signal(signal.SIGTERM)
        self.lan_radvd_thread_stdout.join()
        self.lan_radvd_thread_stdout = None
        self.lan_radvd_thread_stderr.join()
        self.lan_radvd_thread_stderr = None
        self.lan_radvd_process.wait()
        self.lan_radvd_process = None

    def shutdown(self):
        self.stop_wan_dhcpv6_client()
        self.stop_lan_radvd()

    @staticmethod
    def std_stream_dup(prefix, process_stream):  # polling thread
        system_stdout = sys.stdout
        while True:
            try:
                line = process_stream.readline()
            except OSError:
                break
            if not line:
                break
            system_stdout.write(prefix)
            system_stdout.write(line.decode('utf-8'))


def service():
    logging.info('Running as a service')

    wan_interface = sys.argv[1]
    lan_interface = sys.argv[2]
    state_dir = sys.argv[3]

    logging.info('Adding current interfaces')
    dispatcher = Dispatcher(wan_interface, lan_interface, state_dir)
    with pyroute2.IPRoute() as netlink_route:
        for interface in netlink_route.get_links():
            dispatcher.add_interface(interface['index'], dict(interface['attrs'])['IFLA_IFNAME'])

    def ipdb_callback(ipdb, msg, action):
        logging.debug('NETLINK event: %s, %s' % (repr(msg), action))

        if action == 'RTM_NEWLINK':
            ifindex = msg['index']
            ifname = ipdb.interfaces[ifindex]['ifname']
            if msg.get_attr('IFLA_OPERSTATE') == 'UP':
                dispatcher.add_interface(ifindex, ifname)
            else:
                dispatcher.remove_interface(ifindex, ifname)
            return

        if action == 'RTM_DELLINK':
            ifindex = msg['index']
            ifname = ipdb.interfaces[ifindex]['ifname']
            dispatcher.remove_interface(ifindex, ifname)
            return

    ipdb = pyroute2.IPDB()
    ipdb_cb = ipdb.register_callback(ipdb_callback)

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
            logging.info('Still working ...')
        except (InterruptedError, KeyboardInterrupt):
            logging.info('Interrupt received. Shutting down ...')
            break

    ipdb.unregister_callback(ipdb_cb)
    ipdb.release()
    dispatcher.shutdown()


def dhcp_script():
    logging.info('Running as a dhcp script')


if __name__ == '__main__':
    exit(service())