import sys
import os
import os.path
import pyroute2
import pyroute2.ipdb
import subprocess
import signal
import typing
import logging
import ipaddress
from .sysctl import SysctlController, SysctlControllerException
from threading import Thread, Event, Lock


class Dispatcher(object):
    def __init__(self, wan_interface, lan_interface, state_dir):
        self.comm_key = open('/dev/urandom', 'rb').read(128)
        open(os.path.join(state_dir, 'comm_key'), 'wb').write(self.comm_key)

        self.sysctl_controller = SysctlController()
        self.wan_interface = wan_interface
        self.lan_interface = lan_interface
        self.state_dir = state_dir

        self.shutdown_event = Event()

        # instance is thread safe
        # lock is necessary, only once interface method may be running at the same time
        self.lock = Lock()

        self.wan_dhclient6_process = None  # DHCPv6 client on the WAN interface (process)
        self.wan_dhclient6_thread_stdout = None  # DHCPv6 client on the WAN interface (stdout thread poll)
        self.wan_dhclient6_thread_stderr = None  # DHCPv6 client on the WAN interface (stderr thread poll)
        self.lan_radvd_process = None  # radvd on the LAN interface (process)
        self.lan_radvd_thread_stdout = None  # radvd on the LAN interface (stdout thread poll)
        self.wan_dhclient6_thread_stderr = None  # radvd on the LAN interface (stderr thread poll)

        self.my_wan_addresses = list()
        self.my_lan_prefixes = dict()

    def add_interface(self, index, name):
        logging.info('Adding interface to the topology %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.start_wan_dhclient6()
            elif name == self.lan_interface:
                self.start_lan_radvd()
            else:
                pass

    def remove_interface(self, index, name):
        logging.info('Trying to remove interface %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.stop_wan_dhclient6()
            elif name == self.lan_interface:
                self.stop_lan_radvd()

    def start_wan_dhclient6(self):
        if self.wan_dhclient6_process is not None:
            return

        logging.info('wan_dhclient6 starting ...')

        logging.debug('wan_dhclient6 starting script server thread')
        from . import wan_dhclient6_server
        self.wan_dhclient6_server = wan_dhclient6_server.CommandServer(
            os.path.join(self.state_dir, 'dhclient6_comm'),
            self.comm_key,
            self.handle_dhclient6_command
        )
        self.wan_dhclient6_server_thread = Thread(target=self._server_thread, args=(self.wan_dhclient6_server, ))
        self.wan_dhclient6_server_thread.start()

        logging.debug('wan_dhclient6 starting dhclient process')
        self.wan_dhclient6_process = subprocess.Popen(
            [
                'dhclient', '--no-pid', '-d', '-v', '-6', '-P', '-N',
                '-sf', os.path.join(self.state_dir, 'dhclient6_script'),
                self.wan_interface
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.wan_dhclient6_thread_stdout = Thread(
            target=self.std_stream_dup,
            args=('WAN DHCPv6 client stdout: ', self.wan_dhclient6_process.stdout),
            name='WAN_dhclient6_stdout',
        )
        self.wan_dhclient6_thread_stdout.start()
        self.wan_dhclient6_thread_stderr = Thread(
            target=self.std_stream_dup,
            args=('WAN DHCPv6 client stderr: ', self.wan_dhclient6_process.stderr),
            name='WAN_dhclient6_stderr',
        )
        self.wan_dhclient6_thread_stderr.start()

        logging.debug('wan_dhclient6 setting sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'forwarding'], '1')
        except SysctlControllerException:
            pass

        logging.info('wan_dhclient6 started')

    def stop_wan_dhclient6(self):
        if self.wan_dhclient6_process is None:
            return

        logging.info('wan_dhclient6 stopping ...')

        logging.debug('wan_dhclient6 restoring sysctl')
        try:
            self.sysctl_controller.restore_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'forwarding'])
        except SysctlControllerException:
            pass

        logging.debug('wan_dhclient6 stopping dhclient process')
        self.wan_dhclient6_process.send_signal(signal.SIGTERM)
        self.wan_dhclient6_thread_stdout.join()
        self.wan_dhclient6_thread_stdout = None
        self.wan_dhclient6_thread_stderr.join()
        self.wan_dhclient6_thread_stderr = None
        self.wan_dhclient6_process.wait()
        self.wan_dhclient6_process = None

        logging.debug('wan_dhclient6 stopping dhclient script server thread')
        self.wan_dhclient6_server.shutdown()
        self.wan_dhclient6_server.server_close()
        self.wan_dhclient6_server = None
        self.wan_dhclient6_server_thread.join()
        self.wan_dhclient6_server_thread = None

        logging.info('wan_dhclient6 stopped')

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
        self.shutdown_event.set()

        with self.lock:
            self.stop_wan_dhclient6()
            self.stop_lan_radvd()

    def handle_dhclient6_command(self, command_obj):
        logging.info('dhclient6_command received')
        logging.debug('dhclient6_command: %s' % command_obj)

        try:
            reason = command_obj['reason']
        except KeyError:
            logging.error('dhclient6_command reason missing')
            return

        with self.lock:
            if reason in ['BOUND6', 'RENEW6', 'REBIND6', 'REBOOT6']:
                self.handle_dhclient6_command_old_ip6_prefix(command_obj)
                self.handle_dhclient6_command_old_ip6_address(command_obj)
                self.handle_dhclient6_command_new_ip6_address(command_obj)
                self.handle_dhclient6_command_new_ip6_prefix(command_obj)
            elif reason in ['EXPIRE6', 'FAIL6', 'STOP6', 'RELEASE6']:
                self.handle_dhclient6_command_old_ip6_prefix(command_obj)
                self.handle_dhclient6_command_old_ip6_address(command_obj)
            else:
                pass

    def handle_dhclient6_command_old_ip6_address(self, command_obj) -> None:
        old_ip6_address = command_obj.get('old_ip6_address')
        if old_ip6_address is not None:
            old_ip6_prefixlen = int(command_obj['old_ip6_prefixlen'])
            try:
                self.my_wan_addresses.remove((old_ip6_address, old_ip6_prefixlen))
            except ValueError:
                pass

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                    netlink_route.addr('del', index=idx, address=old_ip6_address, prefixlen=old_ip6_prefixlen)
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not delete old address')

    def handle_dhclient6_command_new_ip6_address(self, command_obj) -> None:
        new_ip6_address = command_obj.get('new_ip6_address')
        if new_ip6_address is not None:
            new_ip6_prefixlen = int(command_obj['new_ip6_prefixlen'])
            self.my_wan_addresses.append((new_ip6_address, new_ip6_prefixlen))

            new_preferred_life = int(command_obj['new_preferred_life'])
            new_max_life = int(command_obj['new_max_life'])

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                    netlink_route.addr(
                        'add',
                        index=idx, address=new_ip6_address, prefixlen=new_ip6_prefixlen,
                        IFA_CACHEINFO={
                            'ifa_prefered': new_preferred_life,
                            'ifa_valid': new_max_life,
                        }
                    )
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not add new address')

    def handle_dhclient6_command_old_ip6_prefix(self, command_obj) -> None:
        old_ip6_prefix = command_obj.get('old_ip6_prefix')
        if old_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(old_ip6_prefix)
            try:
                del self.my_lan_prefixes[subnet]
            except KeyError:
                pass

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                    netlink_route.addr('del', index=idx, address=subnet[1], prefixlen=subnet.prefixlen)
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not delete old prefix first address')

    def handle_dhclient6_command_new_ip6_prefix(self, command_obj) -> None:
        new_ip6_prefix = command_obj.get('new_ip6_prefix')
        if new_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(new_ip6_prefix)
            new_preferred_life = int(command_obj['new_preferred_life'])
            new_max_life = int(command_obj['new_max_life'])
            self.my_lan_prefixes[subnet] = {'preferred_life': new_preferred_life, 'max_life': new_max_life}

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                    netlink_route.addr(
                        'add',
                        index=idx, address=subnet[1], prefixlen=subnet.prefixlen,
                        IFA_CACHEINFO={
                            'ifa_prefered': new_preferred_life,
                            'ifa_valid': new_max_life,
                        }
                    )
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not add new prefix first address')

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

    @classmethod
    def _server_thread(cls, server):
        logging.info('Serving %s ...', repr(type(server)))
        server.serve_forever()
