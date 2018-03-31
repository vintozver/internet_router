import os
import os.path
import pyroute2
import pyroute2.ipdb
import subprocess
import signal
import jinja2
import logging
import ipaddress
from . import std_stream_dup
from threading import Thread, Event

'''
start_server() {
    if [ "$CONFIGURE_IFACE" = "yes" ] ; then
                "$DAEMON" --mktun | logger -t "$NAME" -i
                ip link set "$TUN_DEVICE" up
                [ -n "$DYNAMIC_POOL" ] && ip route add "$DYNAMIC_POOL" dev "$TUN_DEVICE"
                [ -n "$IPV6_PREFIX" ] && ip route add "$IPV6_PREFIX" dev "$TUN_DEVICE"
                [ -n "$IPV4_TUN_ADDR" ] && ip addr add "$IPV4_TUN_ADDR" dev "$TUN_DEVICE"
                [ -n "$IPV6_TUN_ADDR" ] && ip addr add "$IPV6_TUN_ADDR" dev "$TUN_DEVICE"
    fi
    iptables -t nat -A POSTROUTING -s "$DYNAMIC_POOL" -j MASQUERADE || true
}

stop_server() {
        if [ "$CONFIGURE_IFACE" = "yes" ] ; then
                ip link set "$TUN_DEVICE" down
                "$DAEMON" --rmtun | logger -t "$NAME" -i
        fi
        iptables -t nat -D POSTROUTING -s "$DYNAMIC_POOL" -j MASQUERADE || true
}
'''


class TaygaManager(object):
    """NAT64 translator"""

    CONFIG_TMPL = '''
tun_device {{ iface }}
ipv4-addr 192.168.255.1
prefix {{ prefix }}
dynamic-pool 192.168.255.0/24
data-dir {{ data_path }}
    '''

    @classmethod
    def build_config(cls, iface: str, prefix: str, data_path: str) -> str:
        return jinja2.Template(cls.CONFIG_TMPL).render({'iface': iface, 'prefix': prefix, 'data_path': data_path})

    def __init__(self, state_dir):
        self.store_dir = os.path.join(state_dir, 'tayga')
        self.conf_file_path = os.path.join(state_dir, 'tayga.conf')
        self.pid_file_path = os.path.join(state_dir, 'tayga.pid')

        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread

        self.shutdown_event = Event()

        self.prefix = None  # type: ipaddress.IPv6Network

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        assert self.prefix is not None, 'Prefix must be defined to run the service'
        assert self.prefix.prefixlen == 96, 'Only /96 subnets are allowed'

        logging.debug('tayga tunnel creating ...')
        tayga_tun = subprocess.Popen(
            ['tayga', '--mktun', '--config', self.conf_file_path, '--pidfile', self.pid_file_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ
        )
        tayga_out, tayga_err = tayga_tun.communicate()
        logging.info('tayga tunnel created, exited: %d, out: %s, err: %s' % (
            tayga_tun.returncode, tayga_out.decode('utf-8'), tayga_err.decode('utf-8')
        ))

        try:
            with pyroute2.IPRoute() as netlink_route:
                idx = netlink_route.link_lookup(ifname='nat64')[0]
                # link up
                try:
                    netlink_route.link_up(idx)
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the link. %s' % err.args)
                # ipv4 route
                try:
                    netlink_route.route('add', dst='192.168.255.0/24', oif=idx)
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the route. %s' % err.args)
                # ipv6 route
                try:
                    netlink_route.route('add', dst=str(self.prefix), oif=idx)
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the routes. %s' % err.args)
        except pyroute2.NetlinkError as err:
            logging.error('tayga could not complete the ip setup. %s' % err.args)

        logging.debug('tayga starting ...')
        self.process = subprocess.Popen(
            ['tayga', '--nodetach', '--config', self.conf_file_path, '--pidfile', self.pid_file_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('tayga stdout: ', self.process.stdout),
            name='tayga_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('tayga stderr: ', self.process.stderr),
            name='tayga_stderr',
        )
        self.thread_stderr.start()
        logging.debug('tayga started')

    def stop(self):
        if self.process is None:
            return

        logging.debug('tayga stopping ...')
        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None
        logging.info('tayga stopped')

        logging.debug('tayga tunnel deleting ...')
        tayga_tun = subprocess.Popen(
            ['tayga', '--rmtun', '--config', self.conf_file_path, '--pidfile', self.pid_file_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ
        )
        tayga_out, tayga_err = tayga_tun.communicate()
        logging.info('tayga tunnel deleting, exited: %d, out: %s, err: %s' % (
            tayga_tun.returncode, tayga_out.decode('utf-8'), tayga_err.decode('utf-8')
        ))

    def update(self, prefix: ipaddress.IPv6Network ) -> None:
        self.prefix = prefix

        if self.prefix is not None:
            try:
                with open(self.conf_file_path, 'r') as conf_file:
                    old_conf = conf_file.read()
            except OSError:
                old_conf = ''

            new_conf = self.build_config(
                'nat64',
                str(prefix),
                self.conf_file_path
            )

            if old_conf != new_conf:
                open(self.conf_file_path, 'w').write(new_conf)

                self.stop()

            self.start()
        else:
            self.stop()
            try:
                os.unlink(self.conf_file_path)
            except OSError:
                pass

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()
