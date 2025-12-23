import os
import os.path
import pyroute2
import subprocess
import signal
import jinja2
import json
import logging
import ipaddress
import nftables
from . import std_stream_dup
from .sysctl import SysctlController, SysctlControllerException
from threading import Thread, Event


class TaygaManager(object):
    """NAT64 translator"""

    CONFIG_TMPL = '''
tun-device {{ interface }}
prefix 64:ff9b::/96
ipv6-addr {{ global_ipv6_addr }}
ipv4-addr 192.168.255.1
dynamic-pool 192.168.255.0/24
data-dir {{ data_path }}
    '''

    @classmethod
    def build_config(cls, interface: str, global_ipv6_addr: str, data_path: str) -> str:
        return jinja2.Template(cls.CONFIG_TMPL).render({
            'interface': interface, 'global_ipv6_addr': global_ipv6_addr,
            'data_path': data_path
        })

    def __init__(self, state_dir):
        self.store_dir = os.path.join(state_dir, 'tayga')
        try:
            os.mkdir(self.store_dir)
        except OSError:
            pass
        self.conf_file_path = os.path.join(state_dir, 'tayga.conf')
        self.pid_file_path = os.path.join(state_dir, 'tayga.pid')

        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread

        self.sysctl_controller = SysctlController()

        self.shutdown_event = Event()

        self.global_ipv6_addr = None  # type: ipaddress.IPv6Address

        self.nft = nftables.Nftables()
        self.nft.set_json_output(True)
        self.nft_action = nftables.Nftables()

        self.nft = nftables.Nftables()
        self.nft.set_json_output(True)
        self.nft_action = nftables.Nftables()

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        assert self.global_ipv6_addr is not None, 'Global IPv6 address must be defined to run the service'

        logging.debug('tayga tunnel creating ...')
        tayga_tun = subprocess.Popen(
            ['tayga', '-d', '--mktun', '--config', self.conf_file_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ
        )
        tayga_out, tayga_err = tayga_tun.communicate()
        logging.info('tayga tunnel created, exited: %d, out: %s, err: %s' % (
            tayga_tun.returncode,
            tayga_out.decode('utf-8') if tayga_out is not None else '<X>',
            tayga_err.decode('utf-8') if tayga_err is not None else '<X>',
        ))

        logging.debug('tayga setting forwarding sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv4', 'conf', 'nat64', 'forwarding'], '1')
        except SysctlControllerException:
            pass

        rc, out, err = self.nft_action.cmd('add rule nat POSTROUTING ip saddr 192.168.255.0/24 masquerade comment NAT64')
        if rc != 0:
            logging.error('tayga nft add error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))

        try:
            with pyroute2.IPRoute() as netlink_route:
                idx = netlink_route.link_lookup(ifname='nat64')[0]
                # link up
                try:
                    netlink_route.link('set', index=idx, state='up')
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the link. %s' % err.args)
                # ipv4 route
                try:
                    netlink_route.route('add', dst='192.168.255.0/24', oif=idx)
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the route. %s' % err.args)
                # ipv6 route
                try:
                    netlink_route.route('add', dst='64:ff9b::/96', oif=idx)
                except pyroute2.NetlinkError as err:
                    logging.error('tayga could not set the routes. %s' % err.args)
        except pyroute2.NetlinkError as err:
            logging.error('tayga could not complete the ip setup. %s' % err.args)

        logging.debug('tayga starting ...')
        self.process = subprocess.Popen(
            ['tayga', '-d', '--config', self.conf_file_path, '--pidfile', self.pid_file_path],
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

        rc, out, err = self.nft.cmd("list table ip nat")
        if rc == 0:
            output_json = json.loads(out)["nftables"]
            handles = list(map(lambda item_handle: item_handle["rule"]["handle"], filter(lambda item: ("rule" in item) and (item["rule"]["family"] == "ip" and item["rule"]["table"] == "nat" and item["rule"]["chain"] == "POSTROUTING" and item["rule"]["comment"] == "NAT64"), output_json)))
            for handle in handles:
                rc, out, err = self.nft_action.cmd("delete rule ip nat POSTROUTING handle %s" % handle)
                if rc != 0:
                    logging.error('tayga nft delete error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))
        else:
            logging.error('tayga nft query error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))


        logging.debug('tayga tunnel deleting ...')
        with pyroute2.IPRoute() as netlink_route:
            links = netlink_route.link_lookup(ifname='nat64')
            try:
                idx = links[0]
            except IndexError:
                idx = None

            if idx is not None:
                try:
                    netlink_route.link('del', index=idx)
                except pyroute2.NetlinkError:
                    logging.error('tayga tunnel deleting failure')
            else:
                logging.warning('tayga tunnel deleting link not found')


    def update(self, global_ipv6_addr: ipaddress.IPv6Address=None) -> None:
        self.global_ipv6_addr = global_ipv6_addr

        if self.global_ipv6_addr is not None:
            try:
                with open(self.conf_file_path, 'r') as conf_file:
                    old_conf = conf_file.read()
            except OSError:
                old_conf = ''

            new_conf = self.build_config(
                'nat64',
                str(global_ipv6_addr),
                self.store_dir
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
