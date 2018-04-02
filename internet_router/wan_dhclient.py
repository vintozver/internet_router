import os
import os.path
import subprocess
import signal
import typing
import logging

from . import std_stream_dup
from .sysctl import SysctlController, SysctlControllerException
from threading import Thread, Event


def _server_thread(server):
    logging.info('Serving %s ...', repr(type(server)))
    server.serve_forever()


class WanDhcpClient6(object):
    def __init__(
            self,
            state_dir: str,
            wan_interface: str,
            callback: typing.Callable[[typing.Mapping], None]
    ):
        self.comm_file_path = os.path.join(state_dir, 'dhclient6_comm')
        self.script_file_path = os.path.join(state_dir, 'dhclient6_script')
        self.wan_interface = wan_interface
        self.callback = callback

        self.process = None
        self.thread_stdout = None
        self.thread_stderr = None

        self.sysctl_controller = SysctlController()

        self.shutdown_event = Event()

        # dhcp client process and its communication streams
        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread
        # socket server, dhcp client callback will form the command and post it here
        self.server = None
        self.server_thread = None

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        logging.info('wan_dhclient6 starting ...')

        logging.debug('wan_dhclient6 starting script server thread')
        from . import wan_dhclient_server
        self.server = wan_dhclient_server.CommandServer(
            '6',
            self.comm_file_path,
            self.callback
        )
        self.server_thread = Thread(target=_server_thread, args=(self.server,))
        self.server_thread.start()

        logging.debug('wan_dhclient6 starting dhclient process')
        self.process = subprocess.Popen(
            [
                'dhclient', '--no-pid', '-d', '-v', '-6', '-P', '-N',
                '-sf', self.script_file_path,
                self.wan_interface
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('WAN DHCPv6 client stdout: ', self.process.stdout),
            name='WAN_dhclient6_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('WAN DHCPv6 client stderr: ', self.process.stderr),
            name='WAN_dhclient6_stderr',
        )
        self.thread_stderr.start()

        logging.debug('wan_dhclient6 setting forwarding sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'forwarding'], '1')
        except SysctlControllerException:
            pass
        # accept routers even if the forwarding is enabled
        logging.debug('wan_dhclient6 setting routing advertisement sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'accept_ra'], '2')
        except SysctlControllerException:
            pass

        logging.info('wan_dhclient6 started')

    def stop(self):
        if self.process is None:
            return

        logging.info('wan_dhclient6 stopping ...')

        logging.debug('wan_dhclient6 restoring routing advertisement sysctl')
        try:
            self.sysctl_controller.restore_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'accept_ra'])
        except SysctlControllerException:
            pass
        logging.debug('wan_dhclient6 restoring forwarding sysctl')
        try:
            self.sysctl_controller.restore_sysctl(['net', 'ipv6', 'conf', self.wan_interface, 'forwarding'])
        except SysctlControllerException:
            pass

        logging.debug('wan_dhclient6 stopping dhclient process')
        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None

        logging.debug('wan_dhclient6 stopping dhclient script server thread')
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.server_thread.join()
        self.server_thread = None

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()


class WanDhcpClient4(object):
    def __init__(
            self,
            state_dir: str,
            wan_interface: str,
            callback: typing.Callable[[typing.Mapping], None]
    ):
        self.comm_file_path = os.path.join(state_dir, 'dhclient4_comm')
        self.script_file_path = os.path.join(state_dir, 'dhclient4_script')
        self.wan_interface = wan_interface
        self.callback = callback

        self.process = None
        self.thread_stdout = None
        self.thread_stderr = None

        self.sysctl_controller = SysctlController()

        self.shutdown_event = Event()

        # dhcp client process and its communication streams
        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread
        # socket server, dhcp client callback will form the command and post it here
        self.server = None
        self.server_thread = None

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        logging.info('wan_dhclient4 starting ...')

        logging.debug('wan_dhclient4 starting script server thread')
        from . import wan_dhclient_server
        self.server = wan_dhclient_server.CommandServer(
            '4',
            self.comm_file_path,
            self.callback
        )
        self.server_thread = Thread(target=_server_thread, args=(self.server,))
        self.server_thread.start()

        logging.debug('wan_dhclient4 starting dhclient process')
        self.process = subprocess.Popen(
            [
                'dhclient', '--no-pid', '-d', '-v', '-4',
                '-sf', self.script_file_path,
                self.wan_interface
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('WAN DHCPv4 client stdout: ', self.process.stdout),
            name='WAN_dhclient4_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('WAN DHCPv4 client stderr: ', self.process.stderr),
            name='WAN_dhclient4_stderr',
        )
        self.thread_stderr.start()

        logging.debug('wan_dhclient4 setting forwarding sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv4', 'conf', self.wan_interface, 'forwarding'], '1')
        except SysctlControllerException:
            pass

        logging.info('wan_dhclient4 started')

    def stop(self):
        if self.process is None:
            return

        logging.info('wan_dhclient4 stopping ...')

        logging.debug('wan_dhclient4 restoring forwarding sysctl')
        try:
            self.sysctl_controller.restore_sysctl(['net', 'ipv4', 'conf', self.wan_interface, 'forwarding'])
        except SysctlControllerException:
            pass

        logging.debug('wan_dhclient4 stopping dhclient process')
        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None

        logging.debug('wan_dhclient4 stopping dhclient script server thread')
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.server_thread.join()
        self.server_thread = None

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()
