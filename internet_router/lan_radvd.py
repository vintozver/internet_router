import os
import os.path
import subprocess
import signal
import typing
import logging
from . import std_stream_dup
from . import lan_radvd_conf
from .sysctl import SysctlController, SysctlControllerException
from threading import Thread, Event


class LanRadvdManager(object):
    def __init__(self, state_dir: str, lan_interface: str):
        self.conf_file_path = os.path.join(state_dir, 'radvd.conf')
        self.pid_file_path = os.path.join(state_dir, 'radvd.pid')
        self.lan_interface = lan_interface

        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread

        self.sysctl_controller = SysctlController()

        self.shutdown_event = Event()

    def update(self, lan_prefixes: typing.Dict, rdnss: typing.Set) -> None:
        try:
            with open(self.conf_file_path, 'r') as conf_file:
                old_conf = conf_file.read()
        except OSError:
            old_conf = ''

        new_conf = lan_radvd_conf.build(
            self.lan_interface,
            [{
                'subnet': str(prefix[0]),
                'preferred_life': prefix[1]['preferred_life'],
                'max_life': prefix[1]['max_life'],
            } for prefix in lan_prefixes.items()],
            [str(rdnss_item) for rdnss_item in rdnss],
        )

        if old_conf != new_conf:
            open(self.conf_file_path, 'w').write(new_conf)

            self.stop()

        if len(lan_prefixes) > 0:
            self.start()

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        logging.debug('lan_radvd setting sysctl')
        try:
            self.sysctl_controller.set_sysctl(['net', 'ipv6', 'conf', self.lan_interface, 'forwarding'], '1')
        except SysctlControllerException:
            pass

        self.process = subprocess.Popen(
            [
                'radvd', '--nodaemon',
                '--logmethod', 'stderr', '--debug', '1',
                '--config=%s' % self.conf_file_path,
                '--pidfile=%s' % self.pid_file_path,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('LAN radvd stdout: ', self.process.stdout),
            name='LAN_radvd_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('LAN radvd stderr: ', self.process.stderr),
            name='LAN_radvd_stderr',
        )
        self.thread_stderr.start()

    def stop(self):
        if self.process is None:
            return

        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None

        logging.debug('lan_radvd restoring sysctl')
        try:
            self.sysctl_controller.restore_sysctl(['net', 'ipv6', 'conf', self.lan_interface, 'forwarding'])
        except SysctlControllerException:
            pass

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()
