import os
import os.path
import subprocess
import signal
import typing
import logging
import re

from . import std_stream_dup
from threading import Thread, Event


def _server_thread(server):
    logging.info('Serving %s ...', repr(type(server)))
    server.serve_forever()


class PppdClient(object):
    PEER_FORMAT = '/etc/ppp/peers/%s'

    def __init__(
            self,
            state_dir: str,
            peer: str,
            ifname: str,
            callback: typing.Callable[[str, typing.Mapping, typing.Mapping], None]
    ):
        self.comm_file_path = os.path.join(state_dir, 'pppd_comm')
        self.script_file_path = os.path.join(state_dir, 'pppd_script')
        self.peer = peer

        self.ifname = ifname
        self.callback = callback

        self.process = None
        self.thread_stdout = None
        self.thread_stderr = None

        self.shutdown_event = Event()

        # pppd client process and its communication streams
        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread
        # socket server, pppd client callback will form the command and post it here
        self.server = None
        self.server_thread = None

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        logging.info('pppd_client starting ...')

        logging.debug('pppd_client starting script server thread')
        from . import pppd_client_server
        self.server = pppd_client_server.CommandServer(
            self.comm_file_path,
            self.callback
        )
        self.server_thread = Thread(target=_server_thread, args=(self.server,))
        self.server_thread.start()

        logging.debug('pppd_client starting pppd process')
        self.process = subprocess.Popen(
            ['pppd', 'call', self.peer, 'ifname', self.ifname, 'nodetach', 'debug'],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('pppd client stdout: ', self.process.stdout),
            name='pppd_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('pppd client stderr: ', self.process.stderr),
            name='pppd_stderr',
        )
        self.thread_stderr.start()

        logging.info('pppd_client started')

    def stop(self):
        if self.process is None:
            return

        logging.info('pppd_client stopping ...')

        logging.debug('pppd_client stopping pppd process')
        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None

        logging.debug('pppd_client stopping pppd script server thread')
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.server_thread.join()
        self.server_thread = None

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()
