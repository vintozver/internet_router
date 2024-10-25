import os
import os.path
import logging
import ipaddress
import subprocess
from . import std_stream_dup
from threading import Thread


class LanExt(object):
    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        self.script = os.path.join(state_dir, 'lan_ext')

    def update(self, lan_subnet: ipaddress.IPv6Network):
        t = Thread(target=self.worker, args=(lan_subnet, ), daemon=True)
        t.start()

    def worker(self, lan_subnet: ipaddress.IPv6Network):
        if os.path.isfile(self.script) and os.access(self.script, os.X_OK):
            logging.debug('lan_ext executing an update')
            process = subprocess.Popen(
                [self.script] + ([str(lan_subnet)] if lan_subnet is not None else []),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.state_dir,
                env=os.environ
            )
            thread_stdout = Thread(target=std_stream_dup, args=('LAN ext stdout: ', process.stdout), name='LAN_ext_stdout', daemon=True)
            thread_stdout.start()
            thread_stderr = Thread(target=std_stream_dup, args=('LAN ext stderr: ', process.stderr), name='LAN_ext_stderr', daemon=True)
            thread_stderr.start()
            process.wait()
        else:
            logging.debug('lan_ext script does not exist or not executable')

