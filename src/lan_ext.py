import os
import os.path
import logging
import ipaddress
import subprocess
from . import std_stream_dup
from threading import Thread


class LanExt(object):
    def __init__(self, lan_subnet: ipaddress.IPv6Network):
        t = Thread(target=self.worker, args=(lan_subnet, ), daemon=True)
        t.start()

    def worker(self, lan_subnet: ipaddress.IPv6Network):
        logging.debug('lan_ext executing an update')
        process = subprocess.Popen(
            ['/home/root/internet_lan_ext.sh'] + ([str(lan_subnet)] if lan_subnet is not None else []),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=os.environ
        )
        thread_stdout = Thread(target=std_stream_dup, args=('LAN ext stdout: ', process.stdout), name='LAN_ext_stdout', daemon=True)
        thread_stdout.start()
        thread_stderr = Thread(target=std_stream_dup, args=('LAN ext stderr: ', process.stderr), name='LAN_ext_stderr', daemon=True)
        thread_stderr.start()
        process.wait()

