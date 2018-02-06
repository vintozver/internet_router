#!python3

import sys
import os
import socket
import json

import logging
logging.basicConfig(level=logging.INFO)


def dhclient6():
    state_dir = sys.argv[1]
    logging.info('dhclient6_script invoked, state_dir: %s' % state_dir)

    comm_key = open(os.path.join(state_dir, 'comm_key'), 'rb').read()
    environment_bytes = json.dumps(dict(os.environ.items())).encode('utf-8')

    logging.info('dhclient6_script creating command socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Connect to server and send data
        sock.connect(os.path.join(state_dir, 'dhclient6_comm'))
        logging.info('dhclient6_script sending key + cmd ...')
        sock.sendall(comm_key + environment_bytes)
        logging.info('dhclient6_script done')
    finally:
        logging.info('dhclient6_script closing command socket')
        sock.close()
