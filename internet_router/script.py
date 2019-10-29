#!python3

import sys
import os
import socket
import json

import logging
logging.basicConfig(level=logging.INFO)


def dhclient4():
    state_dir = sys.argv[1]
    logging.info('dhclient4_script invoked, state_dir: %s' % state_dir)

    environment_bytes = json.dumps(dict(os.environ.items())).encode('utf-8')

    logging.info('dhclient4_script creating command socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Connect to server and send data
        sock.connect(os.path.join(state_dir, 'dhclient4_comm'))
        logging.info('dhclient4_script sending key + cmd ...')
        sock.sendall(environment_bytes)
        logging.info('dhclient4_script done')
    finally:
        logging.info('dhclient4_script closing command socket')
        sock.close()


def dhclient6():
    state_dir = sys.argv[1]
    logging.info('dhclient6_script invoked, state_dir: %s' % state_dir)

    environment_bytes = json.dumps(dict(os.environ.items())).encode('utf-8')

    logging.info('dhclient6_script creating command socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Connect to server and send data
        sock.connect(os.path.join(state_dir, 'dhclient6_comm'))
        logging.info('dhclient6_script sending key + cmd ...')
        sock.sendall(environment_bytes)
        logging.info('dhclient6_script done')
    finally:
        logging.info('dhclient6_script closing command socket')
        sock.close()


def pppd():
    state_dir = sys.argv[1]
    logging.info('pppd_script invoked, state_dir: %s' % state_dir)

    command = dict()
    action = sys.argv[2]
    command['action'] = action
    parameters = dict()
    if action in ('ip-pre-up', 'ip-up', 'ip-down'):
        # interface-name tty-device speed local-IP-address remote-IP-address ipparam
        parameters['interface-name'] = sys.argv[3]
        parameters['tty-device'] = sys.argv[4]
        parameters['speed'] = sys.argv[5]
        parameters['local-IP-address'] = sys.argv[6]
        parameters['remote-IP-address'] = sys.argv[7]
        parameters['ipparam'] = sys.argv[8]
    elif action in ('auth-up', 'auth-down'):
        # interface-name peer-name user-name tty-device speed
        parameters['interface-name'] = sys.argv[3]
        parameters['peer-name'] = sys.argv[4]
        parameters['user-name'] = sys.argv[5]
        parameters['tty-device'] = sys.argv[6]
        parameters['speed'] = sys.argv[7]
    elif action in ('ipv6-up', 'ipv6-down'):
        # interface-name tty-device speed local-link-local-address remote-link-local-address ipparam
        parameters['interface-name'] = sys.argv[3]
        parameters['tty-device'] = sys.argv[4]
        parameters['speed'] = sys.argv[5]
        parameters['local-link-local-address'] = sys.argv[6]
        parameters['remote-link-local-address'] = sys.argv[7]
        parameters['ipparam'] = sys.argv[8]
    else:
        raise RuntimeError('action value is unexpected', action)
    command['parameters'] = parameters
    command['environ'] = dict(os.environ.items())

    command_bytes = json.dumps(command).encode('utf-8')

    logging.info('pppd_script creating command socket')
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        # Connect to server and send data
        sock.connect(os.path.join(state_dir, 'pppd_comm'))
        logging.info('pppd_script sending key + cmd ...')
        sock.sendall(command_bytes)
        logging.info('pppd_script done')
    finally:
        logging.info('pppd_script closing command socket')
        sock.close()
