import socketserver
import os
import logging
import json
import typing


class CommandServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, socket_filename: str, comm_key: bytes, callback: typing.Callable[[typing.Mapping], None]):
        logging.info('Init wan_dhclient6_server')

        self.comm_key = comm_key
        self.callback = callback

        super(CommandServer, self).__init__(socket_filename, CommandHandler)

    def shutdown(self):
        super(CommandServer, self).shutdown()

        try:
            os.unlink(self.server_address)
        except OSError:
            pass


class CommandHandler(socketserver.BaseRequestHandler):
    def handle(self):
        logging.info('wan_dhclient6_server incoming command')

        command_bytes = self.request.recv(4096)
        if command_bytes[:128] != self.server.comm_key:
            logging.warning('wan_dhclient6_server command comm_key mismatch, skipping')
            return

        logging.info('wan_dhclient6_server comm_key match, processing')
        command_obj = None
        try:
            command_obj = json.loads(command_bytes[128:].decode('utf-8'))
            logging.debug('wan_dhclient6_server command received: %s' % command_obj)
        except json.JSONDecodeError as err:
            logging.error('wan_dhclient6_server error decoding json command. Details: %s' % err)
        if command_obj is not None:
            logging.info('wan_dhclient6_server invoking callback')
            self.server.callback(command_obj)
