import socketserver
import os
import logging
import json


class CommandServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, dispatcher, socket_filename: str):
        logging.info('Init wan_dhclient6_server')

        self.dispatcher = dispatcher

        super(CommandServer, self).__init__(socket_filename, CommandHandler)

    def shutdown(self):
        super(CommandServer, self).shutdown()

        try:
            os.unlink(self.server_address)
        except OSError:
            pass


class CommandHandler(socketserver.BaseRequestHandler):
    def handle(self):
        logging.info('Incoming wan_dhclient6_server command')

        command_bytes = self.request.recv(4096)
        if command_bytes[:128] != self.server.dispatcher.comm_key:
            logging.warning('Incoming wan_dhclient6_server command comm_key mismatch, skipping')
            return

        logging.info('Incoming wan_dhclient6_server comm_key matched, processing')
        command_obj = None
        try:
            command_obj = json.loads(command_bytes[128:].decode('utf-8'))
            logging.debug('dhclient6 command received %s' % command_obj)
        except json.JSONDecodeError as err:
            logging.error('Error decoding json command. Details: %s' % err)
        if command_obj is not None:
            logging.info('Invoking dispatcher from dhclient6 command handler')
            self.server.dispatcher.handle_dhclient6_command(command_obj)
