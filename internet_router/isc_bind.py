import typing
import os
import os.path
import subprocess
import signal
import jinja2
import logging
import ipaddress
from . import std_stream_dup
from threading import Thread, Event


class IscBindManager(object):
    """ISC BIND (DNS Server)"""

    CONFIG_TMPL = '''
options {
    directory "{{ working_dir }}";
    pid-file none;

    //========================================================================
    // If BIND logs error messages about the root key being expired,
    // you will need to update your keys.  See https://www.isc.org/bind-keys
    //========================================================================
    dnssec-validation auto;

    auth-nxdomain no;    # conform to RFC1035
    listen-on { any; };
    listen-on-v6 { any; };
};

view clients-ipv4 {
    match-clients {
        {% for client_ipv4 in clients_ipv4 -%}
        {{ client_ipv4 }};
        {%- endfor %}
    };
    match-recursive-only yes;
    forwarders {
        {%- for forwarder_ipv4 in forwarders_ipv4 %}
        {{ forwarder_ipv4 }};
        {% endfor -%}
    };

    // prime the server with knowledge of the root servers
    zone "." {
        type hint;
        file "/etc/bind/db.root";
    };

    // be authoritative for the localhost forward and reverse zones, and for
    // broadcast zones as per RFC 1912

    zone "localhost" {
        type master;
        file "/etc/bind/db.local";
    };

    zone "127.in-addr.arpa" {
        type master;
        file "/etc/bind/db.127";
    };

    zone "0.in-addr.arpa" {
        type master;
        file "/etc/bind/db.0";
    };

    zone "255.in-addr.arpa" {
        type master;
        file "/etc/bind/db.255";
    };

    include "/etc/bind/zones.rfc1918";
};

view clients-ipv6 {
    match-clients {
        {% for client_ipv6 in clients_ipv6 -%}
        {{ client_ipv6 }};
        {%- endfor %}
    };
    match-recursive-only yes;
    forwarders {
        {%- for forwarder_ipv6 in forwarders_ipv6 %}
        {{ forwarder_ipv6 }};
        {% endfor -%}
    };

    zone "." {
        type hint;
        file "/etc/bind/db.root";
    };

    dns64 64:ff9b::/96 {
        suffix ::;
    };
};
    '''

    @classmethod
    def build_config(
            cls,
            working_dir: str,
            forwarders_ipv4: typing.List[ipaddress.IPv4Address], forwarders_ipv6: typing.List[ipaddress.IPv6Address],
            clients_ipv4: typing.List[ipaddress.IPv4Network], clients_ipv6: typing.List[ipaddress.IPv6Network],
    ) -> str:
        return jinja2.Template(cls.CONFIG_TMPL).render({
            'working_dir': working_dir,
            'forwarders_ipv4': forwarders_ipv4, 'clients_ipv4': clients_ipv4,
            'forwarders_ipv6': forwarders_ipv6, 'clients_ipv6': clients_ipv6,
        })

    def __init__(self, state_dir):
        self.store_dir = os.path.join(state_dir, 'isc_bind')
        try:
            os.mkdir(self.store_dir)
        except OSError:
            pass
        self.conf_file_path = os.path.join(self.store_dir, 'named.conf')

        self.process = None
        self.thread_stdout = None  # stdout polling thread
        self.thread_stderr = None  # stderr polling thread

        self.shutdown_event = Event()

        self.clients_ipv4 = list()  # type: typing.List[ipaddress.IPv4Network]
        self.clients_ipv6 = list()  # type: typing.List[ipaddress.IPv6Network]

    def start(self):
        if self.process is not None:
            return

        if self.shutdown_event.is_set():
            return

        logging.debug('ISC BIND starting ...')
        self.process = subprocess.Popen(
            ['named', '-f', '-c', self.conf_file_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=os.environ
        )
        self.thread_stdout = Thread(
            target=std_stream_dup,
            args=('ISC BIND stdout: ', self.process.stdout),
            name='ISC isc_bind_stdout',
        )
        self.thread_stdout.start()
        self.thread_stderr = Thread(
            target=std_stream_dup,
            args=('ISC BIND stderr: ', self.process.stderr),
            name='isc_bind_stderr',
        )
        self.thread_stderr.start()
        logging.debug('ISC BIND started')

    def stop(self):
        if self.process is None:
            return

        logging.debug('ISC BIND stopping ...')
        self.process.send_signal(signal.SIGTERM)
        self.thread_stdout.join()
        self.thread_stdout = None
        self.thread_stderr.join()
        self.thread_stderr = None
        self.process.wait()
        self.process = None
        logging.info('ISC BIND stopped')

    def update(
            self,
            clients_ipv4: typing.List[ipaddress.IPv4Network] = (),
            clients_ipv6: typing.List[ipaddress.IPv6Network] = (),
    ) -> None:
        self.clients_ipv4 = clients_ipv4
        self.clients_ipv6 = clients_ipv6

        try:
            with open(self.conf_file_path, 'r') as conf_file:
                old_conf = conf_file.read()
        except OSError:
            old_conf = ''

        new_conf = self.build_config(
            self.store_dir,
            forwarders_ipv4=[
                ipaddress.IPv4Address('1.1.1.1'),
                ipaddress.IPv4Address('1.0.0.1'),
            ],
            forwarders_ipv6=[
                ipaddress.IPv6Address('2606:4700:4700::1111'),
                ipaddress.IPv6Address('2606:4700:4700::1001'),
            ],
            clients_ipv4=[
                ipaddress.IPv4Network('127.0.0.0/8'),
                ipaddress.IPv4Network('192.168.0.0/24'),
            ] + self.clients_ipv4,
            clients_ipv6=[
                ipaddress.IPv6Network('::1/128'),
            ] + self.clients_ipv6,
        )

        if old_conf != new_conf:
            open(self.conf_file_path, 'w').write(new_conf)

            self.stop()

        self.start()

    def shutdown(self):
        self.shutdown_event.set()
        self.stop()
