import typing
import pyroute2
import pyroute2.ipdb
import iptc
import logging
import ipaddress
from .dispatcher import Dispatcher as BaseDispatcher
from .pppd_client import PppdClient
from .lan_ext import LanExt
from .lan_radvd import LanRadvdManager
from .tayga import TaygaManager
from .isc_bind import IscBindManager
from . import ip6rd


class Dispatcher(BaseDispatcher):
    # Every <net>/64 subnet will have by default
    # <net>.1 - default gateway
    # <net>.2 - service address for the NAT64 translator

    def __init__(
            self,
            ip6rd_subnet: ipaddress.IPv6Network,
            ip6rd_gateway: ipaddress.IPv6Address,
            link_interface: str,
            ppp_peer: str,
            wan_v4_interface: str,
            wan_v6_interface: str,
            lan_interface: str,
            state_dir: str
    ):
        super(Dispatcher, self).__init__(state_dir)

        if ip6rd_subnet.prefixlen > 63:
            raise RuntimeError('The ip6rd cannot operate with the subnet "%s"' % str(ip6rd_subnet))
        self.ip6rd_subnet = ip6rd_subnet
        self.ip6rd_gateway = ip6rd_gateway
        self.wan_v4_interface = wan_v4_interface
        self.wan_v6_interface = wan_v6_interface
        self.pppd_client = PppdClient(state_dir, ppp_peer, self.wan_v4_interface, self.handle_pppd_command)
        self.lan_radvd = LanRadvdManager(state_dir, lan_interface)
        self.lan_ext = LanExt(state_dir)
        self.tayga = TaygaManager(state_dir)
        self.isc_bind = IscBindManager(state_dir)

        self.link_interface = link_interface
        self.ppp_peer = ppp_peer
        self.lan_interface = lan_interface

        self.my_wan_ip4_address: typing.Optional[ipaddress.IPv4Address] = None
        self.my_wan_ip6_prefix: typing.Optional[ipaddress.IPv6Network] = None
        self.my_lan_ip6_prefix: typing.Optional[ipaddress.IPv6Network] = None

        self.lan_ext.update(None)

    def add_interface(self, index, name):
        logging.info('Adding interface to the topology %d:%s' % (index, name))

        with self.lock:
            if name == self.link_interface:
                self.pppd_client.start()
                self.update_tayga()
                self.update_isc_bind()
            elif name == self.lan_interface:
                self.update_lan_radvd()
                self.update_tayga()
                self.update_isc_bind()
            else:
                pass

    def remove_interface(self, index, name):
        logging.info('Trying to remove interface %d:%s' % (index, name))

        with self.lock:
            if name == self.link_interface:
                if self.my_wan_ip4_address is not None:
                    self.remove_ip4_addr(self.my_wan_ip4_address)
                self.pppd_client.stop()
                self.update_tayga()
                self.update_isc_bind()
            elif name == self.lan_interface:
                self.update_lan_radvd()
                self.update_tayga()
                self.update_isc_bind()

    def shutdown(self):
        super(Dispatcher, self).shutdown()

        with self.lock:
            if self.my_wan_ip4_address is not None:
                self.remove_ip4_addr(self.my_wan_ip4_address)
            self.pppd_client.shutdown()
            self.lan_radvd.shutdown()
            self.tayga.shutdown()
            self.isc_bind.shutdown()

    def status(self) -> None:
        logging.debug('Status: my WAN ip4 address: %s' % self.my_wan_ip4_address)
        logging.debug('Status: my WAN ip6 prefix: %s' % self.my_wan_ip6_prefix)
        logging.debug('Status: my LAN ip6 prefixes: %s' % self.my_lan_ip6_prefix)

    def handle_pppd_command(self, action: str, parameters: typing.Mapping, environ: typing.Mapping) -> None:
        if environ['IFNAME'] == self.pppd_client.ifname:
            logging.debug('Dispatcher received pppd command, acquiring lock ...')
            lock_res = self.lock_acquire()
            if lock_res:
                logging.debug('Dispatcher received pppd command, lock acquired')
                try:
                    if action == 'ip-up':
                        self.handle_pppd_ip_up(parameters, environ)
                        self.update_lan_radvd()
                        self.update_tayga()
                        self.update_isc_bind()
                    elif action == 'ip-down':
                        self.handle_pppd_ip_down(parameters, environ)
                        self.update_lan_radvd()
                        self.update_tayga()
                        self.update_isc_bind()
                    else:
                        logging.info('Dispatcher received pppd command: %s' % action)
                finally:
                    logging.debug('Dispatcher received pppd command, lock released')
                    self.lock_release()
                return
            else:
                logging.debug('Dispatcher received pppd command, lock not acquired, shutdown in progress, exiting')

    def handle_pppd_ip_up(self, parameters: typing.Mapping, environ: typing.Mapping) -> None:
        local_ip_address = ipaddress.IPv4Address(environ['IPLOCAL'])
        self.add_ip4_addr(local_ip_address)

    def handle_pppd_ip_down(self, parameters: typing.Mapping, environ: typing.Mapping) -> None:
        local_ip_address = ipaddress.IPv4Address(environ['IPLOCAL'])
        self.remove_ip4_addr(local_ip_address)

    def update_tayga(self):
        if self.my_lan_ip6_prefix is not None and self.my_lan_ip6_prefix.prefixlen == 64:
            self.tayga.update(self.my_lan_ip6_prefix[2])  # get the ...2 address in the network
        else:
            # No /64 subnets. No NAT64 therefore
            self.tayga.update(None)

    def update_lan_radvd(self):
        lan_prefixes = dict()
        rdnss = set()
        if self.my_lan_ip6_prefix is not None:
            lan_prefixes[self.my_lan_ip6_prefix] = {'preferred_life': 3600, 'max_life': 7200}
            rdnss.add(self.my_lan_ip6_prefix[1])
        self.lan_radvd.update(lan_prefixes, rdnss)

    def update_isc_bind(self):
        clients_ipv4 = list()
        if self.my_wan_ip4_address is not None:
            clients_ipv4.append(ipaddress.IPv4Network(self.my_wan_ip4_address))
        clients_ipv6 = list()
        if self.my_wan_ip6_prefix is not None:
            clients_ipv6.append(self.my_wan_ip6_prefix)
        self.isc_bind.update(clients_ipv4=clients_ipv4, clients_ipv6=clients_ipv6)

    def add_ip4_addr(self, addr: ipaddress.IPv4Address):
        self.my_wan_ip4_address = addr
        self.my_wan_ip6_prefix = ipaddress.IPv6Network(
            int(self.ip6rd_subnet.network_address)
            |
            (int(self.my_wan_ip4_address) << (128 - 32 - self.ip6rd_subnet.prefixlen))
        ).supernet(128 - 32 - self.ip6rd_subnet.prefixlen)
        my_lan_ip6_prefix_gen = self.my_wan_ip6_prefix.subnets(128 - 64 - self.my_wan_ip6_prefix.prefixlen)
        next(my_lan_ip6_prefix_gen)  # skip the 0th subnet which is effectively assigned to the WAN interface
        self.my_lan_ip6_prefix = next(my_lan_ip6_prefix_gen)
        self.lan_ext.update(self.my_lan_ip6_prefix)

        # add default route
        with pyroute2.IPRoute() as netlink_route:
            # the interface may be gone since it's created and removed dynamically by pppd
            idx_list = netlink_route.link_lookup(ifname=self.wan_v4_interface)
            if len(idx_list) > 0:
                idx = idx_list[0]

                try:
                    netlink_route.route('add', dst='0.0.0.0/0', oif=idx)
                except pyroute2.NetlinkError:
                    logging.error('dispatcher_centurylink could not add the default route')

        # add WAN NAT translation
        nat_iptc_rule = iptc.Rule()
        nat_iptc_rule.out_interface = self.wan_v4_interface
        nat_iptc_target = nat_iptc_rule.create_target('SNAT')
        nat_iptc_target.to_source = str(addr)
        iptc.Chain(iptc.Table(iptc.Table.NAT), 'POSTROUTING').append_rule(nat_iptc_rule)

        # add WAN unreachable route
        with pyroute2.IPRoute() as netlink_route:
            try:
                netlink_route.route('add', dst=str(self.my_wan_ip6_prefix), type='unreachable')
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink could not add the unreachable route')

        # add ip6rd tunnel
        with pyroute2.IPRoute() as netlink_route:
            # interface
            try:
                netlink_route.link('add', ifname=self.wan_v6_interface, kind='sit', sit_local=str(self.my_wan_ip4_address))
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink could not add the sit interface')
            # interface ip6rd setup
            ip6rd.setup(self.wan_v6_interface, self.ip6rd_subnet)
            # lookup new interface
            idx = netlink_route.link_lookup(ifname=self.wan_v6_interface)[0]
            # address
            try:
                netlink_route.addr(
                    'add',
                    index=idx,
                    address=str(self.my_wan_ip6_prefix[1]),
                    prefixlen=self.my_wan_ip6_prefix.prefixlen,
                )
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink: could not add the address to the sit interface')
            # activate
            try:
                netlink_route.link('set', index=idx, state='up')
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink: could not activate the sit interface')
            # default route
            try:
                netlink_route.route('add', dst='::/0', gateway=str(self.ip6rd_gateway), oif=idx)
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink could not add the default route to the sit interface')

        # add LAN subnet
        with pyroute2.IPRoute() as netlink_route:
            idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]

            netlink_route.addr(
                'add',
                index=idx,
                address=str(self.my_lan_ip6_prefix[1]),
                prefixlen=self.my_lan_ip6_prefix.prefixlen,
                IFA_CACHEINFO={
                    'ifa_preferred': 0xffffffff,  # forever
                    'ifa_valid': 0xffffffff,  # forever
                }
            )

    def remove_ip4_addr(self, addr: ipaddress.IPv4Address):
        if self.my_wan_ip4_address != addr:
            logging.error('dispatcher_centurylink: \
current WAN ip4 address does not match the requested "%s"' % str(addr))
            return

        # remove LAN subnet
        with pyroute2.IPRoute() as netlink_route:
            idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]

            try:
                netlink_route.addr(
                    'del',
                    index=idx,
                    address=str(self.my_lan_ip6_prefix[1]),
                    prefixlen=self.my_lan_ip6_prefix.prefixlen,
                )
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink: could not delete the address')

        # remove ip6rd tunnel
        with pyroute2.IPRoute() as netlink_route:
            idx = netlink_route.link_lookup(ifname=self.wan_v6_interface)[0]

            try:
                netlink_route.link('del', index=idx)
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink could not delete the sit interface')

        # remove WAN unreachable route
        with pyroute2.IPRoute() as netlink_route:
            try:
                netlink_route.route('del', dst=str(self.my_wan_ip6_prefix), type='unreachable')
            except pyroute2.NetlinkError:
                logging.error('dispatcher_centurylink could not delete the route')

        # remove WAN NAT translation
        iptc_nat_postrouting = iptc.Chain(iptc.Table(iptc.Table.NAT), 'POSTROUTING')
        for iptc_rule in iptc_nat_postrouting.rules:
            if iptc_rule.out_interface == self.wan_v4_interface \
                    and iptc_rule.target.name == 'SNAT' and iptc_rule.target.to_source == str(addr):
                iptc_nat_postrouting.delete_rule(iptc_rule)
                break

        # remove default route
        with pyroute2.IPRoute() as netlink_route:
            # the interface may be gone since it's created and removed dynamically by pppd
            idx_list = netlink_route.link_lookup(ifname=self.wan_v4_interface)
            if len(idx_list) > 0:
                idx = idx_list[0]

                try:
                    netlink_route.route('del', dst='0.0.0.0/0', oif=idx)
                except pyroute2.NetlinkError:
                    logging.error('dispatcher_centurylink could not delete the route')

        self.my_wan_ip4_address = None
        self.my_wan_ip6_prefix = None
        self.my_lan_ip6_prefix = None
        self.lan_ext.update(None)

