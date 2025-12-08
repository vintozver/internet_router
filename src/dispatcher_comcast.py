import typing
import pyroute2
import logging
import ipaddress
import json
import nftables
from .dispatcher import Dispatcher as BaseDispatcher
from .wan_dhclient import WanDhcpClient4, WanDhcpClient6
from .lan_ext import LanExt
from .tayga import TaygaManager
from .isc_bind import IscBindManager


class Dispatcher(BaseDispatcher):
    # Every <net>/64 subnet will have by default
    # <net>.1 - default gateway
    # <net>.2 - service address for the NAT64 translator

    def __init__(self, wan_interface, lan_interface, state_dir):
        super(Dispatcher, self).__init__(state_dir)

        self.wan_dhclient4 = WanDhcpClient4(state_dir, wan_interface, self.handle_dhclient4_command)
        self.wan_dhclient6 = WanDhcpClient6(state_dir, wan_interface, self.handle_dhclient6_command)
        self.lan_ext = LanExt(state_dir)
        self.tayga = TaygaManager(state_dir)
        self.isc_bind = IscBindManager(state_dir)

        self.wan_interface = wan_interface
        self.lan_interface = lan_interface

        self.my_wan_ip4_addresses = dict()  # mapping(ip4addr -> dict(subnet:ip4net, routers: list(ip4addr), ttl: int)
        self.my_wan_ip6_prefixes = dict()  # mapping(ip6addr -> dict(preferred_life: int, max_life: int))
        self.my_rdnss = set()

        self.my_lan_ip6_prefix: typing.Optional[ipaddress.IPv6Network] = None

        self.lan_ext.update(None)

        self.nft = nftables.Nftables()
        self.nft.set_json_output(True)
        self.nft_action = nftables.Nftables()
        rc, out, err = self.nft_action.cmd("add table nat")
        if rc != 0:
            logging.error('dispatcher_comcast nft init error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))
        rc, out, err = self.nft_action.cmd("add chain nat POSTROUTING { type nat hook postrouting priority 100 ; }")
        if rc != 0:
            logging.error('dispatcher_comcast nft init error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))

    def add_interface(self, index, name):
        logging.info('Adding interface to the topology %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.wan_dhclient4.start()
                self.wan_dhclient6.start()
                self.update_tayga()
                self.update_isc_bind()
            elif name == self.lan_interface:
                self.update_lan_ext()
                self.update_tayga()
                self.update_isc_bind()
            else:
                pass

    def remove_interface(self, index, name):
        logging.info('Trying to remove interface %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.wan_dhclient4.stop()
                self.wan_dhclient6.stop()
                self.update_tayga()
                self.update_isc_bind()
            elif name == self.lan_interface:
                self.update_lan_ext()
                self.update_tayga()
                self.update_isc_bind()

    def shutdown(self):
        super(Dispatcher, self).shutdown()

        with self.lock:
            for addr in list(self.my_wan_ip4_addresses.keys()):
                self.remove_ip4_addr(addr)
            self.wan_dhclient4.shutdown()
            self.wan_dhclient6.shutdown()
            self.tayga.shutdown()
            self.isc_bind.shutdown()

    def status(self) -> None:
        logging.info('Status: my WAN ip4 addresses: %s' % self.my_wan_ip4_addresses)
        logging.info('Status: my WAN ip6 prefixes: %s' % self.my_wan_ip6_prefixes)
        logging.info('Status: my ip6 rdnss: %s' % self.my_rdnss)

    def handle_dhclient6_command(self, command_obj):
        logging.info('dhclient6_command received')
        logging.debug('dhclient6_command: %s' % command_obj)

        try:
            reason = command_obj['reason']
        except KeyError:
            logging.error('dhclient6_command reason missing')
            return

        with self.lock:
            if reason in ['BOUND6', 'RENEW6', 'REBIND6', 'REBOOT6']:
                self.handle_dhclient6_command_old_ip6_rdnss(command_obj)
                self.handle_dhclient6_command_old_ip6_prefix(command_obj)
                self.handle_dhclient6_command_new_ip6_prefix(command_obj)
                self.handle_dhclient6_command_new_ip6_rdnss(command_obj)
                self.update_lan_ext()
                self.update_tayga()
                self.update_isc_bind()
            elif reason in ['EXPIRE6', 'FAIL6', 'STOP6', 'RELEASE6']:
                self.handle_dhclient6_command_old_ip6_rdnss(command_obj)
                self.handle_dhclient6_command_old_ip6_prefix(command_obj)
                self.update_lan_ext()
                self.update_tayga()
                self.update_isc_bind()
            else:
                logging.warning('dhclient_command: reason "%s" unknown' % reason)

    def handle_dhclient6_command_old_ip6_prefix(self, command_obj) -> None:
        old_ip6_prefix = command_obj.get('old_ip6_prefix')
        if old_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(old_ip6_prefix)
            try:
                del self.my_wan_ip6_prefixes[subnet]
            except KeyError:
                pass

            if self.my_lan_ip6_prefix is not None:
                try:
                    with pyroute2.IPRoute() as netlink_route:
                        idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                        netlink_route.addr(
                            'del',
                            index=idx,
                            address=str(self.my_lan_ip6_prefix[1]),
                            prefixlen=self.my_lan_ip6_prefix.prefixlen
                        )
                except pyroute2.NetlinkError:
                    logging.error('dhclient6_command could not delete old prefix first address')

                self.my_lan_ip6_prefix = None

    def handle_dhclient6_command_new_ip6_prefix(self, command_obj) -> None:
        new_ip6_prefix = command_obj.get('new_ip6_prefix')
        if new_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(new_ip6_prefix)
            new_preferred_life = int(command_obj['new_preferred_life'])
            new_max_life = int(command_obj['new_max_life'])
            self.my_wan_ip6_prefixes[subnet] = {'preferred_life': new_preferred_life, 'max_life': new_max_life}

            if subnet.prefixlen <= 64:
                my_lan_ip6_prefix_gen = subnet.subnets(128 - 64 - subnet.prefixlen)
                self.my_lan_ip6_prefix = next(my_lan_ip6_prefix_gen)
            else:
                self.my_lan_ip6_prefix = None

            if self.my_lan_ip6_prefix is not None:
                try:
                    with pyroute2.IPRoute() as netlink_route:
                        idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                        netlink_route.addr(
                            'add',
                            index=idx,
                            address=str(self.my_lan_ip6_prefix[1]),
                            prefixlen=self.my_lan_ip6_prefix.prefixlen,
                            IFA_CACHEINFO={
                                'ifa_preferred': new_preferred_life,
                                'ifa_valid': new_max_life,
                            }
                        )
                except pyroute2.NetlinkError:
                    logging.error('dhclient6_command could not add new prefix first address')

    def handle_dhclient6_command_old_ip6_rdnss(self, command_obj) -> None:
        rdnss_value = command_obj.get('old_dhcp6_name_servers')
        if rdnss_value is not None:
            for rdnss_item in [ipaddress.IPv6Address(rdnss_value_item) for rdnss_value_item in rdnss_value.split(' ')]:
                try:
                    self.my_rdnss.remove(rdnss_item)
                except KeyError:
                    pass

    def handle_dhclient6_command_new_ip6_rdnss(self, command_obj) -> None:
        rdnss_value = command_obj.get('new_dhcp6_name_servers')
        if rdnss_value is not None:
            for rdnss_item in [ipaddress.IPv6Address(rdnss_value_item) for rdnss_value_item in rdnss_value.split(' ')]:
                try:
                    self.my_rdnss.add(rdnss_item)
                except KeyError:
                    pass

    def handle_dhclient4_command(self, command_obj):
        logging.info('dhclient4_command received')
        logging.debug('dhclient4_command: %s' % command_obj)

        try:
            reason = command_obj['reason']
        except KeyError:
            logging.error('dhclient4_command reason missing')
            return

        with self.lock:
            if reason in ['PREINIT', 'BOUND', 'RENEW', 'REBIND', 'REBOOT']:
                self.handle_dhclient4_command_old_ip_address(command_obj)
                self.handle_dhclient4_command_new_ip_address(command_obj)
                self.update_isc_bind()
            elif reason in ['EXPIRE', 'FAIL', 'STOP', 'RELEASE']:
                self.handle_dhclient4_command_old_ip_address(command_obj)
                self.update_isc_bind()
            else:
                pass

    def handle_dhclient4_command_old_ip_address(self, command_obj) -> None:
        ip_address = command_obj.get('old_ip_address')
        if ip_address is not None:
            ip_address = ipaddress.IPv4Address(ip_address)
            ip_network = ipaddress.IPv4Network((command_obj['old_network_number'], command_obj['old_subnet_mask']))
            if ip_address not in ip_network:
                logging.error('dhclient4_command old ip address is NOT in the same network. No action will be taken.')
                return

            self.remove_ip4_addr(ip_address)

    def handle_dhclient4_command_new_ip_address(self, command_obj) -> None:
        ip_address = command_obj.get('new_ip_address')
        if ip_address is not None:
            ip_address = ipaddress.IPv4Address(ip_address)
            ip_network = ipaddress.IPv4Network((command_obj['new_network_number'], command_obj['new_subnet_mask']))
            if ip_address not in ip_network:
                logging.error('dhclient4_command new ip address is NOT in the same network. No action will be taken.')
                return

            ttl = int(command_obj['new_dhcp_lease_time'])
            routers = [ipaddress.IPv4Address(addr) for addr in command_obj.get('new_routers', '').split(' ')]
            dns = [ipaddress.IPv4Address(addr) for addr in command_obj.get('new_domain_name_servers', '').split(' ')]

            self.add_ip4_addr(ip_address, ip_network, ttl, routers, dns)

    def update_tayga(self):
        if self.my_lan_ip6_prefix is not None and self.my_lan_ip6_prefix.prefixlen == 64:
            self.tayga.update(self.my_lan_ip6_prefix[2])  # get the ...2 address in the network
        else:
            # No /64 subnets. No NAT64 therefore
            self.tayga.update(None)

    def update_lan_ext(self):
        self.lan_ext.update(self.my_lan_ip6_prefix)

    def update_isc_bind(self):
        clients_ipv4 = list(ipaddress.IPv4Network(ip4_addr) for ip4_addr in self.my_wan_ip4_addresses.keys())
        clients_ipv6 = list(self.my_wan_ip6_prefixes.keys())
        self.isc_bind.update(clients_ipv4=clients_ipv4, clients_ipv6=clients_ipv6)

    def add_ip4_addr(
            self,
            addr: ipaddress.IPv4Address, subnet: ipaddress.IPv4Network, ttl: int,
            routers: typing.List[ipaddress.IPv4Address],
            dns: typing.List[ipaddress.IPv4Address],
    ):
        self.my_wan_ip4_addresses[addr] = {
            'subnet': subnet,
            'routers': routers,
            'ttl': ttl,
            'dns': dns,
        }

        with pyroute2.IPRoute() as netlink_route:
            idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
            try:
                netlink_route.addr(
                    'add',
                    index=idx, address=str(addr), prefixlen=subnet.prefixlen,
                    IFA_CACHEINFO={
                        'ifa_valid': ttl,
                    }
                )
            except pyroute2.NetlinkError:
                logging.error('dhclient4_command could not add a new address')

            if len(routers) > 0:
                new_router = routers[0]
                try:
                    netlink_route.route('add', dst='0.0.0.0/0', gateway=str(new_router), oif=idx)
                except pyroute2.NetlinkError:
                    logging.error('dhclient4_command could not add a new route')

        rc, out, err = self.nft_action.cmd("add rule nat POSTROUTING oif %s snat to %s comment INTERNET-NAT" % (
            self.wan_interface, str(addr)
        ))
        if rc != 0:
            logging.error('dispatcher_comcast nft add error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))

    def remove_ip4_addr(self, addr: ipaddress.IPv4Address):
        try:
            my_wan_ip4_address = self.my_wan_ip4_addresses[addr]
        except KeyError:
            logging.error('clean_ip4_addr: old ip address is NOT in out list. No action will be taken.')
            return

        del self.my_wan_ip4_addresses[addr]

        ip_network = my_wan_ip4_address['subnet']

        with pyroute2.IPRoute() as netlink_route:
            idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
            try:
                netlink_route.addr('del', index=idx, address=str(addr), prefixlen=ip_network.prefixlen)
            except pyroute2.NetlinkError:
                logging.warning('clean_ip4_addr: could not delete the address')

            if len(my_wan_ip4_address['routers']) > 0:
                router = my_wan_ip4_address['routers'][0]
                try:
                    netlink_route.route('del', dst='0.0.0.0/0', gateway=str(router), oif=idx)
                except pyroute2.NetlinkError:
                    logging.warning('clean_ip4_addr: could not delete the route')

        rc, out, err = self.nft.cmd("list table ip nat")
        if rc == 0:
            logging.info("Retrieving list of rules success")
            output_json = json.loads(out)["nftables"]
            handles = list(map(lambda item_handle: item_handle["rule"]["handle"], filter(lambda item: ("rule" in item) and (item["rule"]["family"] == "ip" and item["rule"]["table"] == "nat" and item["rule"]["chain"] == "POSTROUTING" and item["rule"]["comment"] == "INTERNET-NAT"), output_json)))
            for handle in handles:
                rc, out, err = self.nft_action.cmd("delete rule ip nat POSTROUTING handle %s" % handle)
                if rc != 0:
                    logging.error('dispatcher_comcast nft delete error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))
        else:
            logging.error('dispatcher_comcast nft query error. rc:%s | stdout:%s | stderr:%s' % (rc, out, err))

