import pyroute2
import pyroute2.ipdb
import iptc
import logging
import ipaddress
from .wan_dhclient import WanDhcpClient6
from .lan_radvd import LanRadvdManager
from .tayga import TaygaManager
from threading import Lock


class Dispatcher(object):
    # Every <net>/64 subnet will have by default
    # <net>.1 - default gateway
    # <net>.2 - service address for the NAT64 translator

    def __init__(self, wan_interface, lan_interface, state_dir):
        self.wan_dhclient4 = WanDhcpClient6(state_dir, wan_interface, self.handle_dhclient4_command)
        self.wan_dhclient6 = WanDhcpClient6(state_dir, wan_interface, self.handle_dhclient6_command)
        self.lan_radvd = LanRadvdManager(state_dir, lan_interface)
        self.tayga = TaygaManager(state_dir)

        self.wan_interface = wan_interface
        self.lan_interface = lan_interface
        self.state_dir = state_dir

        # instance is thread safe
        # lock is necessary, only once interface method may be running at the same time
        self.lock = Lock()

        self.my_wan_ip4_addresses = dict()  # mapping(ip4addr -> dict(subnet:ip4net, routers: list(ip4addr), ttl: int)
        self.my_wan_addresses = list()
        self.my_lan_prefixes = dict()
        self.my_rdnss = set()

    def add_interface(self, index, name):
        logging.info('Adding interface to the topology %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.wan_dhclient4.start()
                self.wan_dhclient6.start()
                self.update_tayga()
            elif name == self.lan_interface:
                self.lan_radvd.update(self.my_lan_prefixes, self.my_rdnss)
                self.update_tayga()
            else:
                pass

    def remove_interface(self, index, name):
        logging.info('Trying to remove interface %d:%s' % (index, name))

        with self.lock:
            if name == self.wan_interface:
                self.wan_dhclient4.stop()
                self.wan_dhclient6.stop()
                self.update_tayga()
            elif name == self.lan_interface:
                self.lan_radvd.update(self.my_lan_prefixes, self.my_rdnss)
                self.update_tayga()

    def shutdown(self):
        with self.lock:
            self.wan_dhclient4.shutdown()
            self.wan_dhclient6.shutdown()
            self.lan_radvd.shutdown()
            self.tayga.shutdown()

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
                self.handle_dhclient6_command_old_ip6_address(command_obj)
                self.handle_dhclient6_command_new_ip6_address(command_obj)
                self.handle_dhclient6_command_new_ip6_prefix(command_obj)
                self.handle_dhclient6_command_new_ip6_rdnss(command_obj)
                self.lan_radvd.update(self.my_lan_prefixes, self.my_rdnss)
                self.update_tayga()
            elif reason in ['EXPIRE6', 'FAIL6', 'STOP6', 'RELEASE6']:
                self.handle_dhclient6_command_old_ip6_rdnss(command_obj)
                self.handle_dhclient6_command_old_ip6_prefix(command_obj)
                self.handle_dhclient6_command_old_ip6_address(command_obj)
                self.lan_radvd.update(self.my_lan_prefixes, self.my_rdnss)
                self.update_tayga()
            else:
                pass

    def handle_dhclient6_command_old_ip6_address(self, command_obj) -> None:
        old_ip6_address = command_obj.get('old_ip6_address')
        if old_ip6_address is not None:
            old_ip6_prefixlen = int(command_obj['old_ip6_prefixlen'])
            try:
                self.my_wan_addresses.remove((old_ip6_address, old_ip6_prefixlen))
            except ValueError:
                pass

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                    netlink_route.addr('del', index=idx, address=old_ip6_address, prefixlen=old_ip6_prefixlen)
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not delete old address')

    def handle_dhclient6_command_new_ip6_address(self, command_obj) -> None:
        new_ip6_address = command_obj.get('new_ip6_address')
        if new_ip6_address is not None:
            new_ip6_prefixlen = int(command_obj['new_ip6_prefixlen'])
            self.my_wan_addresses.append((new_ip6_address, new_ip6_prefixlen, ))

            new_preferred_life = int(command_obj['new_preferred_life'])
            new_max_life = int(command_obj['new_max_life'])

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                    netlink_route.addr(
                        'add',
                        index=idx, address=new_ip6_address, prefixlen=new_ip6_prefixlen,
                        IFA_CACHEINFO={
                            'ifa_prefered': new_preferred_life,
                            'ifa_valid': new_max_life,
                        }
                    )
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not add new address')

    def handle_dhclient6_command_old_ip6_prefix(self, command_obj) -> None:
        old_ip6_prefix = command_obj.get('old_ip6_prefix')
        if old_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(old_ip6_prefix)
            try:
                del self.my_lan_prefixes[subnet]
            except KeyError:
                pass

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                    netlink_route.addr('del', index=idx, address=str(subnet[1]), prefixlen=subnet.prefixlen)
            except pyroute2.NetlinkError:
                logging.error('dhclient6_command could not delete old prefix first address')

    def handle_dhclient6_command_new_ip6_prefix(self, command_obj) -> None:
        new_ip6_prefix = command_obj.get('new_ip6_prefix')
        if new_ip6_prefix is not None:
            subnet = ipaddress.IPv6Network(new_ip6_prefix)
            new_preferred_life = int(command_obj['new_preferred_life'])
            new_max_life = int(command_obj['new_max_life'])
            self.my_lan_prefixes[subnet] = {'preferred_life': new_preferred_life, 'max_life': new_max_life}

            try:
                with pyroute2.IPRoute() as netlink_route:
                    idx = netlink_route.link_lookup(ifname=self.lan_interface)[0]
                    netlink_route.addr(
                        'add',
                        index=idx, address=str(subnet[1]), prefixlen=subnet.prefixlen,
                        IFA_CACHEINFO={
                            'ifa_prefered': new_preferred_life,
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
            elif reason in ['EXPIRE', 'FAIL', 'STOP', 'RELEASE']:
                self.handle_dhclient4_command_old_ip_address(command_obj)
            else:
                pass

    def handle_dhclient4_command_old_ip_address(self, command_obj) -> None:
        old_ip_address = command_obj.get('old_ip_address')
        if old_ip_address is not None:
            old_ip_address = ipaddress.IPv4Address(old_ip_address)
            old_ip_network = ipaddress.IPv4Network(command_obj['old_network_number'], command_obj['old_subnet_mask'])
            if old_ip_address not in old_ip_network:
                logging.error('dhclient4_command old ip address is NOT in the same network. No action will be taken.')
                return

            try:
                my_wan_ip4_address = self.my_wan_ip4_addresses[old_ip_address]
            except KeyError:
                logging.error('dhclient4_command old ip address is NOT in out list. No action will be taken.')
                return

            try:
                del self.my_wan_ip4_addresses[old_ip_address]
            except ValueError:
                pass

            with pyroute2.IPRoute() as netlink_route:
                idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                try:
                    netlink_route.addr(
                        'del',
                        index=idx, address=str(old_ip_address), prefixlen=old_ip_network.prefixlen
                    )
                except pyroute2.NetlinkError:
                    logging.warning('dhclient4_command could not delete old address')

                if len(my_wan_ip4_address['routers']) > 0:
                    old_router = my_wan_ip4_address['routers'][0]
                    try:
                        netlink_route.route('del', dst='0.0.0.0/0', gateway=str(old_router), oif=idx)
                    except pyroute2.NetlinkError as err:
                        logging.warning('dhclient4_command could not add new route, %s' % err.args)

    def handle_dhclient4_command_new_ip_address(self, command_obj) -> None:
        new_ip_address = command_obj.get('new_ip_address')
        if new_ip_address is not None:
            new_ip_address = ipaddress.IPv4Address(new_ip_address)
            new_ip_network = ipaddress.IPv4Network(command_obj['new_network_number'], command_obj['new_subnet_mask'])
            if new_ip_address not in new_ip_network:
                logging.error('dhclient4_command new ip address is NOT in the same network. No action will be taken.')
                return

            new_routers = [ipaddress.IPv4Address(addr) for addr in command_obj.get('new_subnet_mask', '').split(' ')]
            lease_time = int(command_obj['new_dhcp_lease_time'])

            self.my_wan_ip4_addresses[new_ip_address] = {
                'subnet': new_ip_network,
                'routers': new_routers,
                'ttl': lease_time,
            }

            with pyroute2.IPRoute() as netlink_route:
                idx = netlink_route.link_lookup(ifname=self.wan_interface)[0]
                try:
                    netlink_route.addr(
                        'add',
                        index=idx, address=str(new_ip_address), prefixlen=new_ip_network.prefixlen,
                        IFA_CACHEINFO={
                            'ifa_valid': lease_time,
                        }
                    )
                except pyroute2.NetlinkError:
                    logging.error('dhclient4_command could not add new address')

                if len(new_routers) > 0:
                    new_router = new_routers[0]
                    try:
                        netlink_route.route('add', dst='0.0.0.0/0', gateway=str(new_router), oif=idx)
                    except pyroute2.NetlinkError as err:
                        logging.error('dhclient4_command could not add new route, %s' % err.args)

    def update_tayga(self):
        for prefix in self.my_lan_prefixes:
            if prefix.prefixlen == 64:
                self.tayga.update(prefix[2])  # get the ...2 address in the network
                return
        # No /64 subnets. No NAT64 therefore
        self.tayga.update(None)
