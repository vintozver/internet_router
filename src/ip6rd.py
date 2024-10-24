import ctypes
import socket
import ipaddress
import fcntl
from pyroute2.netlink.rtnl.ifinfmsg.compat import IFNAMSIZ


def setup(interface_name: str, prefix: ipaddress.IPv6Network):
    # struct ifreq {
    #     char ifr_name[IFNAMSIZ]; /* Interface name */
    #     union {
    #         ...
    #         char           *ifr_data;
    #     }
    #  }
    #
    # SIOCDEVPRIVATE = 0x89f0
    # SIOCGET6RD = (SIOCDEVPRIVATE + 8)
    # SIOCADD6RD = (SIOCDEVPRIVATE + 9)
    # SIOCDEL6RD = (SIOCDEVPRIVATE + 10)
    # SIOCCHG6RD + (SIOCDEVPRIVATE + 11)
    #
    # struct ip_tunnel_6rd {
    #     struct in6_addr prefix;
    #     __be32 relay_prefix;
    #     __u16 prefixlen;
    #     __u16 relay_prefixlen;
    # }

    class Struct_ip_tunnel_6rd(ctypes.Structure):
        _fields_ = (
                ("prefix", ctypes.c_char * IFNAMSIZ),
                ("relay_prefix", ctypes.c_char * 4),
                ("prefixlen", ctypes.c_ushort),
                ("relay_prefixlen", ctypes.c_ushort),
        )

    class Struct_ifreq(ctypes.Structure):
        _fields_ = (
                ("ifr_name", ctypes.c_char * 16),
                ("ifr_data", ctypes.POINTER(Struct_ip_tunnel_6rd)),
        )

    ip_tunnel_6rd = Struct_ip_tunnel_6rd()
    ip_tunnel_6rd.prefix = prefix.network_address.packed
    ip_tunnel_6rd.prefixlen = prefix.prefixlen

    ifreq = Struct_ifreq()
    ifreq.ifr_name = interface_name.encode('ascii')
    ifreq.ifr_data = ctypes.pointer(ip_tunnel_6rd)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control_socket:
        fcntl.ioctl(control_socket, 0x89f9, ifreq)
