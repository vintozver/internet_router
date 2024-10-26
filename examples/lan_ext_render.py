#!/usr/bin/env python3

import ipaddress
import jinja2
import json
import sys


def render_dhcp6_class_efi(subnet: ipaddress.IPv6Network):
    return {
        'name': 'lan_EFI-BC',
        'test': 'option[client-arch-type].hex == 0x0007',
        'only-if-required': True,
        'option-data': [
            # d2:23:80:ac:10:43 - storage
            {'name': 'bootfile-url', 'data': 'tftp://[%s]/boot/grub/x86_64-efi/core.efi' % str(subnet[0xd02380fffeac1043])},
        ]
    }

def render_dhcp6_class_rpi4(subnet: ipaddress.IPv6Network):
    return {
        'name': 'lan_RPi4',
        'test': 'option[client-arch-type].hex == 0x0029',
        'only-if-required': True,
        'option-data': [
            # d2:23:80:ac:10:43 - storage
            {'name': 'bootfile-url', 'data': 'tftp://[%s]/' % str(subnet[0xd02380fffeac1043])},
        ]
    }


def render_dhcp6_subnet(subnet: ipaddress.IPv6Network):
    return {
        'subnet': str(subnet),
        'pools': [{'pool': '%s-%s' % (subnet[0x1001], subnet[0x1fff])}],
        'interface': 'lan',
        'require-client-classes': ['lan_EFI-BC', 'lan_RPi4'],
        #'reservations': [
        #    {
        #        "hw-address": "d2:23:80:ac:10:43", "ip-addresses": [str(subnet[3])],
        #        "user-context": {"name": "storage"}
        #    },
        #]
    }


def render_radvd(subnet: ipaddress.IPv6Network) -> str:
    empty = '''
interface lan {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;

    route ::/0 {
    };
};
'''
    template = '''
interface lan {
    AdvSendAdvert on;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;

    prefix {{ prefix }} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
        AdvPreferredLifetime 3600;
        AdvValidLifetime 7200;
    };
    route ::/0 {
    };
    RDNSS {{ rdnss }} {
    };
};
'''
    if subnet is not None:
        return jinja2.Template(template).render({'prefix': str(subnet), 'rdnss': str(subnet[1])})
    else:
        return empty


if __name__ == '__main__':
    if len(sys.argv) < 2:
        # empty configs
        with open('lan_radvd.conf', 'wt') as f:
            f.write(render_radvd(None))
        with open('lan_dhcp6_classes.json', 'wt') as f:
            f.truncate()
        with open('lan_dhcp6_subnet.json', 'wt') as f:
            f.truncate()
    else:
        subnet = ipaddress.IPv6Network(sys.argv[1])
        with open('lan_radvd.conf', 'wt') as f:
            f.write(render_radvd(subnet))
        with open('lan_dhcp6_classes.json', 'wt') as f:
            f.write(json.dumps(render_dhcp6_class_efi(subnet)) + ',')  # add extra comma to allow seamless JSON include
            f.write(json.dumps(render_dhcp6_class_rpi4(subnet)) + ',')  # add extra comma to allow seamless JSON include
        with open('lan_dhcp6_subnet.json', 'wt') as f:
            f.write(json.dumps(render_dhcp6_subnet(subnet)) + ',')  # add extra comma to allow seamless JSON include

