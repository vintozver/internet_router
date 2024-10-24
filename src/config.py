import typing
import ipaddress
import configparser


class ComcastConfig(object):
    def __init__(self, wan_interface, lan_interface):
        self.wan_interface = wan_interface
        self.lan_interface = lan_interface


class CenturyLinkConfig(object):
    def __init__(self, link_interface, ppp_peer, wan_v4_interface, wan_v6_interface, lan_interface):
        self.ip6rd_subnet = ipaddress.IPv6Network('2602::/24')
        self.ip6rd_gateway = ipaddress.IPv6Address('::205.171.2.64')
        self.wan_v4_interface = wan_v4_interface
        self.wan_v6_interface = wan_v6_interface
        self.link_interface = link_interface
        self.ppp_peer = ppp_peer
        self.lan_interface = lan_interface


class ConfigException(Exception):
    pass


class Config(object):
    MODE_COMCAST = 'comcast'
    MODE_CENTURYLINK = 'centurylink'

    def __init__(self, mode, comcast: ComcastConfig = None, centurylink: CenturyLinkConfig = None):
        self.mode = mode
        if mode == self.MODE_COMCAST:
            self.comcast = comcast
        elif mode == self.MODE_CENTURYLINK:
            self.centurylink = centurylink
        else:
            raise ConfigException('Mode is unknown', mode)

    @classmethod
    def from_file(cls, f: typing.TextIO):
        try:
            cfg = configparser.ConfigParser()
            cfg.read_file(f)
            cfg_general = cfg['general']
            mode = cfg_general['mode']
            comcast = None
            centurylink = None
            if mode == cls.MODE_COMCAST:
                cfg_comcast = cfg[cls.MODE_COMCAST]
                comcast = ComcastConfig(
                    cfg_comcast['wan_interface'],
                    cfg_comcast['lan_interface'],
                )
            elif mode == cls.MODE_CENTURYLINK:
                cfg_centurylink = cfg[cls.MODE_CENTURYLINK]
                centurylink = CenturyLinkConfig(
                    cfg_centurylink['link_interface'],
                    cfg_centurylink['ppp_peer'],
                    cfg_centurylink['wan_v4_interface'],
                    cfg_centurylink['wan_v6_interface'],
                    cfg_centurylink['lan_interface'],
                )
            else:
                raise ConfigException('Mode is unknown', mode)
        except configparser.Error as err:
            raise ConfigException('Config parsing error', err)
        return Config(mode, comcast=comcast, centurylink=centurylink)
