import typing
import jinja2


template = '''
interface {{ iface }} {
    AdvSendAdvert on;
    {% for prefix in prefixes %}
    prefix {{ prefix['subnet'] }} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
        AdvPreferredLifetime {{ prefix['preferred_life'] }};
        AdvValidLifetime {{ prefix['max_life'] }};
    };
    {% endfor %}
    {% if rdnss|len > 0 %}
    rdnss {% for rdnss_item in rndss %}{{rdnss_item}} {% endfor %}{
    };
    {% endif %}
};
'''


def build(iface: str, prefixes: typing.Iterable[typing.Dict], rdnss: typing.Iterable[str]) -> str:
    return jinja2.Template(template).render({'iface': iface, 'prefixes': prefixes, 'rndss': rdnss})
