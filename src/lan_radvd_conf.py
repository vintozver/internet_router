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
    route ::/0 {
    };
    {% if rdnss|length > 0 %}
    RDNSS {% for rdnss_item in rdnss %}{{rdnss_item}} {% endfor %}{
    };
    {% endif %}
};
'''


def build(iface: str, prefixes: typing.Iterable[typing.Dict], rdnss: typing.Iterable[str]) -> str:
    return jinja2.Template(template).render({'iface': iface, 'prefixes': prefixes, 'rdnss': rdnss})
