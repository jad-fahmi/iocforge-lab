import ipaddress

from ioc_enricher.ioc.types import IocType


def _try_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IocType.IPV4 if ip.version == 4 else IocType.IPV6


def detect(value):
    value = value.strip()
    ip = _try_ip(value)
    if ip:
        return ip
    return IocType.UNKNOWN
