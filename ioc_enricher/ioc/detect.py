import ipaddress
import re
from urllib.parse import urlparse

from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.types import IocType

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _try_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IocType.IPV4 if ip.version == 4 else IocType.IPV6


def _looks_like_url(value):
    if "://" not in value:
        return False
    parsed = urlparse(value)
    return bool(parsed.scheme and parsed.netloc)


def _looks_like_domain(value):
    return bool(DOMAIN_RE.match(value))


def _try_hash(value):
    if MD5_RE.match(value):
        return IocType.MD5
    if SHA1_RE.match(value):
        return IocType.SHA1
    if SHA256_RE.match(value):
        return IocType.SHA256
    return None


def detect(value):
    value = refang(value.strip())

    ip = _try_ip(value)
    if ip:
        return ip

    h = _try_hash(value)
    if h:
        return h

    if _looks_like_url(value):
        return IocType.URL

    if _looks_like_domain(value):
        return IocType.DOMAIN

    return IocType.UNKNOWN
