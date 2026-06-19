import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.types import IocType

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.I,
)

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
SHA512_RE = re.compile(r"^[a-fA-F0-9]{128}$")
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}$", re.I)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
ASN_RE = re.compile(r"^AS\d{1,10}$", re.I)


def _try_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IocType.IPV4 if ip.version == 4 else IocType.IPV6


def _looks_like_url(value):
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme and parsed.netloc and parsed.hostname)
    except ValueError:
        return False


def _looks_like_domain(value):
    try:
        return bool(DOMAIN_RE.match(_idna(value).rstrip(".")))
    except UnicodeError:
        return False


def _idna(value):
    """Return a lowercase ASCII IDNA hostname, rejecting invalid labels."""
    return value.encode("idna").decode("ascii").lower()


def _try_hash(value):
    if MD5_RE.match(value):
        return IocType.MD5
    if SHA1_RE.match(value):
        return IocType.SHA1
    if SHA256_RE.match(value):
        return IocType.SHA256
    if SHA512_RE.match(value):
        return IocType.SHA512
    return None


def detect(value):
    value = refang(value.strip())

    ip = _try_ip(value)
    if ip:
        return ip

    h = _try_hash(value)
    if h:
        return h

    if CVE_RE.match(value):
        return IocType.CVE

    if ASN_RE.match(value):
        return IocType.ASN

    if _looks_like_email(value):
        return IocType.EMAIL

    if _looks_like_url(value):
        return IocType.URL

    if _looks_like_domain(value):
        return IocType.DOMAIN

    return IocType.UNKNOWN


def _looks_like_email(value):
    local, separator, domain = value.rpartition("@")
    if not separator or not domain:
        return False
    try:
        return bool(EMAIL_RE.match(f"{local}@{_idna(domain)}"))
    except UnicodeError:
        return False


def normalize(value, ioc_type):
    """canonicalize an ioc so equivalent inputs share one cache key.

    Domains and hashes are case-insensitive; Unicode hostnames are converted to
    their IDNA ASCII form. URL paths and query strings remain untouched because
    they can be case-sensitive.
    """
    if ioc_type in (IocType.IPV4, IocType.IPV6):
        return str(ipaddress.ip_address(value))
    if ioc_type == IocType.DOMAIN:
        return _idna(value.rstrip("."))
    if ioc_type.is_hash():
        return value.lower()
    if ioc_type == IocType.EMAIL:
        local, _, domain = value.partition("@")
        return f"{local}@{_idna(domain)}"
    if ioc_type == IocType.URL:
        return _normalize_url(value)
    if ioc_type in (IocType.CVE, IocType.ASN):
        return value.upper()
    return value


def _normalize_url(value):
    parsed = urlsplit(value)
    host = parsed.hostname
    if not host:
        return value
    normalized_host = _idna(host)
    try:
        port = parsed.port
    except ValueError:
        return value
    credentials = ""
    if parsed.username is not None:
        credentials = parsed.username
        if parsed.password is not None:
            credentials += f":{parsed.password}"
        credentials += "@"
    if ":" in normalized_host and not normalized_host.startswith("["):
        normalized_host = f"[{normalized_host}]"
    netloc = f"{credentials}{normalized_host}"
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment))
