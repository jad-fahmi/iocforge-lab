from enum import Enum


class IocType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"

    def is_hash(self):
        return self in (IocType.MD5, IocType.SHA1, IocType.SHA256)

    def is_network(self):
        return self in (IocType.IPV4, IocType.IPV6, IocType.DOMAIN, IocType.URL)
