from ioc_enricher.ioc.detect import detect
from ioc_enricher.ioc.types import IocType


def test_ipv4():
    assert detect("8.8.8.8") == IocType.IPV4


def test_ipv6():
    assert detect("2001:4860:4860::8888") == IocType.IPV6


def test_domain():
    assert detect("evil-domain.com") == IocType.DOMAIN


def test_url():
    assert detect("https://evil-domain.com/payload") == IocType.URL


def test_md5():
    assert detect("d41d8cd98f00b204e9800998ecf8427e") == IocType.MD5


def test_sha1():
    assert detect("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IocType.SHA1


def test_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert detect(h) == IocType.SHA256


def test_uppercase_hash():
    assert detect("D41D8CD98F00B204E9800998ECF8427E") == IocType.MD5


def test_defanged_domain():
    assert detect("evil-domain[.]com") == IocType.DOMAIN


def test_unknown():
    assert detect("not an ioc") == IocType.UNKNOWN
