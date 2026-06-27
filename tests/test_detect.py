from ioc_enricher.ioc.detect import detect, normalize
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


def test_sha512():
    h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    h += "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    assert detect(h) == IocType.SHA512


def test_uppercase_hash():
    assert detect("D41D8CD98F00B204E9800998ECF8427E") == IocType.MD5


def test_defanged_domain():
    assert detect("evil-domain[.]com") == IocType.DOMAIN


def test_unicode_domain_is_detected_and_normalized_to_idna():
    domain = "bücher.example"

    assert detect(domain) == IocType.DOMAIN
    assert normalize(domain, IocType.DOMAIN) == "xn--bcher-kva.example"


def test_idna_normalization_does_not_merge_sharp_s_with_ascii_ss():
    unicode_domain = "faß.de"
    ascii_domain = "fass.de"

    assert detect(unicode_domain) == IocType.DOMAIN
    assert normalize(unicode_domain, IocType.DOMAIN) == "xn--fa-hia.de"
    assert normalize(unicode_domain, IocType.DOMAIN) != normalize(
        ascii_domain, IocType.DOMAIN
    )


def test_uts46_maps_ideographic_dot_and_fullwidth_ascii():
    domain = "ＥＸＡＭＰＬＥ。com"

    assert detect(domain) == IocType.DOMAIN
    assert normalize(domain, IocType.DOMAIN) == "example.com"


def test_url_host_is_normalized_without_changing_case_sensitive_path():
    url = "HTTPS://BÜCHER.example/CaseSensitive?Key=Value"

    assert detect(url) == IocType.URL
    assert (
        normalize(url, IocType.URL)
        == "https://xn--bcher-kva.example/CaseSensitive?Key=Value"
    )


def test_malformed_url_and_invalid_unicode_email_are_unknown_not_exceptions():
    assert detect("https://[not-an-ipv6") == IocType.UNKNOWN
    assert detect("analyst@\ud800.example") == IocType.UNKNOWN


def test_unknown():
    assert detect("not an ioc") == IocType.UNKNOWN
