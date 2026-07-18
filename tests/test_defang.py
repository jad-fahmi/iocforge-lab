from ioc_enricher.ioc.defang import defang, refang


def test_refang_dot():
    assert refang("evil[.]com") == "evil.com"


def test_refang_hxxp():
    assert refang("hxxp://bad[.]site/x") == "http://bad.site/x"


def test_refang_dot_word():
    assert refang("evil[dot]com") == "evil.com"


def test_defang_roundish_trip():
    assert refang(defang("http://evil.com")) == "http://evil.com"
