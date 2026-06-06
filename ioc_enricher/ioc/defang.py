import re

_REFANG_SUBS = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[at\]", re.I), "@"),
]


def refang(value):
    """turn a defanged ioc back into its real form."""
    out = value.strip()
    for pattern, repl in _REFANG_SUBS:
        out = pattern.sub(repl, out)
    return out


def defang(value):
    """make an ioc safe to paste into a report."""
    out = value.replace("http", "hxxp")
    out = out.replace(".", "[.]")
    out = out.replace("://", "[://]")
    return out
