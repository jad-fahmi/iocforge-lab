import re
from dataclasses import dataclass, asdict

from ioc_enricher.ioc.defang import refang
from ioc_enricher.ioc.detect import detect, normalize
from ioc_enricher.ioc.types import IocType


TOKEN_RE = re.compile(
    r"(?P<url>hxxps?://[^\s<>'\"]+|https?://[^\s<>'\"]+)|"
    r"(?P<email>[A-Z0-9._%+-]+(?:@|\[at\])[A-Z0-9.-]+(?:\.|\[\.\]|\(dot\)|\[dot\])[A-Z]{2,63})|"
    r"(?P<hash>\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b)|"
    r"(?P<cve>\bCVE-\d{4}-\d{4,}\b)|"
    r"(?P<asn>\bAS\d{1,10}\b)|"
    r"(?P<ip>\b(?:\d{1,3}(?:\.|\[\.\]|\(\.\)|\{\.\})\d{1,3}(?:\.|\[\.\]|\(\.\)|\{\.\})\d{1,3}(?:\.|\[\.\]|\(\.\)|\{\.\})\d{1,3})\b)|"
    r"(?P<domain>\b(?:[A-Z0-9-]+(?:\.|\[\.\]|\(\.\)|\[dot\])[A-Z0-9-]+(?:[A-Z0-9.-]|\[\.\]|\(dot\)|\[dot\])*)\b)",
    re.I,
)

TRAILING = ".,;:)]}>\"'"


@dataclass
class ExtractedIOC:
    value: str
    ioc_type: IocType
    original: str
    normalized: str
    line_number: int
    context: str

    def to_dict(self):
        data = asdict(self)
        data["ioc_type"] = self.ioc_type.value
        return data


def _clean(token):
    return token.strip().strip(TRAILING)


def _context(line, start, end, radius=80):
    left = max(0, start - radius)
    right = min(len(line), end + radius)
    return line[left:right].strip()


def extract_iocs(text):
    """Extract indicators from analyst text while preserving source context."""
    found = []
    seen = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in TOKEN_RE.finditer(line):
            original = _clean(match.group(0))
            if not original:
                continue
            refanged = refang(original)
            ioc_type = detect(refanged)
            if ioc_type == IocType.UNKNOWN:
                continue
            normalized = normalize(refanged, ioc_type)
            key = (normalized, ioc_type)
            if key in seen:
                continue
            seen.add(key)
            found.append(ExtractedIOC(
                value=normalized,
                ioc_type=ioc_type,
                original=original,
                normalized=normalized,
                line_number=line_number,
                context=_context(line, match.start(), match.end()),
            ))
    return found
