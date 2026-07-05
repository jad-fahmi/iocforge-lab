"""turn a bunch of source results into a single verdict."""

# how much we trust each source when it flags something
WEIGHTS = {
    "virustotal": 1.0,
    "abuseipdb": 0.8,
    "otx": 0.7,
    "greynoise": 0.6,
    "shodan": 0.0,  # informational only
}


def score(result):
    num = 0.0
    denom = 0.0
    for s in result.sources:
        if s.error or not s.found:
            continue
        w = WEIGHTS.get(s.source, 0.5)
        if w == 0:
            continue
        denom += w
        if s.malicious:
            contrib = s.score if s.score is not None else 1.0
            num += w * contrib

    final = round(num / denom, 3) if denom else 0.0
    return final, verdict_for(final)


def verdict_for(value):
    if value >= 0.6:
        return "malicious"
    if value >= 0.25:
        return "suspicious"
    if value > 0:
        return "low"
    return "clean"
