import csv
import io

FIELDS = [
    "ioc",
    "ioc_type",
    "verdict",
    "score",
    "confidence",
    "reason_codes",
    "recommended_action",
    "source",
    "found",
    "malicious",
    "source_score",
    "error",
]


def render(results):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS)
    writer.writeheader()
    for r in results:
        for s in r.sources:
            writer.writerow(
                {
                    "ioc": r.ioc,
                    "ioc_type": r.ioc_type.value,
                    "verdict": r.verdict,
                    "score": r.score,
                    "confidence": r.confidence,
                    "reason_codes": ",".join(r.reason_codes),
                    "recommended_action": r.recommended_action,
                    "source": s.source,
                    "found": s.found,
                    "malicious": s.malicious,
                    "source_score": s.score,
                    "error": s.error or "",
                }
            )
    return buf.getvalue().rstrip("\r\n")
