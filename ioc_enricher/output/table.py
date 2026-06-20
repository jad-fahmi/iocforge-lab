from ioc_enricher.output.color import paint


def _row(cols, widths):
    return "  ".join(str(c).ljust(w) for c, w in zip(cols, widths, strict=True))


def render(results):
    lines = []
    for r in results:
        head = (
            f"{r.ioc}  [{r.ioc_type.value}]  ->  "
            f"{r.verdict} ({r.score}, {r.confidence})"
        )
        lines.append(paint(head, r.verdict))
        if r.reason_codes:
            lines.append("  reasons: " + ", ".join(r.reason_codes))
        lines.append("  action: " + r.recommended_action)

        rows = []
        for s in r.sources:
            status = s.error or ("hit" if s.found else "no data")
            mal = "" if s.malicious is None else ("mal" if s.malicious else "ok")
            rows.append([s.source, status, mal, "" if s.score is None else s.score])

        if rows:
            headers = ["source", "status", "flag", "score"]
            widths = [
                max(len(str(row[i])) for row in rows + [headers]) for i in range(4)
            ]
            lines.append("  " + _row(headers, widths))
            for row in rows:
                lines.append("  " + _row(row, widths))
        lines.append("")

    return "\n".join(lines).rstrip()
