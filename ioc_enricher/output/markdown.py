def render(results, summary=None):
    lines = ["# IOC Investigation Report", ""]
    counts = _counts(results)
    lines.extend([
        "## Executive summary",
        "",
        f"Analyzed {len(results)} unique IOCs. Verdicts: "
        + ", ".join(f"{k}: {v}" for k, v in counts.items() if v),
        "",
    ])
    if summary:
        lines.extend([
            f"Deduplicated {summary.get('duplicates', 0)} repeated IOC(s).",
            "",
        ])

    lines.extend(["## IOC table", "", "| IOC | Type | Verdict | Confidence | Reasons |", "|---|---|---|---|---|"])
    for r in results:
        lines.append(
            f"| `{r.ioc}` | {r.ioc_type.value} | {r.verdict} | "
            f"{r.confidence} | {', '.join(r.reason_codes) or '-'} |"
        )
    lines.append("")

    high = [r for r in results if r.verdict in ("malicious", "suspicious")]
    lines.extend(["## High-risk findings", ""])
    if high:
        for r in high:
            lines.append(f"- `{r.ioc}`: {r.verdict} ({r.confidence}). {r.recommended_action}")
    else:
        lines.append("No malicious or suspicious IOCs were identified.")
    lines.append("")

    lines.extend(["## Source evidence", ""])
    for r in results:
        lines.append(f"### `{r.ioc}`")
        if r.source_context:
            lines.append(
                f"Extracted from line {r.source_context.get('line_number')}: "
                f"{r.source_context.get('context')}"
            )
        for item in r.evidence:
            lines.append(f"- Evidence: {item['source']} - {item['summary']}")
        for item in r.counter_evidence:
            lines.append(f"- Counter-evidence: {item['source']} - {item['summary']}")
        if r.no_data:
            lines.append(f"- No data: {', '.join(r.no_data)}")
        if r.errors:
            lines.append("- Errors: " + ", ".join(f"{e['source']} ({e['error']})" for e in r.errors))
        lines.append("")

    lines.extend(["## Recommended next steps", ""])
    for r in results:
        lines.append(f"- `{r.ioc}`: {r.recommended_action}")
    lines.append("")

    lines.extend(["## Errors and blind spots", ""])
    errors = source_error_summary(results)
    if errors:
        for source, count in errors.items():
            lines.append(f"- {source}: {count} error(s)")
    else:
        lines.append("No source errors were reported.")
    return "\n".join(lines).rstrip()


def source_error_summary(results):
    counts = {}
    for r in results:
        for err in r.errors:
            counts[err["source"]] = counts.get(err["source"], 0) + 1
    return counts


def _counts(results):
    counts = {"malicious": 0, "suspicious": 0, "low": 0, "clean": 0}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    return counts
