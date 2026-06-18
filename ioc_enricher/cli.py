import argparse
import json
import sys

from ioc_enricher import __version__
from ioc_enricher.cache import Cache
from ioc_enricher.config import ENV_KEYS, Config, load_dotenv
from ioc_enricher.context import InternalContext
from ioc_enricher.engine import REGISTRY, Engine
from ioc_enricher.history import HistoryStore
from ioc_enricher.ioc.extract import extract_iocs
from ioc_enricher.output import csv_out, json_out, jsonl_out, markdown, table

ALL_SOURCES = list(REGISTRY.names)


def build_parser():
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="enrich indicators of compromise from threat intel sources",
    )
    p.add_argument("ioc", nargs="?", help="a single ioc to enrich")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-i", "--input", help="file of iocs, one per line "
                   "(use - for stdin)")
    p.add_argument("--extract", help="extract IOCs from messy analyst text")
    p.add_argument("-f", "--format", choices=["table", "json", "jsonl", "csv"],
                   default="table")
    p.add_argument("-o", "--output", help="write rendered output to this file")
    p.add_argument("--report", choices=["markdown"],
                   help="render an investigation report")
    p.add_argument("-s", "--sources", help="comma separated subset of: "
                   + ",".join(ALL_SOURCES))
    p.add_argument("--no-cache", action="store_true", help="skip the cache")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print malicious/suspicious verdicts")
    p.add_argument("--context", action="append",
                   help="JSON file with allowlist, blocklist, business_domains, cidrs")
    p.add_argument("--asset-inventory", help="CSV asset inventory")
    p.add_argument("--max-iocs", type=int, help="maximum IOCs to process")
    p.add_argument("--fail-soft", action="store_true",
                   help="exit 0 even when sources error")
    p.add_argument("--fail-on-malicious", action="store_true",
                   help="exit 2 when any IOC is malicious")
    p.add_argument("--provider-status", action="store_true",
                   help="show enabled provider capabilities and exit")
    p.add_argument("--config-diagnostics", action="store_true",
                   help="show safe configuration readiness diagnostics and exit")
    p.add_argument("--explain", action="store_true",
                   help="render only scoring evidence and decision details as JSON")
    p.add_argument("--history", nargs="?", const="",
                   help="show enrichment history, optionally for one IOC")
    p.add_argument("--history-limit", type=int, default=50,
                   help="maximum history rows to return (default: 50)")
    return p


def _sources_arg(value):
    if not value:
        return None
    picked = [s.strip() for s in value.split(",") if s.strip()]
    bad = [s for s in picked if s not in ALL_SOURCES]
    if bad:
        raise SystemExit(f"unknown source(s): {', '.join(bad)}")
    return picked


def read_iocs(args):
    if args.extract:
        text = sys.stdin.read() if args.extract == "-" else open(args.extract).read()
        extracted = extract_iocs(text)
        return [(e.normalized, e.to_dict()) for e in extracted]

    if args.input == "-":
        lines = sys.stdin.read().splitlines()
    elif args.input:
        with open(args.input) as fh:
            lines = fh.read().splitlines()
    else:
        return [args.ioc] if args.ioc else []

    out = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def render(results, fmt, report=None, summary=None):
    if report == "markdown":
        return markdown.render(results, summary=summary)
    if fmt == "json":
        return json_out.render(results)
    if fmt == "jsonl":
        return jsonl_out.render(results)
    if fmt == "csv":
        return csv_out.render(results)
    return table.render(results)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)

    load_dotenv()
    config = Config.load()
    if args.provider_status:
        status = Engine(config, cache=None).provider_status()
        print(json.dumps({"providers": status}, indent=2))
        return 0
    if args.config_diagnostics:
        status = Engine(config, cache=None).provider_status()
        print(json.dumps(_config_diagnostics(config, status), indent=2))
        return 0
    if args.history is not None:
        store = HistoryStore()
        entries = store.list_enrichments(
            ioc=args.history or None, limit=args.history_limit
        )
        print(json.dumps({"history": entries}, indent=2))
        return 0

    iocs = read_iocs(args)
    total_seen = len(iocs)
    if args.max_iocs is not None:
        iocs = iocs[:args.max_iocs]
    if not iocs:
        build_parser().print_help()
        return 1

    cache = None if args.no_cache else Cache(ttl=config.cache_ttl)

    internal_context = InternalContext.from_files(
        paths=args.context,
        asset_inventory=args.asset_inventory,
    )
    engine = Engine(
        config,
        cache=cache,
        sources=_sources_arg(args.sources),
        internal_context=internal_context,
        history=HistoryStore(),
    )
    if len(iocs) == 1:
        item = iocs[0]
        if isinstance(item, tuple):
            results = [engine.enrich(item[0], source_context=item[1])]
        else:
            results = [engine.enrich(item)]
    else:
        def progress(done, total, ioc):
            print(f"[{done}/{total}] enriched {ioc}", file=sys.stderr)
        results = engine.enrich_many(iocs, progress=progress)

    if args.quiet:
        results = [r for r in results
                   if r.verdict in ("malicious", "suspicious")]

    summary = _batch_summary(iocs, results, total_seen)
    _print_batch_summary(summary)
    rendered = _render_explanations(results) if args.explain else render(
        results, args.format, report=args.report, summary=summary
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(rendered)
            output.write("\n")
    else:
        print(rendered)

    if args.fail_on_malicious and any(r.verdict == "malicious" for r in results):
        return 2
    if not args.fail_soft and any(r.errors for r in results):
        return 1
    return 0


def _batch_summary(iocs, results, total_seen):
    unique_seen: dict[str, int] = {}
    for item in iocs:
        ioc = item[0] if isinstance(item, tuple) else item
        unique_seen.setdefault(ioc, 0)
        unique_seen[ioc] += 1
    errors: dict[str, int] = {}
    for r in results:
        for err in r.errors:
            errors[err["source"]] = errors.get(err["source"], 0) + 1
    return {
        "input_count": total_seen,
        "processed_count": len(iocs),
        "unique_count": len(results),
        "duplicates": sum(v - 1 for v in unique_seen.values()),
        "source_errors": errors,
    }


def _print_batch_summary(summary):
    if summary["processed_count"] <= 1:
        return
    print(
        "batch: "
        f"{summary['processed_count']} input, "
        f"{summary['unique_count']} unique, "
        f"{summary['duplicates']} duplicate(s)",
        file=sys.stderr,
    )
    if summary["source_errors"]:
        details = ", ".join(f"{k}={v}" for k, v in summary["source_errors"].items())
        print(f"source errors: {details}", file=sys.stderr)


def _config_diagnostics(config, providers):
    """Return configuration state without exposing provider credentials."""
    return {
        "cache_ttl_seconds": config.cache_ttl,
        "providers": [
            {
                **provider,
                "credential_environment_variable": ENV_KEYS.get(provider["name"]),
            }
            for provider in providers
        ],
    }


def _render_explanations(results):
    fields = (
        "ioc", "ioc_type", "scoring_version", "score", "verdict", "confidence",
        "evidence", "counter_evidence", "no_data", "errors", "reason_codes",
        "recommended_action",
    )
    return json.dumps(
        {"explanations": [{field: result.to_dict()[field] for field in fields} for result in results]},
        indent=2,
    )


if __name__ == "__main__":
    raise SystemExit(main())
