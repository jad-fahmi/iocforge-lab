import argparse
import sys

from ioc_enricher.cache import Cache
from ioc_enricher.config import Config, load_dotenv
from ioc_enricher.engine import REGISTRY, Engine
from ioc_enricher.output import csv_out, json_out, table

ALL_SOURCES = [c.name for c in REGISTRY]


def build_parser():
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="enrich indicators of compromise from threat intel sources",
    )
    p.add_argument("ioc", nargs="?", help="a single ioc to enrich")
    p.add_argument("-i", "--input", help="file of iocs, one per line "
                   "(use - for stdin)")
    p.add_argument("-f", "--format", choices=["table", "json", "csv"],
                   default="table")
    p.add_argument("-s", "--sources", help="comma separated subset of: "
                   + ",".join(ALL_SOURCES))
    p.add_argument("--no-cache", action="store_true", help="skip the cache")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="only print malicious/suspicious verdicts")
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


def render(results, fmt):
    if fmt == "json":
        return json_out.render(results)
    if fmt == "csv":
        return csv_out.render(results)
    return table.render(results)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)

    iocs = read_iocs(args)
    if not iocs:
        build_parser().print_help()
        return 1

    load_dotenv()
    config = Config.load()
    cache = None if args.no_cache else Cache(ttl=config.cache_ttl)

    engine = Engine(config, cache=cache, sources=_sources_arg(args.sources))
    if len(iocs) == 1:
        results = [engine.enrich(iocs[0])]
    else:
        results = engine.enrich_many(iocs)

    if args.quiet:
        results = [r for r in results
                   if r.verdict in ("malicious", "suspicious")]

    print(render(results, args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
