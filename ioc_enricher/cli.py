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
    p.add_argument("-f", "--format", choices=["table", "json", "csv"],
                   default="table")
    p.add_argument("-s", "--sources", help="comma separated subset of: "
                   + ",".join(ALL_SOURCES))
    p.add_argument("--no-cache", action="store_true", help="skip the cache")
    return p


def _sources_arg(value):
    if not value:
        return None
    picked = [s.strip() for s in value.split(",") if s.strip()]
    bad = [s for s in picked if s not in ALL_SOURCES]
    if bad:
        raise SystemExit(f"unknown source(s): {', '.join(bad)}")
    return picked


def render(results, fmt):
    if fmt == "json":
        return json_out.render(results)
    if fmt == "csv":
        return csv_out.render(results)
    return table.render(results)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = build_parser().parse_args(argv)

    if not args.ioc:
        build_parser().print_help()
        return 1

    load_dotenv()
    config = Config.load()
    cache = None if args.no_cache else Cache(ttl=config.cache_ttl)

    engine = Engine(config, cache=cache, sources=_sources_arg(args.sources))
    results = [engine.enrich(args.ioc)]

    print(render(results, args.format))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
