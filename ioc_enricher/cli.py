import argparse
import sys


def build_parser():
    p = argparse.ArgumentParser(
        prog="ioc-enrich",
        description="enrich indicators of compromise from threat intel sources",
    )
    p.add_argument("ioc", nargs="?", help="a single ioc to enrich")
    return p


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.ioc:
        parser.print_help()
        return 1

    print(f"got ioc: {args.ioc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
