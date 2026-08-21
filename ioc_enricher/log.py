import logging
import os

_configured = False


def setup(level=None):
    global _configured
    if _configured:
        return
    level = level or os.environ.get("IOC_LOG_LEVEL", "WARNING")
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _configured = True


def get(name):
    setup()
    return logging.getLogger(name)
