import logging
import os

_configured = False


def setup(level=None):
    """Configure package logging and allow CLI callers to raise its level."""
    global _configured
    selected = level or os.environ.get("IOC_LOG_LEVEL", "WARNING")
    numeric_level = getattr(logging, selected.upper(), logging.WARNING)
    if _configured:
        if level is not None:
            logging.getLogger().setLevel(numeric_level)
        return
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _configured = True


def get(name):
    setup()
    return logging.getLogger(name)
