import os
import sys

RESET = "\033[0m"
COLORS = {
    "malicious": "\033[31m",  # red
    "suspicious": "\033[33m",  # yellow
    "low": "\033[36m",  # cyan
    "clean": "\033[32m",  # green
    "unknown": "\033[90m",  # grey
}


def enabled():
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def paint(text, verdict):
    if not enabled():
        return text
    code = COLORS.get(verdict, "")
    if not code:
        return text
    return f"{code}{text}{RESET}"
