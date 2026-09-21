"""Newline-delimited JSON output for streaming enrichment results."""

import json


def render(results):
    return "\n".join(json.dumps(result.to_dict(), sort_keys=True) for result in results)
