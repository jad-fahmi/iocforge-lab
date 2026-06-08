import json


def render(results, indent=2):
    """results is a list of EnrichmentResult."""
    payload = [r.to_dict() for r in results]
    if len(payload) == 1:
        payload = payload[0]
    return json.dumps(payload, indent=indent)
