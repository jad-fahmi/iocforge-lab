import json
import os
from pathlib import Path

DEFAULT_PATH = Path.home() / ".config" / "ioc-enricher" / "config.json"

# maps a source name to the env var holding its api key
ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
}


class Config:
    def __init__(self, keys=None, cache_ttl=3600):
        self.keys = keys or {}
        self.cache_ttl = cache_ttl

    def key_for(self, source):
        return self.keys.get(source)

    @classmethod
    def load(cls, path=None):
        keys = {}
        path = Path(path) if path else DEFAULT_PATH
        if path.exists():
            data = json.loads(path.read_text())
            keys.update(data.get("keys", {}))

        # env always wins over the file
        for source, env in ENV_KEYS.items():
            val = os.environ.get(env)
            if val:
                keys[source] = val

        ttl = int(os.environ.get("IOC_CACHE_TTL", "3600"))
        return cls(keys=keys, cache_ttl=ttl)
