import json
import os
from pathlib import Path

DEFAULT_PATH = Path.home() / ".config" / "iocforge-lab" / "config.json"

# maps a source name to the env var holding its api key
ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "otx": "OTX_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "urlhaus": "URLHAUS_API_KEY",
}


def load_dotenv(path=".env"):
    """tiny .env reader so we don't pull in a dependency for this."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k and k not in os.environ:
            os.environ[k] = v


class Config:
    def __init__(self, keys=None, cache_ttl=3600, providers=None):
        self.keys = keys or {}
        self.cache_ttl = cache_ttl
        # A provider omitted from configuration remains enabled.  This keeps
        # existing installations working while allowing explicit opt-out.
        self.providers = providers or {}

    def key_for(self, source):
        return self.keys.get(source)

    def provider_enabled(self, source):
        return self.providers.get(source, {}).get("enabled", True)

    @classmethod
    def load(cls, path=None):
        keys = {}
        providers = {}
        path = Path(path) if path else DEFAULT_PATH
        if path.exists():
            data = json.loads(path.read_text())
            keys.update(data.get("keys", {}))
            providers.update(data.get("providers", {}))

        # env always wins over the file
        for source, env in ENV_KEYS.items():
            val = os.environ.get(env)
            if val:
                keys[source] = val

        ttl = int(os.environ.get("IOC_CACHE_TTL", "3600"))
        return cls(keys=keys, cache_ttl=ttl, providers=providers)
