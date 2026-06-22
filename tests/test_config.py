import json

from ioc_enricher.config import Config


def test_config_loads_scheduler_and_provider_policies(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "scheduler": {
                    "max_concurrency": 4,
                    "max_pending": 12,
                    "include_optional": False,
                },
                "providers": {
                    "virustotal": {
                        "priority": 10,
                        "concurrency": 2,
                        "requests_per_window": 20,
                        "window_seconds": 60,
                        "timeout_seconds": 8,
                        "retries": 3,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("IOC_CACHE_TTL", raising=False)

    config = Config.load(path)

    assert config.scheduler == {
        "max_concurrency": 4,
        "max_pending": 12,
        "include_optional": False,
    }
    assert config.providers["virustotal"]["requests_per_window"] == 20
    assert config.providers["virustotal"]["retries"] == 3
