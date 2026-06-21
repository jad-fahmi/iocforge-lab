import pytest
from ioc_enricher import cli
from ioc_enricher.ioc.types import IocType
from ioc_enricher.models import EnrichmentResult


class FakeEngine:
    def __init__(self, *_args, **_kwargs):
        pass

    def enrich(self, ioc, source_context=None):
        return EnrichmentResult(ioc=ioc, ioc_type=IocType.DOMAIN)

    def provider_status(self):
        return [{"name": "rdap", "available": True}]


class FakeHistory:
    def list_enrichments(self, ioc=None, limit=50):
        return [{"ioc": ioc, "limit": limit}]

    def replay_enrichment(self, enrichment_id):
        return {"enrichment_id": enrichment_id, "replayable": True}

    def compare_enrichments(self, baseline_id, comparison_id):
        return {"baseline": baseline_id, "comparison": comparison_id}


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--version"])

    assert error.value.code == 0
    assert "ioc-enrich 0.1.0" in capsys.readouterr().out


def test_cli_writes_output_file(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(cli, "Engine", FakeEngine)
    destination = tmp_path / "result.json"

    assert cli.main(["example.com", "-f", "json", "-o", str(destination)]) == 0

    assert '"ioc": "example.com"' in destination.read_text()
    assert capsys.readouterr().out == ""


def test_cli_explain_renders_scoring_decision(monkeypatch, capsys):
    monkeypatch.setattr(cli, "Engine", FakeEngine)

    assert cli.main(["example.com", "--explain"]) == 0

    rendered = capsys.readouterr().out
    assert '"explanations"' in rendered
    assert '"recommended_action"' in rendered


def test_cli_provider_status_does_not_need_an_ioc(monkeypatch, capsys):
    monkeypatch.setattr(cli, "Engine", FakeEngine)

    assert cli.main(["--provider-status"]) == 0

    assert '"rdap"' in capsys.readouterr().out


def test_cli_config_diagnostics_never_prints_credentials(monkeypatch, capsys):
    monkeypatch.setattr(cli, "Engine", FakeEngine)

    assert cli.main(["--config-diagnostics"]) == 0

    output = capsys.readouterr().out
    assert '"cache_ttl_seconds"' in output
    assert '"credential_environment_variable"' in output
    assert "VT_API_KEY" not in output


def test_cli_history_query_does_not_enrich(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(["--history", "example.com", "--history-limit", "3"]) == 0

    assert '"ioc": "example.com"' in capsys.readouterr().out


def test_cli_replays_enrichment_by_history_id(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(["--replay", "17"]) == 0

    assert '"enrichment_id": 17' in capsys.readouterr().out


def test_cli_compares_two_enrichment_history_ids(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(["--compare", "17", "21"]) == 0

    output = capsys.readouterr().out
    assert '"baseline": 17' in output
    assert '"comparison": 21' in output


@pytest.mark.parametrize(
    ("arguments", "expected_level"),
    [
        (["--provider-status", "--verbose"], "INFO"),
        (["--provider-status", "--debug"], "DEBUG"),
    ],
)
def test_cli_verbosity_selects_operational_log_level(
    monkeypatch, capsys, arguments, expected_level
):
    selected = []
    monkeypatch.setattr(cli, "Engine", FakeEngine)
    monkeypatch.setattr(cli, "setup", selected.append)

    assert cli.main(arguments) == 0

    assert selected == [expected_level]
