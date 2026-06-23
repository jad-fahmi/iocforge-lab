from pathlib import Path

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

    def replay_investigation(self, investigation_id, as_of):
        return {
            "investigation_id": investigation_id,
            "as_of": as_of,
            "replayable": True,
        }

    def compare_investigations(self, investigation_id, baseline_as_of, comparison_as_of):
        return {
            "investigation_id": investigation_id,
            "baseline": baseline_as_of,
            "comparison": comparison_as_of,
        }

    def compare_enrichments(self, baseline_id, comparison_id):
        return {"baseline": baseline_id, "comparison": comparison_id}

    def suggest_pivots(self, ioc, limit=25, as_of=None, entity_type=None):
        return {
            "ioc": ioc,
            "limit": limit,
            "as_of": as_of,
            "entity_type": entity_type,
        }

    def suggest_pivot_paths(
        self, ioc, limit=25, max_depth=4, as_of=None, entity_type=None
    ):
        return {
            "ioc": ioc,
            "limit": limit,
            "max_depth": max_depth,
            "as_of": as_of,
            "entity_type": entity_type,
        }

    def close(self):
        pass


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


def test_cli_replays_investigation_at_requested_time(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(
        ["--replay-investigation", "7", "--as-of", "2026-01-01T00:00:00Z"]
    ) == 0

    output = capsys.readouterr().out
    assert '"investigation_id": 7' in output
    assert '"as_of": "2026-01-01T00:00:00Z"' in output


def test_cli_compares_investigation_at_two_times(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(
        [
            "--compare-investigations",
            "7",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert '"investigation_id": 7' in output
    assert '"baseline": "2026-01-01T00:00:00Z"' in output
    assert '"comparison": "2026-01-02T00:00:00Z"' in output


def test_cli_compares_two_enrichment_history_ids(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(["--compare", "17", "21"]) == 0

    output = capsys.readouterr().out
    assert '"baseline": 17' in output
    assert '"comparison": 21' in output


def test_cli_ranks_saved_graph_pivots(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(["--pivots", "evil.example", "--pivot-limit", "3"]) == 0

    output = capsys.readouterr().out
    assert '"ioc": "evil.example"' in output
    assert '"limit": 3' in output


def test_cli_ranks_bounded_multi_hop_pivot_paths(monkeypatch, capsys):
    monkeypatch.setattr(cli, "HistoryStore", FakeHistory)

    assert cli.main(
        ["--pivot-paths", "evil.example", "--pivot-depth", "4", "--pivot-limit", "3"]
    ) == 0

    output = capsys.readouterr().out
    assert '"ioc": "evil.example"' in output
    assert '"max_depth": 4' in output
    assert '"limit": 3' in output


def test_cli_evaluates_offline_fixture(capsys):
    fixture_path = Path(__file__).parent / "fixtures" / "provider-evaluation-v1.json"

    assert cli.main(["--evaluate-fixture", str(fixture_path)]) == 0

    output = capsys.readouterr().out
    assert '"methodology": "iocforge-provider-evaluation-v1"' in output
    assert '"balanced_accuracy": 0.75' in output


def test_cli_inspects_investigation_bundle_offline(monkeypatch, tmp_path, capsys):
    bundle_path = tmp_path / "case.iocforge"
    bundle_path.write_bytes(b"local bundle")
    monkeypatch.setattr(
        cli,
        "inspect_bundle",
        lambda _path, **_kwargs: {"investigation": {"title": "Offline case"}},
    )

    assert cli.main(["--bundle-inspect", str(bundle_path)]) == 0

    assert '"title": "Offline case"' in capsys.readouterr().out


def test_cli_replays_and_compares_bundle_investigation_offline(
    monkeypatch, tmp_path, capsys
):
    bundle_path = tmp_path / "case.iocforge"
    bundle_path.write_bytes(b"local bundle")

    def inspect(_path, **kwargs):
        return {"offline_times": kwargs}

    monkeypatch.setattr(cli, "inspect_bundle", inspect)
    assert cli.main(
        [
            "--bundle-inspect",
            str(bundle_path),
            "--bundle-as-of",
            "2026-01-01T00:00:00Z",
            "--bundle-compare-as-of",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
        ]
    ) == 0

    output = capsys.readouterr().out
    assert '"as_of": "2026-01-01T00:00:00Z"' in output
    assert '"comparison_as_of": "2026-01-02T00:00:00Z"' in output


def test_cli_exports_investigation_bundle(monkeypatch, tmp_path, capsys):
    destination = tmp_path / "case.iocforge"

    class BundleHistory:
        def investigation_bundle_payload(self, investigation_id):
            return {"investigation": {"id": investigation_id}}

        def close(self):
            pass

    monkeypatch.setattr(cli, "HistoryStore", BundleHistory)
    monkeypatch.setattr(cli, "build_bundle", lambda _payload: b"bundle bytes")

    assert cli.main(
        ["--bundle-export", "7", "--bundle-output", str(destination)]
    ) == 0

    assert destination.read_bytes() == b"bundle bytes"
    assert '"bytes": 12' in capsys.readouterr().out


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
