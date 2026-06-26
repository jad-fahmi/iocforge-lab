from threading import Event, Lock, Thread
from time import monotonic, sleep

import pytest
from ioc_enricher.scheduler import EnrichmentScheduler


class NamedConnector:
    def __init__(self, name):
        self.name = name


def _wait(futures):
    for future in futures.values():
        future.result()


def test_scheduler_applies_process_and_provider_concurrency_limits():
    scheduler = EnrichmentScheduler(
        settings={"max_concurrency": 3, "max_pending": 8},
        providers={"alpha": {"concurrency": 1}},
    )
    connectors = [NamedConnector("alpha") for _ in range(4)] + [
        NamedConnector(f"other-{index}") for index in range(4)
    ]
    guard = Lock()
    active_by_name = {}
    maximum_by_name = {}
    total_active = 0
    maximum_total = 0

    def task(connector):
        nonlocal total_active, maximum_total
        with guard:
            total_active += 1
            maximum_total = max(maximum_total, total_active)
            active_by_name[connector.name] = active_by_name.get(connector.name, 0) + 1
            maximum_by_name[connector.name] = max(
                maximum_by_name.get(connector.name, 0), active_by_name[connector.name]
            )
        sleep(0.015)
        with guard:
            total_active -= 1
            active_by_name[connector.name] -= 1

    try:
        futures = scheduler.submit(connectors, task)
        _wait(futures)
        assert maximum_total <= 3
        assert maximum_by_name["alpha"] == 1
    finally:
        scheduler.shutdown()


def test_scheduler_dispatches_by_priority_then_skips_disabled_optional_sources():
    scheduler = EnrichmentScheduler(
        settings={"max_concurrency": 1, "max_pending": 4, "include_optional": False},
        providers={
            "low": {"priority": 0},
            "high": {"priority": 10},
            "optional": {"priority": 100, "optional": True},
        },
    )
    order = []
    try:
        futures = scheduler.submit(
            [NamedConnector("low"), NamedConnector("optional"), NamedConnector("high")],
            lambda connector: order.append(connector.name),
        )
        _wait(futures)
        assert order == ["high", "low"]
        assert len(futures) == 2
    finally:
        scheduler.shutdown()


def test_scheduler_prioritizes_queued_work_across_concurrent_lookups():
    scheduler = EnrichmentScheduler(
        settings={"max_concurrency": 1, "max_pending": 4},
        providers={"blocker": {"priority": -1}, "low": {"priority": 0}, "high": {"priority": 10}},
    )
    entered = Event()
    release = Event()
    order = []
    try:
        running = scheduler.submit(
            [NamedConnector("blocker")],
            lambda _: (entered.set(), release.wait(timeout=2)),
        )
        assert entered.wait(timeout=1)
        low = scheduler.submit(
            [NamedConnector("low"), NamedConnector("low")],
            lambda connector: order.append(connector.name),
        )
        high = scheduler.submit(
            [NamedConnector("high")],
            lambda connector: order.append(connector.name),
        )

        release.set()
        _wait(running)
        _wait(low)
        _wait(high)

        assert order == ["high", "low", "low"]
    finally:
        release.set()
        scheduler.shutdown()


def test_scheduler_enforces_sliding_window_provider_quota():
    scheduler = EnrichmentScheduler(
        settings={"max_concurrency": 2, "max_pending": 2},
        providers={"limited": {"requests_per_window": 1, "window_seconds": 0.04}},
    )
    started = monotonic()
    try:
        futures = scheduler.submit(
            [NamedConnector("limited"), NamedConnector("limited")],
            lambda connector: scheduler.admit_request(connector.name),
        )
        _wait(futures)
        assert monotonic() - started >= 0.03
    finally:
        scheduler.shutdown()


def test_scheduler_applies_backpressure_at_pending_limit():
    scheduler = EnrichmentScheduler(settings={"max_concurrency": 1, "max_pending": 1})
    entered = Event()
    release = Event()
    second_returned = Event()

    def blocked_task(_connector):
        entered.set()
        release.wait(timeout=2)

    try:
        first = scheduler.submit([NamedConnector("first")], blocked_task)
        assert entered.wait(timeout=1)

        def submit_second():
            futures = scheduler.submit([NamedConnector("second")], lambda _: None)
            second_returned.set()
            _wait(futures)

        second = Thread(target=submit_second)
        second.start()
        assert not second_returned.wait(timeout=0.03)
        release.set()
        assert second_returned.wait(timeout=1)
        _wait(first)
        second.join(timeout=1)
        assert not second.is_alive()
    finally:
        release.set()
        scheduler.shutdown()


@pytest.mark.parametrize(
    "settings, providers",
    [
        ({"max_concurrency": 0}, {}),
        ({"include_optional": "no"}, {}),
        ({}, {"alpha": {"priority": 1.5}}),
        ({}, {"alpha": {"concurrency": 0}}),
        ({}, {"alpha": {"requests_per_window": 0}}),
    ],
)
def test_scheduler_rejects_invalid_policies(settings, providers):
    with pytest.raises(ValueError):
        scheduler = EnrichmentScheduler(settings=settings, providers=providers)
        try:
            scheduler.submit([NamedConnector("alpha")], lambda _: None)
        finally:
            scheduler.shutdown()
