"""Bounded, single-process dispatch for provider lookups."""

import math
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from threading import BoundedSemaphore, Lock
from time import monotonic, sleep
from typing import Any, Callable, Iterable


class EnrichmentScheduler:
    """Apply engine-local concurrency, quota, priority, and backpressure rules.

    Provider configuration supports ``priority`` (higher runs first),
    ``optional`` (skipped when optional sources are disabled),
    ``concurrency``, ``requests_per_window``, and ``window_seconds``. A bounded
    executor queue makes concurrent API and batch requests share one limit.
    """

    def __init__(self, settings=None, providers=None):
        settings = settings or {}
        self.providers = providers or {}
        if not isinstance(settings, dict):
            raise ValueError("scheduler settings must be an object")
        if not isinstance(self.providers, dict) or any(
            not isinstance(name, str) or not isinstance(policy, dict)
            for name, policy in self.providers.items()
        ):
            raise ValueError("provider settings must map names to objects")
        self.max_concurrency = _positive_int(
            settings.get("max_concurrency", 8), "scheduler.max_concurrency"
        )
        self.max_pending = _positive_int(
            settings.get("max_pending", self.max_concurrency * 4),
            "scheduler.max_pending",
        )
        self.include_optional = settings.get("include_optional", True)
        if not isinstance(self.include_optional, bool):
            raise ValueError("scheduler.include_optional must be boolean")
        self._executor = ThreadPoolExecutor(max_workers=self.max_concurrency)
        self._pending = BoundedSemaphore(self.max_pending)
        self._provider_slots: dict[str, BoundedSemaphore] = {}
        self._provider_locks: dict[str, Lock] = {}
        self._starts: dict[str, deque[float]] = {}
        self._state_lock = Lock()
        self._validate_provider_policies()

    def optional(self, source: str) -> bool:
        value = self.providers.get(source, {}).get("optional", False)
        if not isinstance(value, bool):
            raise ValueError(f"providers.{source}.optional must be boolean")
        return value

    def submit(
        self,
        connectors: Iterable[Any],
        task: Callable[[Any], Any],
        include_optional: bool | None = None,
    ) -> dict[Any, Future[Any]]:
        """Submit connectors in priority order, blocking callers when full."""
        should_include_optional = (
            self.include_optional if include_optional is None else include_optional
        )
        if not isinstance(should_include_optional, bool):
            raise ValueError("include_optional must be boolean")
        connectors = list(connectors)
        ordered = sorted(
            enumerate(connectors),
            key=lambda pair: (
                -self._priority(pair[1].name),
                self.optional(pair[1].name),
                pair[0],
            ),
        )
        futures: dict[Any, Future[Any]] = {}
        for _, connector in ordered:
            if self.optional(connector.name) and not should_include_optional:
                continue
            name = connector.name
            provider_slot = self._provider_slot(name)
            provider_slot.acquire()
            try:
                self._pending.acquire()
            except BaseException:
                provider_slot.release()
                raise
            try:
                future = self._executor.submit(task, connector)
            except BaseException:
                self._pending.release()
                provider_slot.release()
                raise
            def release(_future: Future[Any], slot=provider_slot) -> None:
                self._release(slot)

            future.add_done_callback(release)
            futures[connector] = future
        return futures

    def shutdown(self, wait=True):
        """Stop accepting scheduled work and optionally wait for active calls."""
        self._executor.shutdown(wait=wait)

    def _release(self, provider_slot):
        provider_slot.release()
        self._pending.release()

    def _priority(self, source):
        value = self.providers.get(source, {}).get("priority", 0)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"providers.{source}.priority must be an integer")
        return value

    def _validate_provider_policies(self):
        for source, policy in self.providers.items():
            self._priority(source)
            self.optional(source)
            self._provider_slot(source)
            count = policy.get("requests_per_window")
            if count is not None:
                _positive_int(count, f"providers.{source}.requests_per_window")
                window = policy.get("window_seconds", 60.0)
                if (
                    isinstance(window, bool)
                    or not isinstance(window, (int, float))
                    or not math.isfinite(window)
                    or window <= 0
                ):
                    raise ValueError(
                        f"providers.{source}.window_seconds must be positive"
                    )

    def admit_request(self, source: str) -> None:
        """Block until a provider request fits its configured sliding window."""
        self._admit_rate(source)

    def _provider_slot(self, source):
        with self._state_lock:
            slot = self._provider_slots.get(source)
            if slot is None:
                default = self.max_concurrency
                limit = _positive_int(
                    self.providers.get(source, {}).get("concurrency", default),
                    f"providers.{source}.concurrency",
                )
                slot = BoundedSemaphore(limit)
                self._provider_slots[source] = slot
            return slot

    def _admit_rate(self, source):
        provider = self.providers.get(source, {})
        count = provider.get("requests_per_window")
        if count is None:
            return
        count = _positive_int(count, f"providers.{source}.requests_per_window")
        window = provider.get("window_seconds", 60.0)
        if (
            isinstance(window, bool)
            or not isinstance(window, (int, float))
            or not math.isfinite(window)
            or window <= 0
        ):
            raise ValueError(f"providers.{source}.window_seconds must be positive")
        with self._state_lock:
            lock = self._provider_locks.setdefault(source, Lock())
            starts = self._starts.setdefault(source, deque())
        while True:
            with lock:
                now = monotonic()
                while starts and starts[0] <= now - window:
                    starts.popleft()
                if len(starts) < count:
                    starts.append(now)
                    return
                wait = starts[0] + window - now
            sleep(max(wait, 0.001))


def _positive_int(value, setting):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{setting} must be a positive integer")
    return value
