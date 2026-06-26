"""Bounded, single-process dispatch for provider lookups."""

import math
from collections import deque
from concurrent.futures import Future
from threading import BoundedSemaphore, Condition, Thread
from time import monotonic
from typing import Any, Callable, Iterable


class EnrichmentScheduler:
    """Apply engine-local concurrency, quota, priority, and backpressure rules.

    Provider configuration supports ``priority`` (higher runs first),
    ``optional`` (skipped when optional sources are disabled), ``concurrency``,
    ``requests_per_window``, and ``window_seconds``. A bounded global queue
    orders pending work across concurrent lookups by provider priority.
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
        self._pending = BoundedSemaphore(self.max_pending)
        self._condition = Condition()
        self._queue: list[dict[str, Any]] = []
        self._sequence = 0
        self._active_by_provider: dict[str, int] = {}
        self._provider_limits: dict[str, int] = {}
        self._starts: dict[str, deque[float]] = {}
        self._rate_lock = Condition()
        self._shutdown = False
        self._workers = [
            Thread(
                target=self._worker,
                name=f"iocforge-scheduler-{index + 1}",
                daemon=True,
            )
            for index in range(self.max_concurrency)
        ]
        self._validate_provider_policies()
        self._workers_started = False

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
        """Queue connectors; callers block when all in-flight capacity is used."""
        should_include_optional = (
            self.include_optional if include_optional is None else include_optional
        )
        if not isinstance(should_include_optional, bool):
            raise ValueError("include_optional must be boolean")
        futures: dict[Any, Future[Any]] = {}
        ordered = sorted(
            enumerate(connectors),
            key=lambda pair: (
                -self._priority(pair[1].name),
                self.optional(pair[1].name),
                pair[0],
            ),
        )
        for _, connector in ordered:
            name = connector.name
            optional = self.optional(name)
            if optional and not should_include_optional:
                continue
            future: Future[Any] = Future()
            self._pending.acquire()
            with self._condition:
                if self._shutdown:
                    self._pending.release()
                    raise RuntimeError("cannot schedule work after shutdown")
                if not self._workers_started:
                    for worker in self._workers:
                        worker.start()
                    self._workers_started = True
                self._sequence += 1
                self._queue.append(
                    {
                        "priority": self._priority(name),
                        "optional": optional,
                        "sequence": self._sequence,
                        "connector": connector,
                        "task": task,
                        "future": future,
                    }
                )
                self._condition.notify_all()
            futures[connector] = future
        return futures

    def shutdown(self, wait=True):
        """Stop accepting work and optionally wait for queued tasks to finish."""
        with self._condition:
            self._shutdown = True
            self._condition.notify_all()
        if wait and self._workers_started:
            for worker in self._workers:
                worker.join()

    def admit_request(self, source: str) -> None:
        """Block until a provider request fits its configured sliding window."""
        self._admit_rate(source)

    def _priority(self, source):
        value = self.providers.get(source, {}).get("priority", 0)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"providers.{source}.priority must be an integer")
        return value

    def _validate_provider_policies(self):
        for source, policy in self.providers.items():
            self._priority(source)
            self.optional(source)
            self._provider_limits[source] = _positive_int(
                policy.get("concurrency", self.max_concurrency),
                f"providers.{source}.concurrency",
            )
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

    def _provider_limit(self, source):
        return self._provider_limits.get(source, self.max_concurrency)

    def _next_eligible(self):
        eligible = [
            (index, item)
            for index, item in enumerate(self._queue)
            if self._active_by_provider.get(item["connector"].name, 0)
            < self._provider_limit(item["connector"].name)
        ]
        if not eligible:
            return None
        index, item = min(
            eligible,
            key=lambda pair: (
                -pair[1]["priority"],
                pair[1]["optional"],
                pair[1]["sequence"],
            ),
        )
        self._queue.pop(index)
        return item

    def _worker(self):
        while True:
            with self._condition:
                item = None
                while item is None:
                    cancelled = [
                        index
                        for index, queued in enumerate(self._queue)
                        if queued["future"].cancelled()
                    ]
                    for index in reversed(cancelled):
                        self._queue.pop(index)
                        self._pending.release()
                    item = self._next_eligible()
                    if item is not None:
                        if not item["future"].set_running_or_notify_cancel():
                            self._pending.release()
                            item = None
                            continue
                        name = item["connector"].name
                        self._active_by_provider[name] = (
                            self._active_by_provider.get(name, 0) + 1
                        )
                        break
                    if self._shutdown and not self._queue:
                        return
                    self._condition.wait()

            try:
                result = item["task"](item["connector"])
            except BaseException as error:
                item["future"].set_exception(error)
            else:
                item["future"].set_result(result)
            finally:
                with self._condition:
                    name = item["connector"].name
                    self._active_by_provider[name] -= 1
                    self._pending.release()
                    self._condition.notify_all()

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
        while True:
            with self._rate_lock:
                starts = self._starts.setdefault(source, deque())
                now = monotonic()
                while starts and starts[0] <= now - window:
                    starts.popleft()
                if len(starts) < count:
                    starts.append(now)
                    return
                wait = starts[0] + window - now
                self._rate_lock.wait(timeout=max(wait, 0.001))


def _positive_int(value, setting):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{setting} must be a positive integer")
    return value
