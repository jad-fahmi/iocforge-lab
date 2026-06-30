from ioc_enricher.api.rate_limit import RateLimiter


def test_rate_limiter_retries_after_window_and_prunes_old_requests():
    now = [100.0]
    limiter = RateLimiter(limit=2, window_seconds=10, clock=lambda: now[0])

    assert limiter.check("client") == (True, 1, 0)
    assert limiter.check("client") == (True, 0, 0)
    allowed, remaining, retry_after = limiter.check("client")

    assert allowed is False
    assert remaining == 0
    assert retry_after == 10
    now[0] = 110.0
    assert limiter.check("client") == (True, 1, 0)


def test_zero_rate_limit_disables_limiting():
    limiter = RateLimiter(limit=0)

    assert limiter.check("client") == (True, 0, 0)


def test_rate_limiter_bounds_peer_state_and_shares_overflow_bucket():
    now = [100.0]
    limiter = RateLimiter(
        limit=1, window_seconds=10, clock=lambda: now[0], max_clients=1
    )

    assert limiter.check("tracked-peer") == (True, 0, 0)
    assert limiter.check("overflow-peer-a") == (True, 0, 0)
    assert limiter.check("overflow-peer-b") == (False, 0, 10)
    assert len(limiter._requests) == 1

    now[0] = 110.0
    assert limiter.check("new-peer") == (True, 0, 0)
    assert len(limiter._requests) == 1
