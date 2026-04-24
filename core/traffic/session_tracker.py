from __future__ import annotations

from collections import defaultdict, deque
from time import time

from core.models import RequestContext, TrafficStats


class SessionTracker:
    """Tracks short-lived per-IP traffic and adaptive offender history."""

    def __init__(self, decay_window_seconds: int = 900) -> None:
        self.decay_window_seconds = decay_window_seconds
        self.ip_requests: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.login_failures: dict[str, deque[float]] = defaultdict(deque)
        self.offender_scores: dict[str, float] = defaultdict(float)
        self.last_seen: dict[str, float] = {}

    def enrich(self, context: RequestContext) -> RequestContext:
        now = context.timestamp
        events = self.ip_requests[context.ip]
        events.append((now, context.route))
        self._trim_request_events(events, now)
        failures = self.login_failures[context.ip]
        self._trim_float_events(failures, now, window=300)

        context.traffic = TrafficStats(
            requests_last_second=sum(1 for ts, _ in events if now - ts <= 1),
            requests_last_minute=len(events),
            login_failures_last_5m=len(failures),
            payload_size=len(context.raw_body.encode("utf-8")),
            route_hits_last_minute=sum(1 for ts, route in events if route == context.route and now - ts <= 60),
        )
        self._decay_ip(context.ip, now)
        self.last_seen[context.ip] = now
        return context

    def record_login_failure(self, ip: str) -> None:
        now = time()
        self.login_failures[ip].append(now)
        self._trim_float_events(self.login_failures[ip], now, window=300)

    def record_decision(self, ip: str, risk_score: int) -> None:
        now = time()
        self._decay_ip(ip, now)
        if risk_score >= 31:
            self.offender_scores[ip] += max(1, risk_score / 20)
        self.last_seen[ip] = now

    def history_risk(self, ip: str) -> int:
        self._decay_ip(ip, time())
        return min(20, int(self.offender_scores[ip]))

    def _decay_ip(self, ip: str, now: float) -> None:
        previous = self.last_seen.get(ip)
        if previous is None:
            return
        elapsed = max(0.0, now - previous)
        if elapsed == 0:
            return
        decay_factor = max(0.0, 1.0 - elapsed / self.decay_window_seconds)
        self.offender_scores[ip] *= decay_factor
        if self.offender_scores[ip] < 0.1:
            self.offender_scores[ip] = 0.0

    @staticmethod
    def _trim_request_events(events: deque[tuple[float, str]], now: float) -> None:
        while events and now - events[0][0] > 60:
            events.popleft()

    @staticmethod
    def _trim_float_events(events: deque[float], now: float, window: int) -> None:
        while events and now - events[0] > window:
            events.popleft()

