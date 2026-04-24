from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from core.ai_engine import DecisionEngine
from core.detection import AnomalyDetector, BehaviorDetector, SignatureDetector
from core.logging import ForensicsLogger
from core.models import Action, RequestContext
from core.response import ResponseAgent
from core.traffic import SessionTracker


@dataclass
class CyberAgentConfig:
    database_path: str = "data/logs.db"
    modules: dict[str, bool] = field(default_factory=lambda: {"signature": True, "behavior": True, "anomaly": True})
    thresholds: dict[str, Any] = field(
        default_factory=lambda: {
            "requests_per_second": 8,
            "requests_per_minute": 120,
            "brute_force_failures": 5,
            "max_payload_bytes": 32768,
            "anomaly_warmup_samples": 15,
            "anomaly_z_threshold": 3.0,
        }
    )
    response: dict[str, Any] = field(default_factory=lambda: {"throttle_delay_ms": 650, "ban_seconds": 300})
    logging: dict[str, Any] = field(default_factory=lambda: {"log_allowed_requests": False})

    @classmethod
    def from_file(cls, path: str | Path) -> "CyberAgentConfig":
        with open(path, "r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        return cls(**loaded)


class CyberAgent(BaseHTTPMiddleware):
    def __init__(self, app: Any, config: CyberAgentConfig | dict[str, Any] | None = None) -> None:
        super().__init__(app)
        self.config = config if isinstance(config, CyberAgentConfig) else CyberAgentConfig(**(config or {}))
        thresholds = self.config.thresholds
        modules = self.config.modules
        response_config = self.config.response

        self.tracker = SessionTracker()
        self.signature = SignatureDetector(enabled=modules.get("signature", True))
        self.behavior = BehaviorDetector(
            enabled=modules.get("behavior", True),
            requests_per_second=int(thresholds.get("requests_per_second", 8)),
            requests_per_minute=int(thresholds.get("requests_per_minute", 120)),
            brute_force_failures=int(thresholds.get("brute_force_failures", 5)),
            max_payload_bytes=int(thresholds.get("max_payload_bytes", 32768)),
        )
        self.anomaly = AnomalyDetector(
            enabled=modules.get("anomaly", True),
            warmup_samples=int(thresholds.get("anomaly_warmup_samples", 15)),
            z_threshold=float(thresholds.get("anomaly_z_threshold", 3.0)),
        )
        self.decision_engine = DecisionEngine(
            tracker=self.tracker,
            throttle_delay_ms=int(response_config.get("throttle_delay_ms", 650)),
        )
        self.response_agent = ResponseAgent(ban_seconds=int(response_config.get("ban_seconds", 300)))
        self.logger = ForensicsLogger(self.config.database_path)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        if request.url.path.startswith(("/cyberagent", "/docs", "/openapi.json", "/health")):
            return await call_next(request)

        ip = self._client_ip(request)
        if self.response_agent.is_banned(ip):
            context = await self._context_from_request(request, ip)
            return self._blocked_response(context, reason="ip_temporarily_banned")

        context = await self._context_from_request(request, ip)
        context = self.tracker.enrich(context)
        findings = self.signature.scan(context) + self.behavior.scan(context) + self.anomaly.scan(context)
        decision = self.decision_engine.decide(ip, findings)
        self.logger.record(context, decision)
        self.tracker.record_decision(ip, decision.risk_score)

        request.state.cyberagent = {
            "risk_score": decision.risk_score,
            "action": decision.action.value,
            "findings": [finding.__dict__ for finding in decision.findings],
            "reasons": decision.reasons,
        }

        if decision.action == Action.BLOCK:
            self.response_agent.apply(ip, decision)
            return JSONResponse(
                status_code=403,
                content={
                    "blocked": True,
                    "action": decision.action.value,
                    "risk_score": decision.risk_score,
                    "attack_types": decision.attack_types,
                    "message": "CyberAgent blocked this request.",
                },
            )

        if decision.action == Action.THROTTLE and decision.delay_ms:
            await asyncio.sleep(decision.delay_ms / 1000)

        response = await call_next(request)
        response.headers["X-CyberAgent-Risk"] = str(decision.risk_score)
        response.headers["X-CyberAgent-Action"] = decision.action.value
        return response

    def record_login_failure(self, ip: str) -> None:
        self.tracker.record_login_failure(ip)

    def dashboard_snapshot(self) -> dict[str, Any]:
        return {
            "stats": self.logger.stats(),
            "events": self.logger.query_events(limit=80),
            "blocked_ips": self.response_agent.blocked_list(),
        }

    async def _context_from_request(self, request: Request, ip: str) -> RequestContext:
        body_bytes = await request.body()
        raw_body = body_bytes.decode("utf-8", errors="replace")
        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": body_bytes, "more_body": False}
        request._receive = receive

        body: Any = raw_body
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type and raw_body:
            try:
                body = json.loads(raw_body)
            except json.JSONDecodeError:
                body = raw_body
        return RequestContext(
            ip=ip,
            method=request.method,
            route=request.url.path,
            headers={key: value for key, value in request.headers.items()},
            query=dict(request.query_params),
            body=body,
            raw_body=raw_body,
        )

    @staticmethod
    def _client_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @staticmethod
    def _blocked_response(context: RequestContext, reason: str) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "action": "block",
                "risk_score": 100,
                "attack_types": reason,
                "message": "CyberAgent blocked this request.",
                "ip": context.ip,
            },
        )


def build_cyberagent(config_path: str | Path = "plugin/config.yaml") -> dict[str, Any]:
    return CyberAgentConfig.from_file(config_path).__dict__
