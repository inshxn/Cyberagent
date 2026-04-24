from __future__ import annotations

import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from plugin import CyberAgent, CyberAgentConfig
from xpulse.backend.auth import create_session, current_user, hash_password, verify_password
from xpulse.backend.database import XPulseDB
from xpulse.backend.schemas import LoginIn, PostIn, SignupIn

ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = ROOT / "xpulse" / "frontend" / "dist"
CONFIG_PATH = ROOT / "plugin" / "config.yaml"

db = XPulseDB(os.getenv("XPULSE_DB_PATH", str(ROOT / "data" / "xpulse.db")))
config = CyberAgentConfig.from_file(CONFIG_PATH)
config.database_path = os.getenv("CYBERAGENT_DB_PATH", str(ROOT / "data" / "logs.db"))

app = FastAPI(title="CyberAgent + XPulse", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(CyberAgent, config=config)


def cyberagent_instance() -> CyberAgent | None:
    for middleware in app.user_middleware:
        if middleware.cls is CyberAgent:
            return None
    return None


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyberagent-xpulse"}


@app.post("/api/signup")
def signup(payload: SignupIn) -> dict[str, object]:
    try:
        user = db.create_user(payload.username, hash_password(payload.password))
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Username already exists") from exc
    token = create_session(user)
    return {"token": token, "user": user}


@app.post("/api/login")
def login(payload: LoginIn, request: Request) -> dict[str, object]:
    user = db.get_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        middleware = request.app.middleware_stack
        while hasattr(middleware, "app"):
            if isinstance(middleware, CyberAgent):
                middleware.record_login_failure(client_ip(request))
                break
            middleware = middleware.app
        raise HTTPException(status_code=401, detail="Invalid credentials")
    safe_user = {"id": user["id"], "username": user["username"]}
    token = create_session(safe_user)
    return {"token": token, "user": safe_user}


@app.get("/api/feed")
def feed() -> dict[str, object]:
    return {"posts": db.feed()}


@app.post("/api/posts")
def create_post(payload: PostIn, user: dict[str, object] = Depends(current_user)) -> dict[str, object]:
    return {"post": db.create_post(int(user["user_id"]), payload.content)}


@app.get("/cyberagent/events")
def cyberagent_events(request: Request, limit: int = 100) -> dict[str, object]:
    middleware = _middleware_from_stack(request)
    return {"events": middleware.logger.query_events(limit=limit)}


@app.get("/cyberagent/dashboard")
def cyberagent_dashboard(request: Request) -> dict[str, object]:
    middleware = _middleware_from_stack(request)
    return middleware.dashboard_snapshot()


@app.get("/cyberagent/blocked")
def cyberagent_blocked(request: Request) -> dict[str, object]:
    middleware = _middleware_from_stack(request)
    return {"blocked_ips": middleware.response_agent.blocked_list()}


@app.get("/simulate/sql-injection")
def simulate_sql_injection(q: str = "' OR 1=1 --") -> dict[str, str]:
    return {"simulation": "sql_injection", "input": q}


@app.post("/simulate/xss")
def simulate_xss(payload: dict[str, object]) -> dict[str, object]:
    return {"simulation": "xss", "echo": payload}


@app.get("/simulate/ping")
def simulate_ping() -> dict[str, str]:
    return {"simulation": "rapid_requests", "status": "ok"}


def _middleware_from_stack(request: Request) -> CyberAgent:
    middleware = request.app.middleware_stack
    while hasattr(middleware, "app"):
        if isinstance(middleware, CyberAgent):
            return middleware
        middleware = middleware.app
    raise HTTPException(status_code=503, detail="CyberAgent middleware is not available")


if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="frontend")
