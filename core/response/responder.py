from __future__ import annotations

from time import time

from core.models import Action, Decision


class ResponseAgent:
    def __init__(self, ban_seconds: int = 300) -> None:
        self.ban_seconds = ban_seconds
        self.banned_ips: dict[str, float] = {}

    def is_banned(self, ip: str) -> bool:
        expires = self.banned_ips.get(ip)
        if expires is None:
            return False
        if expires <= time():
            self.banned_ips.pop(ip, None)
            return False
        return True

    def apply(self, ip: str, decision: Decision) -> None:
        if decision.action == Action.BLOCK:
            self.banned_ips[ip] = time() + self.ban_seconds

    def blocked_list(self) -> list[dict[str, object]]:
        now = time()
        active = []
        for ip, expires in list(self.banned_ips.items()):
            if expires <= now:
                self.banned_ips.pop(ip, None)
                continue
            active.append({"ip": ip, "expires_in_seconds": round(expires - now)})
        return active

