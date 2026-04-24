from __future__ import annotations

import argparse
import concurrent.futures

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Run CyberAgent attack simulations against XPulse.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--rapid-count", type=int, default=18)
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    with httpx.Client(timeout=8) as client:
        print("SQL injection:", client.get(f"{base}/simulate/sql-injection", params={"q": "' OR 1=1 --"}).status_code)
        print("XSS:", client.post(f"{base}/simulate/xss", json={"post": "<script>alert('xss')</script>"}).status_code)

        def ping(_: int) -> int:
            return client.get(f"{base}/simulate/ping").status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(ping, range(args.rapid_count)))
        print("Rapid statuses:", statuses)
        dashboard = client.get(f"{base}/cyberagent/dashboard").json()
        print("Events:", len(dashboard["events"]))
        print("Blocked IPs:", dashboard["blocked_ips"])


if __name__ == "__main__":
    main()

