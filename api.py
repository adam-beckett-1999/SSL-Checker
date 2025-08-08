import os
import socket
import ipaddress
import time
from collections import deque
from typing import List, Optional, Tuple, Dict

from fastapi import FastAPI, HTTPException, Query, Depends, Header, Request
import json

# Import the existing checker
from ssl_checker import SSLChecker

app = FastAPI(
    title="SSL Checker API",
    version="1.0.0",
    description="Self-hosted API wrapper around the Python SSL/TLS checker",
)

# Config (environment-overridable)
MAX_HOSTS: int = int(os.getenv("SSL_CHECKER_MAX_HOSTS", "5"))
_allowed_ports_env = os.getenv("SSL_CHECKER_ALLOWED_PORTS", "443")
ALLOWED_PORTS = {int(p.strip()) for p in _allowed_ports_env.split(",") if p.strip().isdigit()}
REQUIRE_API_KEY: Optional[str] = os.getenv("SSL_CHECKER_API_KEY")
RATE_LIMIT_PER_MIN: int = int(os.getenv("SSL_CHECKER_RATE_PER_MIN", "60"))

# naive in-memory rate limiter storage { ip: deque[timestamps] }
_rl_buckets: Dict[str, deque] = {}


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    """Optional API key auth. If SSL_CHECKER_API_KEY is set, require matching X-API-Key header."""
    if REQUIRE_API_KEY is None:
        return
    if not x_api_key or x_api_key != REQUIRE_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: invalid API key")


def rate_limit(request: Request):
    """Very simple per-IP sliding-window rate limiter (requests/min)."""
    if RATE_LIMIT_PER_MIN <= 0:
        return
    # Prefer X-Forwarded-For (first IP) when behind a proxy
    xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
    client_ip = None
    if xff:
        client_ip = xff.split(",")[0].strip()
    if not client_ip:
        client = request.client
        client_ip = client.host if client else "unknown"

    now = time.time()
    window_start = now - 60
    bucket = _rl_buckets.setdefault(client_ip, deque())
    # Drop old entries
    while bucket and bucket[0] < window_start:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        raise HTTPException(status_code=429, detail="Too Many Requests")
    bucket.append(now)


def _parse_host_port(raw: str) -> Tuple[str, int]:
    """Parse 'host[:port]' and validate basic format."""
    if "://" in raw or "/" in raw or "[" in raw or "]" in raw:
        raise HTTPException(status_code=400, detail=f"Invalid host format: {raw}")
    host = raw
    port = 443
    if ":" in raw:
        parts = raw.rsplit(":", 1)
        if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
            raise HTTPException(status_code=400, detail=f"Invalid host:port: {raw}")
        host, port_str = parts
        port = int(port_str)
    if port not in ALLOWED_PORTS:
        raise HTTPException(status_code=400, detail=f"Port not allowed: {port}")
    return host, port


def _is_disallowed_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True


def _validate_no_ssrf(host: str, allow_unresolved: bool = True):
    """Resolve host and block connections to private/link-local/loopback/etc.

    If allow_unresolved is True, do not raise when DNS resolution fails (let the checker handle it).
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        if allow_unresolved:
            return
        raise HTTPException(status_code=400, detail=f"Failed to resolve host '{host}': {e}")
    ips = {str(info[4][0]) for info in infos if info and info[4]}
    if not ips:
        raise HTTPException(status_code=400, detail=f"No IPs resolved for host '{host}'")
    # If any resolved IP is disallowed, reject to prevent SSRF
    for ip in ips:
        if _is_disallowed_ip(ip):
            raise HTTPException(status_code=400, detail=f"Host '{host}' resolves to a disallowed IP: {ip}")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def _run_check(hosts: List[str], analyze: bool = False) -> dict:
    """Helper to run the SSLChecker and return parsed JSON data."""
    checker = SSLChecker()
    args = checker.get_args(json_args={"hosts": hosts})
    if analyze:
        setattr(args, "analyze", True)

    # show_result returns a JSON string when used as an imported module
    result_json = checker.show_result(args)
    try:
        data = json.loads(result_json)
    except Exception as e:
        # If for any reason JSON parsing fails, surface an error
        raise HTTPException(status_code=500, detail=f"Failed to parse result: {e}")
    return data


@app.get("/api/v1/check/{host}")
def check_single_host(host: str, analyze: bool = False, auth: None = Depends(require_api_key), _rl: None = Depends(rate_limit)):
    """
    Check a single host. Host may include an optional port (e.g., example.com:8443).
    """
    normalized_host, _port = _parse_host_port(host)
    _validate_no_ssrf(normalized_host)
    data = _run_check([host], analyze=analyze)
    # If the checker marked it failed, reflect a 502 error. The checker normalizes the host key
    # (e.g., strips ports), so detect any single-entry failure regardless of key name.
    if len(data) == 0:
        raise HTTPException(status_code=502, detail=f"No result for host: {host}")
    if len(data) == 1:
        only_val = next(iter(data.values()))
        if only_val == "failed":
            raise HTTPException(status_code=502, detail=f"Failed to check host: {host}")
    return data


@app.get("/api/v1/check")
def check_multiple_hosts(
    hosts: List[str] = Query(..., description="One or more hosts, can repeat the param: ?hosts=a.com&hosts=b.com"),
    analyze: bool = False,
    auth: None = Depends(require_api_key),
    _rl: None = Depends(rate_limit),
):
    """
    Check multiple hosts using repeated query params, e.g.:
    /api/v1/check?hosts=example.com&hosts=github.com:443
    """
    if not hosts:
        raise HTTPException(status_code=400, detail="At least one host is required")
    if len(hosts) > MAX_HOSTS:
        raise HTTPException(status_code=400, detail=f"Too many hosts; max {MAX_HOSTS}")

    # Validate each host before running
    for raw in hosts:
        h, _port = _parse_host_port(raw)
        _validate_no_ssrf(h)
    data = _run_check(hosts, analyze=analyze)
    return data
