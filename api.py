from fastapi import FastAPI, HTTPException, Query
from typing import List
import json

# Import the existing checker
from ssl_checker import SSLChecker

app = FastAPI(
    title="SSL Checker API",
    version="1.0.0",
    description="Self-hosted API wrapper around the Python SSL/TLS checker",
)


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
def check_single_host(host: str, analyze: bool = False):
    """
    Check a single host. Host may include an optional port (e.g., example.com:8443).
    """
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
):
    """
    Check multiple hosts using repeated query params, e.g.:
    /api/v1/check?hosts=example.com&hosts=github.com:443
    """
    if not hosts:
        raise HTTPException(status_code=400, detail="At least one host is required")
    data = _run_check(hosts, analyze=analyze)
    return data
