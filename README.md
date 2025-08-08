# SSL/TLS Checker (API + Docker)

Self-hosted API and CLI to inspect SSL/TLS certificates for one or more hosts. Returns rich certificate metadata (issuer, SANs, validity, TLS version used, etc.) and can optionally call SSL Labs to enrich results with a security grade.

Highlights:

- FastAPI server with simple curl-friendly endpoints
- Docker-first deployment
- CLI still available (inside or outside the container)
- Optional deep analysis via SSL Labs (slower; external API)

## Quick start (Docker)

Use the published image:

```bash
docker pull sentinelkasai/ssl-checker:dev
docker run --rm -p 8000:8000 sentinelkasai/ssl-checker:dev
```

Verify it’s up:

```bash
curl http://localhost:8000/healthz
```

Query a host:

```bash
curl http://localhost:8000/api/v1/check/example.com
```

Multiple hosts:

```bash
curl "http://localhost:8000/api/v1/check?hosts=example.com&hosts=github.com:443"
```

Optional deep analysis (uses SSL Labs API; slower):

```bash
curl "http://localhost:8000/api/v1/check/example.com?analyze=true"
```

Container details:

- Exposes port 8000
- Default command runs the API server (uvicorn)

## API reference

Base URL: `/`

- GET `/healthz`
  - Returns `{ "status": "ok" }` when the service is healthy.

- GET `/api/v1/check/{host}`
  - Path parameter `host`: domain, optionally with port (e.g., `example.com:8443`)
  - Query parameter `analyze` (bool, default false): include SSL Labs report when true
  - Response: JSON object keyed by normalized host
  - On connection/handshake failure for the host, returns HTTP 502

- GET `/api/v1/check`
  - Query parameter `hosts`: repeatable, e.g., `?hosts=a.com&hosts=b.com:443`
  - Query parameter `analyze` (bool, default false)
  - Response: JSON object keyed by normalized host

Notes:

- TLS: Auto‑negotiates the highest protocol supported by the server and OpenSSL (TLS 1.3 when available).
- Analyze: When `analyze=true`, results come from SSL Labs (cached where possible, short timeouts). If not READY, the response may include `analyze_status`/`analyze_error` instead of a grade.

## Configuration (env vars)

You can tune basic safety limits using environment variables (all have sensible defaults):

- SSL_CHECKER_MAX_HOSTS (default 5): Max number of hosts per request.
- SSL_CHECKER_ALLOWED_PORTS (default 443): Comma‑separated list of allowed ports, e.g. `443,8443`.
- SSL_CHECKER_RATE_PER_MIN (default 60): Per‑IP requests per minute.
- SSL_CHECKER_API_KEY (set at runtime only): If set, requests must include header `X-API-Key` with this value.

Example:

```bash
docker run --rm -p 8000:8000 \
  -e SSL_CHECKER_MAX_HOSTS=2 \
  -e SSL_CHECKER_ALLOWED_PORTS=443 \
  -e SSL_CHECKER_RATE_PER_MIN=30 \
  -e SSL_CHECKER_API_KEY=changeme \
  sentinelkasai/ssl-checker:dev
```

Tip: The image includes a HEALTHCHECK that calls `/healthz`. In CI, consider waiting for `docker inspect -f '{{json .State.Health.Status}}'` to be `healthy` before curl tests.

## Use the CLI (inside Docker)

The image includes the original script. Override the container command to run the CLI instead of the API:

```bash
docker run --rm sentinelkasai/ssl-checker:dev python ssl_checker.py -H example.com -j
```

More CLI examples:

```bash
# Multiple hosts
docker run --rm sentinelkasai/ssl-checker:dev python ssl_checker.py -H example.com github.com:443

# Summary only
docker run --rm sentinelkasai/ssl-checker:dev python ssl_checker.py -H example.com -S

# Save JSON per host
docker run --rm -v "$PWD:/out" -w /out sentinelkasai/ssl-checker:dev python /app/ssl_checker.py -H example.com -J
```

Tip: Mount a volume (`-v $PWD:/out -w /out`) when you want files (CSV/JSON/HTML) written back to the host.

## Local development (optional)

Run the API directly:

```bash
python -m pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

Run the CLI directly:

```bash
python ssl_checker.py -H example.com -j
```

## CLI help (reference)

```bash
./ssl_checker.py -h
usage: ssl_checker.py (-H [HOSTS [HOSTS ...]] | -f HOST_FILE) [-s HOST:PORT] [-c FILENAME.CSV] [-j] [-S] [-x] [-J] [-a] [-v] [-h]

Collects useful information about the given host's SSL certificates.

optional arguments:
-H [HOSTS [HOSTS ...]], --host [HOSTS [HOSTS ...]]  Hosts as input separated by space
-f HOST_FILE, --host-file HOST_FILE                 Hosts as input from a file
-s HOST:PORT, --socks HOST:PORT                     Enable SOCKS proxy for connection
-c FILENAME.CSV, --csv FILENAME.CSV                 Enable CSV file export
-j, --json            Enable JSON in the output
-S, --summary         Enable summary output only
-x, --html            Enable HTML file export
-J, --json-save       Enable JSON export individually per host
-a, --analyze         Enable SSL security analysis on the host
-v, --verbose         Enable verbose to see what is going on
-h, --help            Show this help message and exit
```

Port defaults to 443 when not specified.

## Notes

- If a certificate has fewer than 15 days remaining, it is counted as a “warning” in the summary.
- SOCKS proxies are supported via `-s/--socks HOST:PORT` in CLI mode.

## License

This project is licensed under the terms of the MIT License. See `LICENSE`.
