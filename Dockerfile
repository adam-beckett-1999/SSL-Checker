FROM python:3.11-alpine

# Ensure all packages are up to date to reduce vulnerabilities
RUN apk update && apk upgrade

WORKDIR /app

# System deps for cryptography/pyopenssl
RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && apk del gcc musl-dev libffi-dev

COPY . /app

EXPOSE 8000

# Security/configuration defaults (override at runtime with -e)
ENV SSL_CHECKER_MAX_HOSTS=5 \
    SSL_CHECKER_ALLOWED_PORTS=443 \
    SSL_CHECKER_RATE_PER_MIN=60

# Container health check (uses busybox wget available in Alpine)
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
    CMD wget -qO- http://127.0.0.1:8000/healthz >/dev/null 2>&1 || exit 1

# Default to run the API server; can override to run the CLI
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
