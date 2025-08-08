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

# Default to run the API server; can override to run the CLI
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
