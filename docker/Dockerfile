FROM python:3.11-slim-bookworm

LABEL maintainer="ApexHunter DAST Agent"
LABEL description="Autonomous Non-Destructive Penetration Testing Agent"

# ── System Dependencies ────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    nmap \
    whois \
    dnsutils \
    net-tools \
    build-essential \
    libffi-dev \
    libssl-dev \
    chromium \
    golang-go \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Go bin path ────────────────────────────────────
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# ── Install Nuclei (Non-Destructive Scanner) ──────
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

# ── Install ffuf (Fuzzer) ─────────────────────────
RUN go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true

# ── Install httpx-toolkit (HTTP Prober) ───────────
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true

# ── Install subfinder (Subdomain Discovery) ───────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true

# ── Install interactsh-client (OOB Listener) ──────
RUN go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || true

# ── Python Dependencies ───────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Install Playwright Browsers ───────────────────
RUN playwright install --with-deps chromium

# ── Copy Source Code ──────────────────────────────
COPY src/ ./src/
COPY data/ ./data/

# ── Create working directories ────────────────────
RUN mkdir -p /app/output /app/logs /app/state /app/warc

# ── Environment Variables ─────────────────────────
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV APEX_OUTPUT_DIR=/app/output
ENV APEX_LOG_DIR=/app/logs
ENV APEX_STATE_DIR=/app/state
ENV APEX_WARC_DIR=/app/warc

ENTRYPOINT ["python", "-m", "src.main"]
