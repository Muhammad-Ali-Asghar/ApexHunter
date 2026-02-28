# ApexHunter

Autonomous, non-destructive penetration testing agent powered by LLM-driven planning and execution. ApexHunter uses LangChain and LangGraph to build a fully autonomous workflow that discovers, validates, and reports web application vulnerabilities -- without human intervention and without exploiting targets.

Built as a Final Year Project (FYP) to demonstrate how large language models can be applied to offensive security in a safe, auditable, and legally compliant manner.

## Key Principles

- **Non-destructive only** -- identifies and validates vulnerabilities but never exploits them.
- **Fully autonomous** -- no human-in-the-loop. The agent plans, executes, and reports on its own.
- **Auditable** -- every HTTP request is logged to a WARC flight recorder with a cryptographic hash chain.
- **Scope-locked** -- a regex-based egress firewall (RoE Gatekeeper) prevents any request outside the defined target scope.
- **Resilient** -- circuit breaker auto-sleeps when the target is stressed, state checkpointing enables crash recovery.

## Architecture

ApexHunter is a 17-node LangGraph state machine organized into four phases:

```
Phase 1: Intelligence Gathering
  Init -> OSINT -> Auth -> Recon -> Fuzzer -> WAF

Phase 2: Strategy & Planning
  Reducer -> Planner (Cloud LLM)

Phase 3: Execution
  JIT Tools -> Executor (Local LLM)

Phase 4: Analysis & Cleanup
  OOB Check -> Reviewer -> Pivot Loop -> Second-Order -> Janitor -> Report -> Sanitize
```

### Agents

| Agent | Role |
|---|---|
| **OSINT** | Historical recon via Wayback Machine, CommonCrawl, and DNS records. Retries with backoff if APIs are unavailable. |
| **Auth** | Multi-role authentication. Logs in as admin, user_a, user_b to build an auth matrix for IDOR/BAC cross-auth testing. |
| **Recon** | DOM-aware crawling with Playwright. Discovers endpoints, OpenAPI specs, GraphQL introspection, and DOM sinks. |
| **Fuzzer** | Exhaustive deep fuzzing with massive wordlists via ffuf. Time is not a constraint. |
| **WAF** | WAF fingerprinting and bypass profiling. |
| **Reducer** | Semantic deduplication of the attack surface using embedding similarity. |
| **Planner** | Cloud LLM (GPT-4o / Claude) generates a prioritized task tree of vulnerability checks. |
| **Executor** | Runs each task using Nuclei, custom scripts, or direct HTTP probes. JWT cracking runs in a parallel thread pool. Race condition testing enabled by default. |
| **OOB Checker** | Polls interactsh for out-of-band callbacks (blind SSRF, blind XSS). |
| **Reviewer** | Differential analysis -- compares responses across auth roles to confirm IDOR/BAC. |
| **Pivot Loop** | If new attack surface is discovered, loops back to the Planner for another pass. |
| **Second-Order** | Checks for stored/delayed vulnerabilities (stored XSS, second-order SQLi). |
| **Janitor** | Cleans up any test data created on the target during the scan. |
| **Reporter** | Generates a structured JSON report with OWASP classifications and evidence. |
| **Sanitizer** | Securely shreds all local state, logs, and temporary files (GDPR/SOC2 compliance). |

### Guardrails

| Component | Purpose |
|---|---|
| **RoE Gatekeeper** | Regex-based egress firewall. Blocks requests to localhost, cloud metadata endpoints (169.254.169.254), and any URL outside the defined scope. |
| **Circuit Breaker** | Monitors 5xx error rates and response latency. Auto-sleeps when the target is stressed, resumes at 50% speed. |
| **Flight Data Recorder** | Append-only WARC log with SHA-256 hash chain. Every request/response pair is cryptographically linked for tamper-evident auditing. |

### LLM Providers

ApexHunter uses a dual-LLM architecture:

- **Planner** (heavy reasoning): Azure OpenAI (GPT-4o), AWS Bedrock (Claude 3.5 Sonnet), Google Gemini (2.5 Pro), or Ollama
- **Executor** (fast, cheap): Ollama (Llama 3) recommended for high-volume tactical decisions

Configure via environment variables:
```
APEX_PLANNER_PROVIDER=gemini
APEX_EXECUTOR_PROVIDER=ollama
```

#### Google Gemini via Gemini CLI OAuth

Instead of using a rate-limited API key from AI Studio, ApexHunter can reuse the OAuth token from the [Gemini CLI](https://github.com/google-gemini/gemini-cli). This gives access to the same generous quota the CLI uses.

1. Install and run the Gemini CLI once: `gemini`
2. Complete the browser OAuth flow when prompted
3. Set the provider in `.env`:
   ```
   APEX_PLANNER_PROVIDER=gemini
   GEMINI_MODEL=gemini-2.5-pro
   GEMINI_OAUTH_CLIENT_ID=<client-id-from-gemini-cli>
   GEMINI_OAUTH_CLIENT_SECRET=<client-secret-from-gemini-cli>
   ```

The OAuth client ID and secret are the Gemini CLI's own public desktop-app credentials (hardcoded in its source code). You can find them in the [Gemini CLI repo](https://github.com/google-gemini/gemini-cli). The OAuth token at `~/.gemini/oauth_creds.json` is automatically loaded and refreshed. Inside Docker, the `~/.gemini` directory is bind-mounted read-only into the container.

## Project Structure

```
apexhunter/
├── README.md
├── requirements.txt
├── pyproject.toml
├── scan_config.example.json
├── .env.example
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── src/
│   ├── main.py                  # CLI entry point
│   ├── state.py                 # LangGraph state (TypedDicts)
│   ├── graph.py                 # 17-node state machine
│   ├── utils/
│   │   ├── config.py            # Pydantic configuration
│   │   ├── http_client.py       # Guarded HTTP client
│   │   ├── llm_provider.py      # LLM factory (Azure/Bedrock/Ollama/Gemini)
│   │   └── logger.py            # Structured logging (structlog)
│   ├── guardrails/
│   │   ├── roe_gatekeeper.py    # Scope enforcement
│   │   ├── circuit_breaker.py   # Adaptive rate limiting
│   │   └── flight_recorder.py   # WARC audit log
│   ├── tools/
│   │   ├── cli_wrappers.py      # Async subprocess wrappers (nmap, ffuf, nuclei)
│   │   ├── jit_installer.py     # Runtime tool installation
│   │   ├── sandbox.py           # Script execution sandbox
│   │   └── rag_engine.py        # ChromaDB vector store for payloads
│   ├── agents/
│   │   ├── osint.py             # Wayback, CommonCrawl, DNS
│   │   ├── auth.py              # Multi-role authentication
│   │   ├── recon.py             # DOM-aware crawling
│   │   ├── fuzzer.py            # Exhaustive fuzzing
│   │   ├── waf.py               # WAF detection
│   │   ├── reducer.py           # Attack surface deduplication
│   │   ├── planner.py           # LLM-driven task planning
│   │   ├── executor.py          # Multi-vector execution
│   │   └── phase4.py            # OOB, review, pivot, cleanup
│   └── reporting/
│       └── reporter.py          # JSON report generation
├── data/
│   └── seclists/                # Wordlists (mounted at runtime)
└── tests/
    └── test_smoke.py            # 31 smoke tests
```

## Prerequisites

- **Docker** and **Docker Compose**
- An LLM provider configured (Azure OpenAI, AWS Bedrock, Google Gemini, or a local Ollama instance)

Everything else (Python, Go tools, Playwright, Chromium) is managed inside the Docker container.

## Quick Start

### 1. Clone the repository

```bash
git clone git@github.com:Muhammad-Ali-Asghar/ApexHunter.git
cd ApexHunter
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your LLM provider credentials. At minimum, configure one of:

- **Azure OpenAI**: `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`
- **AWS Bedrock**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
- **Google Gemini**: Run `gemini` CLI once to authenticate, then set `APEX_PLANNER_PROVIDER=gemini`
- **Ollama** (local): `OLLAMA_BASE_URL` (defaults to `http://host.docker.internal:11434`)

### 3. Configure the scan target

```bash
cp scan_config.example.json scan_config.json
```

Edit `scan_config.json`:

```json
{
    "target_url": "https://your-target.com",
    "target_scope": "^https?://(.*\\.)?your-target\\.com",
    "credentials": [
        {
            "role": "admin",
            "username": "admin@your-target.com",
            "password": "your-password",
            "login_url": "https://your-target.com/login"
        },
        {
            "role": "user_a",
            "username": "alice@your-target.com",
            "password": "her-password"
        },
        {
            "role": "user_b",
            "username": "bob@your-target.com",
            "password": "his-password"
        }
    ]
}
```

Providing multiple credentials enables cross-auth testing (IDOR, broken access control).

### 4. Build and run

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm apexhunter --config scan_config.json
```

Or using CLI arguments directly:

```bash
docker compose -f docker/docker-compose.yml run --rm apexhunter \
  --target https://your-target.com \
  --scope "^https?://(.*\.)?your-target\.com" \
  --creds "admin:admin@your-target.com:password" \
  --creds "user_a:alice@your-target.com:password"
```

### 5. Resume a crashed scan

```bash
docker compose -f docker/docker-compose.yml run --rm apexhunter \
  --config scan_config.json \
  --resume <scan-id>
```

The scan ID is printed at startup. State is checkpointed to SQLite after every node.

## Output

ApexHunter produces a single JSON report in the output directory containing:

- All confirmed vulnerabilities with OWASP Top 10 classification
- Evidence (request/response pairs, payloads, screenshots)
- CVSS-style severity ratings
- Remediation recommendations
- Scan metadata (duration, endpoints tested, errors)

The WARC flight recorder log provides a tamper-evident audit trail of every HTTP interaction.

After report generation, the Sanitizer agent securely shreds all local state, logs, and temporary files.

## Running Tests

Tests run outside Docker using a local virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install pytest pytest-asyncio structlog typing_extensions
PYTHONPATH=. pytest tests/ -v
```

Current status: **31/31 tests passing** (state management, guardrails, flight recorder, JWT analysis).

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `APEX_PLANNER_PROVIDER` | `azure` | LLM for strategic planning (`azure`, `bedrock`, `ollama`, `openai`, `gemini`) |
| `APEX_EXECUTOR_PROVIDER` | `ollama` | LLM for tactical execution |
| `GEMINI_MODEL` | `gemini-2.5-pro` | Gemini model name |
| `GEMINI_OAUTH_CREDS_PATH` | `~/.gemini/oauth_creds.json` | Path to Gemini CLI OAuth token file |
| `APEX_MAX_CONCURRENT` | `20` | Max concurrent requests for race condition testing |
| `APEX_CIRCUIT_BREAKER_THRESHOLD` | `5` | 5xx error rate (%) to trigger auto-sleep |
| `APEX_AUTOSLEEP_DURATION` | `900` | Seconds to sleep when circuit breaker trips |
| `APEX_RESUME_SPEED_FACTOR` | `0.5` | Speed multiplier when resuming after auto-sleep |
| `APEX_MAX_DEPTH` | `10` | Max crawling depth for the spider |

### Docker Services

| Service | Purpose |
|---|---|
| `apexhunter` | Main agent container |
| `postgres` | State persistence (optional, SQLite used by default) |
| `mitmproxy` | Traffic capture and replay |

## Security Considerations

- **Scope enforcement**: The RoE Gatekeeper blocks all requests outside the target scope, including SSRF attempts against localhost, cloud metadata endpoints, and private IP ranges.
- **Command injection prevention**: All CLI tool wrappers use `asyncio.create_subprocess_exec` with explicit argument lists. No shell interpolation.
- **Input validation**: Every agent validates its inputs before processing. Empty or missing values trigger early returns with logged warnings.
- **Data sanitization**: After the final report, all local state, logs, and temporary files are securely shredded using `shred` (GDPR/SOC2 compliance).
- **Audit trail**: The WARC flight recorder maintains a SHA-256 hash chain. Any tampering breaks the chain and is detectable.

## Legal Disclaimer

ApexHunter is designed for **authorized security testing only**. You must have explicit written permission from the target owner before running a scan. Unauthorized use against systems you do not own or have permission to test is illegal and unethical. The authors accept no liability for misuse of this tool.

## License

This project was developed as a Final Year Project. All rights reserved.
