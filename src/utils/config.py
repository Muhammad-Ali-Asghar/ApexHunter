"""
ApexHunter Configuration Module

Loads all environment variables and provides a centralized,
validated configuration object for the entire agent.
"""

from __future__ import annotations

import os
import re
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings


class TargetConfig(BaseModel):
    """Target website configuration."""

    url: str = Field(..., description="The root URL of the target application")
    scope_regex: str = Field(
        ...,
        description="Regex pattern defining allowed domains/IPs for the RoE Gatekeeper",
    )
    max_depth: int = Field(default=10, description="Max crawling depth")

    @field_validator("scope_regex")
    @classmethod
    def validate_scope_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid scope regex: {e}")
        return v


class AuthCredential(BaseModel):
    """A single set of credentials for the auth matrix."""

    username: str
    password: str
    role: str = Field(default="user", description="Role label (admin, user_a, user_b)")
    login_url: Optional[str] = Field(default=None, description="Override login URL")


class LLMProviderConfig(BaseSettings):
    """LLM provider configuration loaded from environment."""

    # ── Provider Selection ────────────────────────
    planner_provider: str = Field(default="azure", alias="APEX_PLANNER_PROVIDER")
    executor_provider: str = Field(default="ollama", alias="APEX_EXECUTOR_PROVIDER")

    # ── Azure OpenAI ──────────────────────────────
    azure_openai_api_key: Optional[str] = Field(default=None, alias="AZURE_OPENAI_API_KEY")
    azure_openai_endpoint: Optional[str] = Field(default=None, alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_deployment: str = Field(default="gpt-4o", alias="AZURE_OPENAI_DEPLOYMENT")
    azure_openai_api_version: str = Field(
        default="2024-08-01-preview", alias="AZURE_OPENAI_API_VERSION"
    )

    # ── AWS Bedrock ───────────────────────────────
    aws_access_key_id: Optional[str] = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")
    aws_bedrock_model_id: str = Field(
        default="anthropic.claude-3-5-sonnet-20241022-v2:0",
        alias="AWS_BEDROCK_MODEL_ID",
    )

    # ── Local Ollama ──────────────────────────────
    ollama_base_url: str = Field(
        default="http://host.docker.internal:11434", alias="OLLAMA_BASE_URL"
    )
    ollama_model: str = Field(default="llama3", alias="OLLAMA_MODEL")

    # ── Google Gemini (via Gemini CLI OAuth) ──────
    gemini_model: str = Field(default="gemini-2.5-pro", alias="GEMINI_MODEL")
    gemini_oauth_creds_path: str = Field(
        default="~/.gemini/oauth_creds.json", alias="GEMINI_OAUTH_CREDS_PATH"
    )

    class Config:
        env_file = ".env"
        populate_by_name = True


class AgentConfig(BaseSettings):
    """Agent behavior configuration."""

    max_concurrent_requests: int = Field(default=20, alias="APEX_MAX_CONCURRENT")
    circuit_breaker_threshold: int = Field(
        default=5,
        alias="APEX_CIRCUIT_BREAKER_THRESHOLD",
        description="Percentage of 5xx errors to trigger circuit breaker",
    )
    autosleep_duration: int = Field(
        default=900,
        alias="APEX_AUTOSLEEP_DURATION",
        description="Seconds to sleep when circuit breaker trips",
    )
    resume_speed_factor: float = Field(
        default=0.5,
        alias="APEX_RESUME_SPEED_FACTOR",
        description="Speed factor when resuming after auto-sleep (0.0-1.0)",
    )
    request_delay: float = Field(default=0.5, description="Base delay between requests in seconds")
    max_retries: int = Field(default=3, description="Max retries for OSINT/external APIs")
    retry_backoff: float = Field(default=5.0, description="Backoff seconds between retries")
    jwt_crack_wordlist: str = Field(
        default="/app/data/seclists/jwt-secrets.txt",
        description="Path to JWT secret wordlist",
    )
    fuzzing_wordlist_dirs: str = Field(
        default="/app/data/seclists/Discovery/Web-Content/",
        description="Path to directory fuzzing wordlists",
    )
    fuzzing_wordlist_params: str = Field(
        default="/app/data/seclists/Discovery/Web-Content/burp-parameter-names.txt",
        description="Path to parameter fuzzing wordlists",
    )

    class Config:
        env_file = ".env"
        populate_by_name = True


class PathConfig(BaseSettings):
    """File system paths."""

    output_dir: str = Field(default="/app/output", alias="APEX_OUTPUT_DIR")
    log_dir: str = Field(default="/app/logs", alias="APEX_LOG_DIR")
    state_dir: str = Field(default="/app/state", alias="APEX_STATE_DIR")
    warc_dir: str = Field(default="/app/warc", alias="APEX_WARC_DIR")
    chroma_dir: str = Field(default="/app/data/chromadb")

    class Config:
        env_file = ".env"
        populate_by_name = True


class ApexConfig:
    """Master configuration object aggregating all sub-configs."""

    def __init__(
        self,
        target_url: str,
        target_scope: str,
        credentials: Optional[List[dict]] = None,
    ):
        self.target = TargetConfig(url=target_url, scope_regex=target_scope)
        self.llm = LLMProviderConfig()
        self.agent = AgentConfig()
        self.paths = PathConfig()

        # Build the auth matrix
        self.auth_matrix: List[AuthCredential] = []
        if credentials:
            for cred in credentials:
                self.auth_matrix.append(AuthCredential(**cred))

        # Ensure output directories exist
        for d in [
            self.paths.output_dir,
            self.paths.log_dir,
            self.paths.state_dir,
            self.paths.warc_dir,
        ]:
            os.makedirs(d, exist_ok=True)

    def get_proxy_url(self) -> str:
        """Return the internal mitmproxy URL."""
        return "http://apexhunter-proxy:8080"

    def get_db_url(self) -> str:
        """Return the PostgreSQL connection URL for the checkpointer."""
        return "postgresql://apexhunter:apexhunter_secret@apexhunter-db:5432/apexhunter_state"
