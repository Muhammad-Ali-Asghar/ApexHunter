"""
LLM Provider Factory

Creates and returns the appropriate LangChain ChatModel based on
the configured provider (Azure OpenAI, AWS Bedrock, local Ollama,
or Google Gemini via Gemini CLI OAuth).
Separates "planner" (heavy reasoning) from "executor" (fast, cheap).
"""

from __future__ import annotations

import json
import os
from typing import Optional

import structlog
from langchain_core.language_models.chat_models import BaseChatModel

from src.utils.config import LLMProviderConfig

logger = structlog.get_logger("apexhunter.utils.llm_provider")

_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def create_planner_llm(config: LLMProviderConfig) -> BaseChatModel:
    """
    Create the LLM used for strategic planning (Node 7/8).
    Uses cloud models for high reasoning capability.
    """
    return _create_llm(config.planner_provider, config, temperature=0.1)


def create_executor_llm(config: LLMProviderConfig) -> BaseChatModel:
    """
    Create the LLM used for tactical execution (Node 10/11).
    Uses local models for speed and cost efficiency.
    """
    return _create_llm(config.executor_provider, config, temperature=0.0)


def _load_gemini_cli_credentials(creds_path: str):
    """
    Load OAuth credentials from the Gemini CLI's oauth_creds.json
    and return a google.oauth2.credentials.Credentials object that
    supports automatic token refresh.

    The Gemini CLI stores tokens at ~/.gemini/oauth_creds.json after
    the user authenticates via `gemini` (OAuth browser flow). This
    function reuses those tokens so ApexHunter gets the same generous
    quota as the CLI — no API key needed.

    Args:
        creds_path: Path to oauth_creds.json (supports ~ expansion).

    Returns:
        A google.oauth2.credentials.Credentials instance.

    Raises:
        FileNotFoundError: If the creds file doesn't exist.
        ValueError: If required fields are missing.
    """
    from google.oauth2.credentials import Credentials

    expanded_path = os.path.expanduser(creds_path)
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(
            f"Gemini CLI OAuth credentials not found at {expanded_path}. "
            f"Run `gemini` once to authenticate via the browser OAuth flow."
        )

    with open(expanded_path, "r") as f:
        data = json.load(f)

    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        raise ValueError(
            f"No refresh_token found in {expanded_path}. Re-run `gemini` to re-authenticate."
        )

    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri=_GOOGLE_TOKEN_URI,
        client_id=os.environ.get("GEMINI_OAUTH_CLIENT_ID", ""),
        client_secret=os.environ.get("GEMINI_OAUTH_CLIENT_SECRET", ""),
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    logger.info(
        "gemini_oauth_loaded",
        creds_path=expanded_path,
        has_access_token=bool(access_token),
        has_refresh_token=bool(refresh_token),
    )

    return creds


def _create_llm(
    provider: str,
    config: LLMProviderConfig,
    temperature: float = 0.1,
) -> BaseChatModel:
    """
    Internal factory to create a ChatModel.

    Args:
        provider: One of "azure", "bedrock", "ollama", "openai", "gemini".
        config: The LLM provider configuration.
        temperature: Sampling temperature.

    Returns:
        A LangChain BaseChatModel instance.
    """
    provider = provider.lower().strip()

    if provider == "azure":
        logger.info("llm_provider_azure", deployment=config.azure_openai_deployment)
        from langchain_openai import AzureChatOpenAI

        return AzureChatOpenAI(
            azure_deployment=config.azure_openai_deployment,
            azure_endpoint=config.azure_openai_endpoint or "",
            api_key=config.azure_openai_api_key or "",
            api_version=config.azure_openai_api_version,
            temperature=temperature,
            max_tokens=4096,
        )

    elif provider == "bedrock":
        logger.info("llm_provider_bedrock", model=config.aws_bedrock_model_id)
        from langchain_aws import ChatBedrock

        return ChatBedrock(
            model_id=config.aws_bedrock_model_id,
            region_name=config.aws_region,
            model_kwargs={"temperature": temperature, "max_tokens": 4096},
        )

    elif provider == "ollama":
        logger.info("llm_provider_ollama", model=config.ollama_model)
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=config.ollama_model,
            base_url=config.ollama_base_url,
            temperature=temperature,
        )

    elif provider == "openai":
        logger.info("llm_provider_openai")
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(
            temperature=temperature,
            max_tokens=4096,
        )

    elif provider == "gemini":
        logger.info("llm_provider_gemini", model=config.gemini_model)
        from langchain_google_genai import ChatGoogleGenerativeAI

        creds = _load_gemini_cli_credentials(config.gemini_oauth_creds_path)

        return ChatGoogleGenerativeAI(
            model=config.gemini_model,
            credentials=creds,
            temperature=temperature,
            max_output_tokens=8192,
        )

    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. Supported: azure, bedrock, ollama, openai, gemini"
        )
