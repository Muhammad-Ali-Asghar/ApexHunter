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

        # Mode 1: API key (Developer API) — simplest
        if config.gemini_api_key:
            logger.info("gemini_mode_api_key")
            from langchain_google_genai import ChatGoogleGenerativeAI

            return ChatGoogleGenerativeAI(
                model=config.gemini_model,
                google_api_key=config.gemini_api_key,
                temperature=temperature,
                max_output_tokens=8192,
            )

        # Mode 2: OAuth via Gemini CLI → Code Assist API
        # Uses the same internal API as the Gemini CLI and OpenCode.
        # No API key or GCP project setup required — project is
        # auto-discovered from the Code Assist backend.
        logger.info("gemini_mode_code_assist_oauth")
        from src.utils.gemini_code_assist import ChatGeminiCodeAssist

        return ChatGeminiCodeAssist(
            model=config.gemini_model,
            creds_path=config.gemini_oauth_creds_path,
            client_id=config.gemini_oauth_client_id,
            client_secret=config.gemini_oauth_client_secret,
            temperature=temperature,
            max_output_tokens=8192,
        )

    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. Supported: azure, bedrock, ollama, openai, gemini"
        )
