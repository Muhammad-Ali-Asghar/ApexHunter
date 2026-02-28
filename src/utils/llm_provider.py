"""
LLM Provider Factory

Creates and returns the appropriate LangChain ChatModel based on
the configured provider (Azure OpenAI, AWS Bedrock, or local Ollama).
Separates "planner" (heavy reasoning) from "executor" (fast, cheap).
"""

from __future__ import annotations

from typing import Optional

import structlog
from langchain_core.language_models.chat_models import BaseChatModel

from src.utils.config import LLMProviderConfig

logger = structlog.get_logger("apexhunter.utils.llm_provider")


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
        provider: One of "azure", "bedrock", "ollama".
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

    else:
        raise ValueError(
            f"Unknown LLM provider '{provider}'. "
            f"Supported: azure, bedrock, ollama, openai"
        )
