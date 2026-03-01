"""
Gemini Code Assist LangChain ChatModel

Custom LangChain BaseChatModel that uses Google's internal Code Assist API
(cloudcode-pa.googleapis.com) with OAuth tokens from the Gemini CLI.

This is the same API endpoint the Gemini CLI and OpenCode use. It accepts
OAuth bearer tokens from the Gemini CLI's OAuth flow, bypassing the need
for API keys or GCP Vertex AI project setup.

Flow:
  1. Load OAuth tokens from ~/.gemini/oauth_creds.json
  2. Refresh the access token if expired
  3. Call /v1internal:loadCodeAssist to get the project ID
  4. Call /v1internal:generateContent with the Gemini API request
     wrapped in a Code Assist envelope: { project, model, request }
  5. Unwrap the response envelope and return standard Gemini format
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Iterator, List, Optional

import requests as http_requests
import structlog
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import PrivateAttr

logger = structlog.get_logger("apexhunter.utils.gemini_code_assist")

_CODE_ASSIST_BASE = "https://cloudcode-pa.googleapis.com"
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"

_CODE_ASSIST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "google-api-nodejs-client/9.15.1",
    "X-Goog-Api-Client": "gl-node/22.17.0",
    "Client-Metadata": ("ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI"),
}


def _load_and_refresh_credentials(
    creds_path: str,
    client_id: str,
    client_secret: str,
):
    """Load OAuth creds from Gemini CLI and refresh the access token."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    expanded = os.path.expanduser(creds_path)
    if not os.path.exists(expanded):
        raise FileNotFoundError(
            f"Gemini CLI OAuth credentials not found at {expanded}. "
            f"Run `gemini` once to authenticate via the browser OAuth flow."
        )

    with open(expanded, "r") as f:
        data = json.load(f)

    refresh_token = data.get("refresh_token")
    if not refresh_token:
        raise ValueError(f"No refresh_token in {expanded}. Re-run `gemini` to re-authenticate.")

    creds = Credentials(
        token=data.get("access_token"),
        refresh_token=refresh_token,
        token_uri=_GOOGLE_TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    # Always refresh to ensure a valid token
    creds.refresh(Request())
    return creds


def _discover_project(access_token: str) -> str:
    """Call loadCodeAssist to discover the Code Assist project ID."""
    resp = http_requests.post(
        f"{_CODE_ASSIST_BASE}/v1internal:loadCodeAssist",
        headers={
            "Authorization": f"Bearer {access_token}",
            **_CODE_ASSIST_HEADERS,
        },
        json={},
        timeout=30,
    )
    resp.raise_for_status()
    project = resp.json().get("cloudaicompanionProject")
    if not project:
        raise ValueError(
            "loadCodeAssist did not return a cloudaicompanionProject. "
            "Ensure the Gemini CLI has been authenticated at least once."
        )
    return project


def _messages_to_contents(messages: List[BaseMessage]) -> tuple[Optional[str], list]:
    """
    Convert LangChain messages to Gemini API contents format.

    Returns (system_instruction_text, contents_list).
    """
    system_text = None
    contents = []

    for msg in messages:
        if isinstance(msg, SystemMessage):
            # Gemini uses systemInstruction, not a system role in contents
            system_text = msg.content if isinstance(msg.content, str) else str(msg.content)
        elif isinstance(msg, HumanMessage):
            text = msg.content if isinstance(msg.content, str) else str(msg.content)
            contents.append(
                {
                    "role": "user",
                    "parts": [{"text": text}],
                }
            )
        elif isinstance(msg, AIMessage):
            text = msg.content if isinstance(msg.content, str) else str(msg.content)
            contents.append(
                {
                    "role": "model",
                    "parts": [{"text": text}],
                }
            )
        else:
            # ToolMessage, FunctionMessage, etc. — treat as user
            text = msg.content if isinstance(msg.content, str) else str(msg.content)
            contents.append(
                {
                    "role": "user",
                    "parts": [{"text": text}],
                }
            )

    return system_text, contents


class ChatGeminiCodeAssist(BaseChatModel):
    """
    LangChain ChatModel that calls Google's Code Assist API
    using Gemini CLI OAuth tokens.

    Usage:
        llm = ChatGeminiCodeAssist(
            model="gemini-2.5-flash",
            creds_path="~/.gemini/oauth_creds.json",
            client_id="...",
            client_secret="...",
        )
        result = llm.invoke("Hello!")
    """

    model: str = "gemini-2.5-flash"
    creds_path: str = "~/.gemini/oauth_creds.json"
    client_id: str = ""
    client_secret: str = ""
    temperature: float = 0.1
    max_output_tokens: int = 8192

    # Internal state (Pydantic PrivateAttr — not serialized, uses factories)
    _access_token: Optional[str] = PrivateAttr(default=None)
    _project_id: Optional[str] = PrivateAttr(default=None)
    _credentials: Any = PrivateAttr(default=None)
    _lock: threading.Lock = PrivateAttr(default_factory=threading.Lock)

    class Config:
        arbitrary_types_allowed = True

    def _ensure_auth(self) -> tuple[str, str]:
        """Ensure we have a valid access token and project ID."""
        with self._lock:
            needs_refresh = (
                self._credentials is None or self._access_token is None or self._credentials.expired
            )

            if needs_refresh:
                logger.debug("gemini_code_assist_refreshing_token")
                self._credentials = _load_and_refresh_credentials(
                    self.creds_path, self.client_id, self.client_secret
                )
                self._access_token = self._credentials.token
                logger.info(
                    "gemini_code_assist_token_refreshed",
                    token_prefix=self._access_token[:15] + "...",
                )

            if self._project_id is None:
                assert self._access_token is not None
                self._project_id = _discover_project(self._access_token)
                logger.info(
                    "gemini_code_assist_project_discovered",
                    project=self._project_id,
                )

            if needs_refresh:
                logger.debug("gemini_code_assist_refreshing_token")
                self._credentials = _load_and_refresh_credentials(
                    self.creds_path, self.client_id, self.client_secret
                )
                self._access_token = self._credentials.token
                logger.info(
                    "gemini_code_assist_token_refreshed",
                    token_prefix=self._access_token[:15] + "...",
                )

            if self._project_id is None:
                self._project_id = _discover_project(self._access_token)
                logger.info(
                    "gemini_code_assist_project_discovered",
                    project=self._project_id,
                )

            return self._access_token, self._project_id

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForLLMRun] = None,
        **kwargs: Any,
    ) -> ChatResult:
        access_token, project_id = self._ensure_auth()

        system_text, contents = _messages_to_contents(messages)

        # Build the inner Gemini request
        inner_request: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
            },
        }

        if system_text:
            inner_request["systemInstruction"] = {
                "parts": [{"text": system_text}],
            }

        if stop:
            inner_request["generationConfig"]["stopSequences"] = stop

        # Wrap in Code Assist envelope
        payload = {
            "project": project_id,
            "model": self.model,
            "request": inner_request,
        }

        logger.debug(
            "gemini_code_assist_request",
            model=self.model,
            project=project_id,
            messages_count=len(contents),
        )

        resp = http_requests.post(
            f"{_CODE_ASSIST_BASE}/v1internal:generateContent",
            headers={
                "Authorization": f"Bearer {access_token}",
                **_CODE_ASSIST_HEADERS,
            },
            json=payload,
            timeout=300,
        )

        if resp.status_code == 401:
            # Token expired mid-request — force refresh and retry once
            logger.warning("gemini_code_assist_401_retrying")
            with self._lock:
                self._credentials = None
                self._access_token = None
            access_token, project_id = self._ensure_auth()
            payload["project"] = project_id

            resp = http_requests.post(
                f"{_CODE_ASSIST_BASE}/v1internal:generateContent",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    **_CODE_ASSIST_HEADERS,
                },
                json=payload,
                timeout=300,
            )

        resp.raise_for_status()
        result = resp.json()

        # Unwrap Code Assist envelope
        inner_response = result.get("response", result)
        candidates = inner_response.get("candidates", [])

        if not candidates:
            logger.warning("gemini_code_assist_no_candidates", response=result)
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])

        # Extract the text from the first candidate
        first = candidates[0]
        parts = first.get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts)

        # Extract usage metadata
        usage = inner_response.get("usageMetadata", {})
        llm_output = {
            "model": inner_response.get("modelVersion", self.model),
            "usage": {
                "prompt_tokens": usage.get("promptTokenCount", 0),
                "completion_tokens": usage.get("candidatesTokenCount", 0),
                "total_tokens": usage.get("totalTokenCount", 0),
            },
        }

        logger.info(
            "gemini_code_assist_response",
            model=inner_response.get("modelVersion", self.model),
            prompt_tokens=usage.get("promptTokenCount", 0),
            completion_tokens=usage.get("candidatesTokenCount", 0),
            finish_reason=first.get("finishReason", ""),
        )

        return ChatResult(
            generations=[ChatGeneration(message=AIMessage(content=text))],
            llm_output=llm_output,
        )

    @property
    def _llm_type(self) -> str:
        return "gemini-code-assist"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
        }
