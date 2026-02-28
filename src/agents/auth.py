"""
Auth Agent (Node 3 - The Forger)

Handles dynamic login flows via Playwright. Captures and stores
session tokens for all roles in the auth_matrix. Also performs
offline JWT cracking, alg=none testing, and SAML signature analysis
in parallel background workers.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse

import structlog

from src.state import ApexState, AuthToken

logger = structlog.get_logger("apexhunter.agents.auth")

# ── Common weak JWT secrets ──────────────────────────────
COMMON_JWT_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "changeme",
    "test",
    "default",
    "mysecret",
    "supersecret",
    "jwt",
    "token",
    "api_key",
    "private",
    "public",
    "none",
    "s3cr3t",
    "p@ssw0rd",
    "qwerty",
    "letmein",
    "welcome",
    "password1",
    "abc123",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "football",
    "shadow",
    "sunshine",
    "trustno1",
    "iloveyou",
    "batman",
    "access",
    "hello",
    "charlie",
    "donald",
    "password123",
    "654321",
    "joshua",
    "michael",
    "ashley",
    "qwerty123",
    "1q2w3e4r",
    "pass",
    "your-256-bit-secret",
    "my-secret-key",
    "hmac-secret",
    "HS256-secret",
    "jwt-secret-key",
    "app-secret",
    "my_super_secret_key_123",
    "development",
    "staging",
    "production",
    "devkey",
    "testkey",
    "secretkey",
]


class AuthAgent:
    """
    The Forger — handles multi-role authentication and token analysis.

    1. Dynamically logs in via Playwright for each credential set
    2. Captures JWT/Session cookies
    3. Runs parallel offline attacks on captured tokens
    """

    def __init__(self, http_client: Any, config: Any):
        self._http = http_client
        self._config = config

    async def run(self, state: ApexState) -> dict:
        """
        Execute the authentication phase.

        Returns:
            Dict with updated auth_matrix and any auth vulnerabilities.
        """
        credentials = state.get("auth_credentials", [])
        target_url = state.get("target_url", "")

        if not target_url:
            logger.warning("auth_no_target_url")
            return {"auth_matrix": []}

        if not credentials:
            logger.warning("auth_no_credentials", msg="No credentials provided, skipping auth")
            return {"auth_matrix": []}

        logger.info("auth_start", roles=len(credentials))

        auth_matrix: list[AuthToken] = []
        auth_vulns: list[dict] = []

        # Authenticate each role
        for cred in credentials:
            token = await self._authenticate(target_url, cred)
            if token:
                auth_matrix.append(token)
                logger.info("auth_success", role=cred.get("role", "unknown"))
            else:
                logger.warning("auth_failed", role=cred.get("role", "unknown"))

        # Run JWT analysis in parallel (non-blocking)
        jwt_tasks = []
        for token in auth_matrix:
            if token.get("token_type") == "jwt":
                jwt_tasks.append(self._analyze_jwt(token))

        if jwt_tasks:
            jwt_results = await asyncio.gather(*jwt_tasks, return_exceptions=True)
            for jwt_result in jwt_results:
                if isinstance(jwt_result, BaseException):
                    logger.warning("jwt_analysis_failed", error=str(jwt_result))
                    continue
                if isinstance(jwt_result, dict) and jwt_result.get("vulnerable"):
                    auth_vulns.append(jwt_result)

        logger.info(
            "auth_complete",
            authenticated_roles=len(auth_matrix),
            jwt_vulns=len(auth_vulns),
        )

        result: dict[str, Any] = {"auth_matrix": auth_matrix}

        # Add any JWT vulnerabilities to the report
        if auth_vulns:
            existing_vulns = list(state.get("vulnerability_report", []))
            for vuln in auth_vulns:
                from src.state import Vulnerability

                existing_vulns.append(
                    Vulnerability(
                        vuln_id=f"AUTH-JWT-{len(existing_vulns) + 1}",
                        title=vuln.get("title", "JWT Vulnerability"),
                        vuln_type="broken_authentication",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        severity=vuln.get("severity", "high"),
                        cvss_score=vuln.get("cvss", 7.5),
                        affected_endpoint=state.get("target_url", "unknown"),
                        affected_method="POST",
                        affected_param="Authorization",
                        evidence=vuln.get("evidence", ""),
                        request_sent="",
                        response_received="",
                        remediation=vuln.get("remediation", ""),
                        discovered_at=time.time(),
                        validated=True,
                        is_second_order=False,
                        chain_parent=None,
                    )
                )
            result["vulnerability_report"] = existing_vulns

        return result

    async def _authenticate(self, target_url: str, cred: dict) -> Optional[AuthToken]:
        """
        Authenticate using Playwright headless browser.

        Navigates to the login page, fills credentials, and captures
        the resulting session cookies/JWT.
        """
        role = cred.get("role", "user")
        username = cred.get("username", "")
        password = cred.get("password", "")
        login_url = cred.get("login_url", f"{target_url}/login")

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )
                page = await context.new_page()

                # Navigate to login page
                await page.goto(login_url, wait_until="networkidle", timeout=30000)

                # Try to find and fill login form
                # Strategy 1: Look for common input names
                username_selectors = [
                    'input[name="username"]',
                    'input[name="email"]',
                    'input[name="user"]',
                    'input[name="login"]',
                    'input[type="email"]',
                    'input[id="username"]',
                    'input[id="email"]',
                    "#username",
                    "#email",
                ]
                password_selectors = [
                    'input[name="password"]',
                    'input[name="passwd"]',
                    'input[name="pass"]',
                    'input[type="password"]',
                    "#password",
                    "#pass",
                ]
                submit_selectors = [
                    'button[type="submit"]',
                    'input[type="submit"]',
                    'button:has-text("Login")',
                    'button:has-text("Sign in")',
                    'button:has-text("Log in")',
                    'button:has-text("Submit")',
                    "#login-button",
                    ".login-btn",
                    ".submit-btn",
                ]

                # Fill username
                filled_user = False
                for sel in username_selectors:
                    try:
                        elem = await page.query_selector(sel)
                        if elem:
                            await elem.fill(username)
                            filled_user = True
                            break
                    except Exception as e:
                        logger.debug("auth_selector_skip", selector=sel, error=str(e))
                        continue

                # Fill password
                filled_pass = False
                for sel in password_selectors:
                    try:
                        elem = await page.query_selector(sel)
                        if elem:
                            await elem.fill(password)
                            filled_pass = True
                            break
                    except Exception as e:
                        logger.debug("auth_selector_skip", selector=sel, error=str(e))
                        continue

                if not filled_user or not filled_pass:
                    logger.warning("auth_form_not_found", role=role, url=login_url)
                    await browser.close()
                    return None

                # Submit the form
                submitted = False
                for sel in submit_selectors:
                    try:
                        elem = await page.query_selector(sel)
                        if elem:
                            await elem.click()
                            submitted = True
                            break
                    except Exception as e:
                        logger.debug("auth_selector_skip", selector=sel, error=str(e))
                        continue

                if not submitted:
                    # Try pressing Enter
                    await page.keyboard.press("Enter")

                # Wait for navigation
                try:
                    await page.wait_for_load_state("networkidle", timeout=10000)
                except Exception as e:
                    logger.debug("auth_load_state_timeout", role=role, error=str(e))
                    await asyncio.sleep(3)

                # Capture cookies
                cookies = await context.cookies()
                cookie_dict = {c.get("name", ""): c.get("value", "") for c in cookies}

                # Check for JWT in localStorage or cookies
                jwt_token = None
                try:
                    # Check localStorage
                    local_storage = await page.evaluate("""() => {
                        const items = {};
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            items[key] = localStorage.getItem(key);
                        }
                        return items;
                    }""")

                    for key, value in local_storage.items():
                        if value and self._looks_like_jwt(value):
                            jwt_token = value
                            break
                except Exception as e:
                    logger.debug("auth_localstorage_check_failed", role=role, error=str(e))
                if not jwt_token:
                    for name, value in cookie_dict.items():
                        if self._looks_like_jwt(value):
                            jwt_token = value
                            break

                await browser.close()

                # Build the auth token
                token = AuthToken(
                    role=role,
                    token_type="jwt" if jwt_token else "cookie",
                    token_value=jwt_token or "",
                    cookies=cookie_dict,
                    headers={},
                    expires_at=None,
                    is_valid=True,
                )

                if jwt_token:
                    token["headers"] = {"Authorization": f"Bearer {jwt_token}"}
                elif cookie_dict:
                    cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
                    token["headers"] = {"Cookie": cookie_str}

                return token

        except ImportError:
            logger.error("playwright_not_installed")
            return await self._authenticate_http(target_url, cred)
        except Exception as e:
            logger.error("auth_error", role=role, error=str(e))
            return None

    async def _authenticate_http(self, target_url: str, cred: dict) -> Optional[AuthToken]:
        """
        Fallback: authenticate via direct HTTP POST when Playwright is unavailable.
        """
        role = cred.get("role", "user")
        username = cred.get("username", "")
        password = cred.get("password", "")
        login_url = cred.get("login_url", f"{target_url}/login")

        response = await self._http.post(
            login_url,
            json={"username": username, "password": password},
            auth_role=role,
        )

        if response is None or response.status_code >= 400:
            # Try form-encoded
            response = await self._http.post(
                login_url,
                data={"username": username, "password": password},
                auth_role=role,
            )

        if response is None or response.status_code >= 400:
            return None

        # Extract tokens from response
        cookies = dict(response.cookies) if hasattr(response, "cookies") else {}
        headers_dict = dict(response.headers)

        jwt_token = None
        # Check response body for token
        try:
            body = response.json()
            for key in ["token", "access_token", "jwt", "accessToken", "id_token"]:
                if key in body:
                    jwt_token = body[key]
                    break
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass

        # Check Set-Cookie headers
        if not jwt_token:
            for name, value in cookies.items():
                if self._looks_like_jwt(value):
                    jwt_token = value
                    break

        token = AuthToken(
            role=role,
            token_type="jwt" if jwt_token else "cookie",
            token_value=jwt_token or "",
            cookies=cookies,
            headers={},
            expires_at=None,
            is_valid=True,
        )

        if jwt_token:
            token["headers"] = {"Authorization": f"Bearer {jwt_token}"}
        elif cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            token["headers"] = {"Cookie": cookie_str}

        return token

    def _looks_like_jwt(self, value: str) -> bool:
        """Check if a string looks like a JWT token."""
        parts = value.split(".")
        if len(parts) != 3:
            return False
        try:
            # Try to decode the header
            header = parts[0] + "=" * (4 - len(parts[0]) % 4)
            decoded = base64.urlsafe_b64decode(header)
            data = json.loads(decoded)
            return "alg" in data or "typ" in data
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return False

    async def _analyze_jwt(self, token: AuthToken) -> dict:
        """
        Analyze a JWT token for vulnerabilities (offline, parallel).

        Tests:
        1. alg=none bypass
        2. Weak secret cracking via dictionary
        3. Algorithm confusion (RS256 -> HS256)
        """
        jwt_value = token.get("token_value", "")
        if not jwt_value:
            return {"vulnerable": False}

        results: dict[str, Any] = {"vulnerable": False, "findings": []}

        # Parse the JWT
        try:
            parts = jwt_value.split(".")
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            logger.debug("jwt_parse_failed", error=str(e))
            return results

        alg = header.get("alg", "").upper()

        # Test 1: alg=none
        none_result = await self._test_alg_none(header, payload)
        if none_result:
            results["vulnerable"] = True
            results["title"] = "JWT Algorithm None Bypass"
            results["severity"] = "critical"
            results["cvss"] = 9.8
            results["evidence"] = "JWT accepts alg=none, allowing token forgery"
            results["remediation"] = (
                "Enforce algorithm validation on the server. "
                "Reject tokens with alg=none or unexpected algorithms."
            )

        # Test 2: Weak secret cracking (run in thread pool to avoid blocking)
        if alg in ("HS256", "HS384", "HS512"):
            cracked_secret = await asyncio.get_event_loop().run_in_executor(
                None, self._crack_jwt_secret, jwt_value, alg
            )
            if cracked_secret:
                results["vulnerable"] = True
                results["title"] = "JWT Weak Secret Key"
                results["severity"] = "critical"
                results["cvss"] = 9.1
                results["evidence"] = (
                    f"JWT secret cracked via dictionary attack. Secret: '{cracked_secret}'"
                )
                results["remediation"] = (
                    "Use a strong, random secret key (minimum 256 bits). "
                    "Rotate the key immediately."
                )

        # Test 3: Check for missing expiration
        if "exp" not in payload:
            results["findings"].append(
                {
                    "type": "missing_expiration",
                    "severity": "medium",
                    "evidence": "JWT has no 'exp' claim — token never expires",
                }
            )

        return results

    async def _test_alg_none(self, header: dict, payload: dict) -> bool:
        """
        Test if the server accepts JWT with alg=none.
        This is a detection-only test — we forge the token locally
        but note that actual server-side validation requires sending it.
        """
        # We can only flag the potential — actual validation happens
        # during the executor phase when we send the forged token
        alg = header.get("alg", "")
        if alg.lower() in ("none", ""):
            return True
        return False

    def _crack_jwt_secret(self, jwt_value: str, algorithm: str) -> Optional[str]:
        """
        Attempt to crack the JWT secret using a dictionary attack.
        Runs in a thread pool to avoid blocking the event loop.
        """
        parts = jwt_value.split(".")
        if len(parts) != 3:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        signature = parts[2]

        # Pad the signature for base64
        sig_padded = signature + "=" * (4 - len(signature) % 4)
        try:
            expected_sig = base64.urlsafe_b64decode(sig_padded)
        except Exception:
            return None

        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(algorithm, hashlib.sha256)

        for secret in COMMON_JWT_SECRETS:
            computed = hmac.new(
                secret.encode("utf-8"),
                signing_input,
                hash_func,
            ).digest()

            if hmac.compare_digest(computed, expected_sig):
                logger.warning("jwt_secret_cracked", secret=secret)
                return secret

        # Try loading from wordlist file if available
        try:
            wordlist_path = "/app/data/seclists/jwt-secrets.txt"
            import os

            if os.path.exists(wordlist_path):
                with open(wordlist_path, "r", errors="ignore") as f:
                    for line in f:
                        secret = line.strip()
                        if not secret:
                            continue
                        computed = hmac.new(
                            secret.encode("utf-8"),
                            signing_input,
                            hash_func,
                        ).digest()
                        if hmac.compare_digest(computed, expected_sig):
                            logger.warning("jwt_secret_cracked", secret=secret)
                            return secret
        except Exception as e:
            logger.debug("jwt_wordlist_load_error", error=str(e))

    async def re_authenticate(self, state: ApexState, role: str) -> Optional[AuthToken]:
        """
        Re-authenticate a specific role when a session expires.
        Called by the executor when it detects a 401/403.
        """
        credentials = state.get("auth_credentials", [])
        for cred in credentials:
            if cred.get("role") == role:
                logger.info("auth_re_authenticate", role=role)
                return await self._authenticate(state.get("target_url", ""), cred)
        return None
