"""
Semantic Attack Surface Reducer (Node 7)

Analyzes thousands of endpoints from Recon/Fuzzing and mathematically
clusters structurally identical endpoints (e.g., /user/1, /user/2 -> /user/{id}).
Prevents LLM context overflow by passing only unique business logic flows.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, parse_qs

import structlog

from src.state import ApexState, Endpoint

logger = structlog.get_logger("apexhunter.agents.reducer")


class ReducerAgent:
    """
    The Semantic Attack Surface Reducer.

    Takes thousands of raw endpoints and reduces them to unique
    business logic templates that the LLM Planner can reason about
    without context overflow.
    """

    def run(self, state: ApexState) -> dict:
        """Execute the attack surface reduction."""
        endpoints = list(state.get("discovered_endpoints", []))
        hidden = list(state.get("hidden_surface_map", []))
        all_endpoints = endpoints + hidden

        logger.info("reducer_start", total_endpoints=len(all_endpoints))

        # Phase 1: Normalize and extract URL templates
        templates: dict[str, dict[str, Any]] = {}
        for ep in all_endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            if not url:
                continue

            template = self._url_to_template(url)
            key = f"{method}:{template}"

            if key not in templates:
                templates[key] = {
                    "template": template,
                    "method": method,
                    "example_url": url,
                    "params": ep.get("params", []),
                    "content_type": ep.get("content_type", ""),
                    "requires_auth": ep.get("requires_auth", False),
                    "source": ep.get("source", ""),
                    "occurrences": 0,
                    "sample_values": {},
                }

            templates[key]["occurrences"] += 1

            # Collect sample values for parameterized segments
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")
            template_parts = template.strip("/").split("/")
            for i, (actual, tmpl) in enumerate(zip(path_parts, template_parts)):
                if tmpl.startswith("{") and tmpl.endswith("}"):
                    param_name = tmpl[1:-1]
                    if param_name not in templates[key]["sample_values"]:
                        templates[key]["sample_values"][param_name] = []
                    if actual not in templates[key]["sample_values"][param_name]:
                        templates[key]["sample_values"][param_name].append(actual)
                        # Keep only 5 samples
                        templates[key]["sample_values"][param_name] = templates[key][
                            "sample_values"
                        ][param_name][:5]

        # Phase 2: Merge parameters from multiple occurrences
        reduced_surface = []
        for key, data in templates.items():
            reduced_surface.append(
                {
                    "template": data["template"],
                    "method": data["method"],
                    "example_url": data["example_url"],
                    "params": data["params"],
                    "content_type": data["content_type"],
                    "requires_auth": data["requires_auth"],
                    "source": data["source"],
                    "occurrences": data["occurrences"],
                    "sample_values": data["sample_values"],
                }
            )

        # Sort by importance (endpoints with params first, then by occurrences)
        reduced_surface.sort(
            key=lambda x: (
                len(x.get("params", [])) > 0,
                x.get("occurrences", 0),
            ),
            reverse=True,
        )

        logger.info(
            "reducer_complete",
            original=len(all_endpoints),
            reduced=len(reduced_surface),
            reduction_ratio=f"{(1 - len(reduced_surface) / max(len(all_endpoints), 1)) * 100:.1f}%",
        )

        return {
            "reduced_attack_surface": reduced_surface,
            "untested_surface": list(reduced_surface),
            "current_phase": "reduction_complete",
        }

    def _url_to_template(self, url: str) -> str:
        """
        Convert a URL to a parameterized template.

        Examples:
            /api/users/123/profile -> /api/users/{id}/profile
            /products/abc-shoe-42 -> /products/{slug}
            /v1/orders/2024-01-15 -> /v1/orders/{date}
        """
        parsed = urlparse(url)
        path = parsed.path

        parts = path.strip("/").split("/")
        template_parts = []

        for part in parts:
            if not part:
                continue

            # Pure numeric -> {id}
            if re.match(r"^\d+$", part):
                template_parts.append("{id}")
            # UUID
            elif re.match(
                r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                part,
                re.IGNORECASE,
            ):
                template_parts.append("{uuid}")
            # Date-like
            elif re.match(r"^\d{4}-\d{2}-\d{2}$", part):
                template_parts.append("{date}")
            # Hex hash (e.g., commit SHAs, object IDs)
            elif re.match(r"^[0-9a-f]{24,}$", part, re.IGNORECASE):
                template_parts.append("{hash}")
            # Email-like
            elif re.match(r"^[^@]+@[^@]+\.[^@]+$", part):
                template_parts.append("{email}")
            # Slug with numbers (e.g., product-name-42)
            elif re.match(r"^[a-z0-9]+-[a-z0-9-]+-\d+$", part, re.IGNORECASE):
                template_parts.append("{slug}")
            # Base64-encoded token
            elif re.match(r"^[A-Za-z0-9+/=]{20,}$", part):
                template_parts.append("{token}")
            # Generic alphanumeric with mixed case (likely an ID)
            elif re.match(r"^[A-Za-z0-9]{16,}$", part):
                template_parts.append("{object_id}")
            else:
                template_parts.append(part)

        return "/" + "/".join(template_parts) if template_parts else "/"
