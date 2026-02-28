"""
Structured Logger

Provides consistent, structured logging across all ApexHunter modules
using structlog. All logs are JSON-formatted for easy parsing.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog


def setup_logging(log_dir: str = "/app/logs", log_level: str = "INFO") -> None:
    """
    Configure structured logging for the entire application.

    Args:
        log_dir: Directory to write log files.
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR).
    """
    os.makedirs(log_dir, exist_ok=True)

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    # File handler for persistent logs
    file_handler = logging.FileHandler(
        os.path.join(log_dir, "apexhunter.log"),
        mode="a",
    )
    file_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(file_handler)

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
