"""
ApexHunter CLI Entry Point

The main entry point for the ApexHunter DAST Agent.
Accepts a JSON configuration file or CLI arguments to configure
the target, credentials, and LLM providers.

Usage:
    python -m src.main --config scan_config.json
    python -m src.main --target https://example.com --scope "^https?://(.*\\.)?example\\.com"
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from typing import Optional

import click

from src.state import create_initial_state
from src.utils.config import ApexConfig
from src.utils.logger import setup_logging


BANNER = r"""
    ___                  __  __            __
   /   |  ____  ___  _  / / / /_  ______  / /____  _____
  / /| | / __ \/ _ \| |/_/ /_/ / / / __ \/ __/ _ \/ ___/
 / ___ |/ /_/ /  __/>  </ __  / /_/ / / / / /  __/ /
/_/  |_/ .___/\___/_/|_/_/ /_/\__,_/_/ /_/\__/\___/_/
      /_/

  Autonomous Non-Destructive Penetration Testing Agent v1.0
  ──────────────────────────────────────────────────────────
"""


@click.command()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Path to JSON configuration file",
)
@click.option(
    "--target",
    "-t",
    type=str,
    help="Target URL (e.g., https://example.com)",
)
@click.option(
    "--scope",
    "-s",
    type=str,
    help="Scope regex (e.g., '^https?://(.*\\.)?example\\.com')",
)
@click.option(
    "--creds",
    "-u",
    type=str,
    multiple=True,
    help="Credentials in format 'role:username:password' (can specify multiple)",
)
@click.option(
    "--resume",
    type=str,
    default=None,
    help="Resume a previous scan by scan ID",
)
@click.option(
    "--output",
    "-o",
    type=str,
    default=None,
    help="Output directory for reports",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level",
)
def main(
    config: Optional[str],
    target: Optional[str],
    scope: Optional[str],
    creds: tuple,
    resume: Optional[str],
    output: Optional[str],
    log_level: str,
):
    """ApexHunter - Autonomous Non-Destructive Penetration Testing Agent."""
    print(BANNER)

    # Setup logging
    log_dir = os.environ.get("APEX_LOG_DIR", "/app/logs")
    setup_logging(log_dir=log_dir, log_level=log_level)

    # Load configuration
    if config:
        scan_config = _load_config_file(config)
    elif target:
        scan_config = _build_config_from_cli(target, scope, creds)
    else:
        click.echo("Error: Either --config or --target is required.")
        click.echo(
            "Usage: python -m src.main --target https://example.com --scope '^https?://example\\.com'"
        )
        sys.exit(1)

    # Override output dir if specified
    if output:
        os.environ["APEX_OUTPUT_DIR"] = output

    # Build the ApexConfig
    try:
        apex_config = ApexConfig(
            target_url=scan_config.get("target_url", ""),
            target_scope=scan_config.get("target_scope", ""),
            credentials=scan_config.get("credentials", []),
        )
    except Exception as e:
        click.echo(f"Configuration error: {e}")
        sys.exit(1)

    # Generate or resume scan ID
    scan_id = resume or uuid.uuid4().hex[:12]

    click.echo(f"  Target:   {scan_config.get('target_url', 'N/A')}")
    click.echo(f"  Scope:    {scan_config.get('target_scope', 'N/A')}")
    click.echo(f"  Scan ID:  {scan_id}")
    click.echo(f"  Creds:    {len(scan_config.get('credentials', []))} role(s)")
    click.echo(f"  Planner:  {apex_config.llm.planner_provider}")
    click.echo(f"  Executor: {apex_config.llm.executor_provider}")
    click.echo("─" * 58)
    click.echo()

    # Run the scan
    asyncio.run(_run_scan(apex_config, scan_config, scan_id, resume))


async def _run_scan(
    apex_config: ApexConfig,
    scan_config: dict,
    scan_id: str,
    resume_id: Optional[str],
):
    """Execute the ApexHunter scan."""
    from src.graph import build_graph
    from src.state import create_initial_state

    # Create initial state
    initial_state = create_initial_state(
        target_url=scan_config.get("target_url", ""),
        target_scope=scan_config.get("target_scope", ""),
        credentials=scan_config.get("credentials", []),
        scan_id=scan_id,
    )

    # Build the graph
    graph = build_graph(apex_config)

    # Setup checkpointer for state persistence
    checkpointer = None
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        db_path = os.path.join(apex_config.paths.state_dir, f"apex_{scan_id}.db")
        checkpointer = AsyncSqliteSaver.from_conn_string(db_path)
    except ImportError:
        click.echo("  Warning: SQLite checkpointer unavailable. State will not persist.")

    # Configure execution
    config = {"configurable": {"thread_id": scan_id}}

    click.echo("  Starting autonomous scan...")
    click.echo("  Press Ctrl+C to gracefully stop.\n")

    start_time = time.time()

    try:
        if checkpointer:
            # Check for existing state (resume)
            if resume_id:
                click.echo(f"  Attempting to resume scan {resume_id}...")

            async with checkpointer as saver:
                graph_with_cp = build_graph(apex_config)
                # Run with checkpointer
                result = await graph_with_cp.ainvoke(
                    initial_state,
                    config=config,
                )
        else:
            # Run without checkpointer
            result = await graph.ainvoke(initial_state, config=config)

        elapsed = time.time() - start_time
        click.echo(f"\n  Scan completed in {elapsed:.1f}s")

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        click.echo(f"\n  Scan interrupted after {elapsed:.1f}s")
        click.echo("  State has been checkpointed. Use --resume to continue.")
    except Exception as e:
        elapsed = time.time() - start_time
        click.echo(f"\n  Scan failed after {elapsed:.1f}s: {e}")
        raise


def _load_config_file(path: str) -> dict:
    """Load scan configuration from a JSON file."""
    with open(path, "r") as f:
        data = json.load(f)

    required = ["target_url", "target_scope"]
    for key in required:
        if key not in data:
            raise click.ClickException(f"Missing required key '{key}' in config file")

    return data


def _build_config_from_cli(
    target: str,
    scope: Optional[str],
    creds: tuple,
) -> dict:
    """Build scan configuration from CLI arguments."""
    from urllib.parse import urlparse

    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        raise click.ClickException(f"Invalid target URL: {target}")

    # Auto-generate scope if not provided
    if not scope:
        domain = parsed.netloc.replace(".", "\\.")
        scope = f"^https?://(.*\\.)?{domain}"

    # Parse credentials
    credentials = []
    for cred_str in creds:
        parts = cred_str.split(":", 2)
        if len(parts) == 3:
            credentials.append(
                {
                    "role": parts[0],
                    "username": parts[1],
                    "password": parts[2],
                }
            )
        elif len(parts) == 2:
            credentials.append(
                {
                    "role": "user",
                    "username": parts[0],
                    "password": parts[1],
                }
            )
        else:
            raise click.ClickException(
                f"Invalid credential format: '{cred_str}'. "
                f"Use 'role:username:password' or 'username:password'"
            )

    return {
        "target_url": target,
        "target_scope": scope,
        "credentials": credentials,
    }


if __name__ == "__main__":
    main()
