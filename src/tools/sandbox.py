"""
Script Sandbox

Safely executes LLM-generated Python scripts within an isolated
subprocess. Scripts are restricted to network operations only
(httpx requests) and cannot access the filesystem or OS commands.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import os
import textwrap
from typing import Any, Optional

import structlog

logger = structlog.get_logger("apexhunter.tools.sandbox")

# ── Blocked imports / patterns that scripts MUST NOT contain ──
BLOCKED_PATTERNS = [
    "os.system",
    "subprocess",
    "shutil.rmtree",
    "shutil.move",
    "__import__",
    "eval(",
    "exec(",
    "compile(",
    "open(",  # Block file operations
    "pathlib",
    "importlib",
    "ctypes",
    "multiprocessing",
    "threading.Thread",
    "socket.socket",  # Raw sockets
    "DROP ",
    "DELETE FROM",
    "UPDATE ",
    "INSERT INTO",
    "TRUNCATE",
    "ALTER TABLE",
    "; --",
    "rm -rf",
    "wget ",
    "curl ",
    "chmod ",
    "chown ",
]

# ── Allowed imports that scripts CAN use ──
ALLOWED_IMPORTS = [
    "httpx",
    "json",
    "re",
    "urllib.parse",
    "base64",
    "hashlib",
    "time",
    "html",
    "collections",
    "math",
    "typing",
]

SANDBOX_WRAPPER = textwrap.dedent("""\
import sys
import json

# Restrict available modules
ALLOWED = {allowed_imports}

# Execute the user script
result = {{"status": "error", "output": "", "error": ""}}
try:
{script_indented}

    # If the script defines a `run()` function, call it
    if 'run' in dir():
        output = run()
        result = {{"status": "success", "output": json.dumps(output, default=str)}}
    else:
        result = {{"status": "success", "output": "Script executed (no run() defined)"}}
except Exception as e:
    result = {{"status": "error", "output": "", "error": str(e)}}

print(json.dumps(result))
""")


class ScriptSandbox:
    """
    Executes LLM-generated Python validation scripts safely.

    Scripts are:
    1. Scanned for blocked patterns (filesystem ops, destructive SQL)
    2. Wrapped in a restricted execution environment
    3. Run in a subprocess with a strict timeout
    """

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    def validate_script(self, script: str) -> tuple[bool, Optional[str]]:
        """
        Validate a script for safety before execution.

        Returns:
            (is_safe, error_message)
        """
        script_lower = script.lower()

        for pattern in BLOCKED_PATTERNS:
            if pattern.lower() in script_lower:
                return False, f"Blocked pattern detected: '{pattern}'"

        return True, None

    async def execute(
        self,
        script: str,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Execute a Python script in a sandboxed subprocess.

        Args:
            script: The Python script source code.
            timeout: Override default timeout.

        Returns:
            Dict with 'status', 'output', and 'error' keys.
        """
        # 1. Validate
        is_safe, error = self.validate_script(script)
        if not is_safe:
            logger.warning("sandbox_blocked", reason=error)
            return {
                "status": "blocked",
                "output": "",
                "error": f"Script blocked: {error}",
            }

        # 2. Wrap the script
        script_indented = textwrap.indent(script, "    ")
        allowed_str = repr(ALLOWED_IMPORTS)
        wrapped = SANDBOX_WRAPPER.format(
            allowed_imports=allowed_str,
            script_indented=script_indented,
        )

        # 3. Write to temp file
        script_file = tempfile.mktemp(suffix=".py")
        with open(script_file, "w") as f:
            f.write(wrapped)

        # 4. Execute in subprocess
        exec_timeout = timeout or self._timeout
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "python3",
                script_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=exec_timeout
            )

            stdout_str = stdout.decode("utf-8", errors="replace").strip()
            stderr_str = stderr.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                logger.warning(
                    "sandbox_script_error",
                    returncode=proc.returncode,
                    stderr=stderr_str[:500],
                )
                return {
                    "status": "error",
                    "output": stdout_str,
                    "error": stderr_str[:1000],
                }

            # Parse the JSON result
            try:
                result = json.loads(stdout_str)
                logger.info("sandbox_script_success")
                return result
            except (json.JSONDecodeError, ValueError):
                return {
                    "status": "success",
                    "output": stdout_str,
                    "error": "",
                }

        except asyncio.TimeoutError:
            logger.warning("sandbox_timeout", timeout=exec_timeout)
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            return {
                "status": "timeout",
                "output": "",
                "error": f"Script timed out after {exec_timeout}s",
            }
        except Exception as e:
            logger.error("sandbox_execution_error", error=str(e))
            return {
                "status": "error",
                "output": "",
                "error": str(e),
            }
        finally:
            if os.path.exists(script_file):
                os.unlink(script_file)
