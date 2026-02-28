"""
JIT (Just-In-Time) Tool Installer (Node 9)

At runtime, the agent checks if a required CLI tool is installed.
If missing, it dynamically generates and executes the installation
command within the Docker container. Self-healing infrastructure.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Optional

import structlog

logger = structlog.get_logger("apexhunter.tools.jit_installer")

# ── Known Tool Registry ──────────────────────────────────
# Maps tool names to their installation commands and verification commands.
TOOL_REGISTRY: dict[str, dict[str, str]] = {
    "nuclei": {
        "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "verify": "nuclei -version",
        "description": "Template-based vulnerability scanner",
    },
    "ffuf": {
        "install": "go install -v github.com/ffuf/ffuf/v2@latest",
        "verify": "ffuf -V",
        "description": "Fast web fuzzer for directory/parameter brute-forcing",
    },
    "httpx-toolkit": {
        "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "verify": "httpx -version",
        "description": "HTTP probe and technology detection",
    },
    "subfinder": {
        "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "verify": "subfinder -version",
        "description": "Subdomain discovery tool",
    },
    "interactsh-client": {
        "install": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
        "verify": "interactsh-client -version",
        "description": "OOB interaction client for blind vulnerability detection",
    },
    "nmap": {
        "install": "apt-get update && apt-get install -y nmap",
        "verify": "nmap --version",
        "description": "Network port scanner and service detection",
    },
    "whatweb": {
        "install": "apt-get update && apt-get install -y whatweb",
        "verify": "whatweb --version",
        "description": "Web technology fingerprinting",
    },
    "wapiti": {
        "install": "pip install wapiti3",
        "verify": "wapiti --version",
        "description": "Web application vulnerability scanner",
    },
    "nikto": {
        "install": "apt-get update && apt-get install -y nikto",
        "verify": "nikto -Version",
        "description": "Web server scanner for dangerous files and misconfigurations",
    },
    "arjun": {
        "install": "pip install arjun",
        "verify": "arjun --help",
        "description": "HTTP parameter discovery suite",
    },
    "wafw00f": {
        "install": "pip install wafw00f",
        "verify": "wafw00f --version",
        "description": "WAF fingerprinting tool",
    },
}


class JITInstaller:
    """
    Just-In-Time tool installer.

    Checks if tools are available, installs them if missing,
    and tracks which tools are ready for the executor.
    """

    def __init__(self):
        self._installed: dict[str, bool] = {}
        self._install_lock = asyncio.Lock()

    def is_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and available on PATH."""
        # Check cache first
        if tool_name in self._installed:
            return self._installed[tool_name]

        # Check if binary exists on PATH
        binary = tool_name
        if tool_name == "httpx-toolkit":
            binary = "httpx"

        found = shutil.which(binary) is not None
        self._installed[tool_name] = found
        return found

    async def ensure_installed(self, tool_name: str) -> bool:
        """
        Ensure a tool is installed. If not, install it.

        Args:
            tool_name: Name of the tool from TOOL_REGISTRY.

        Returns:
            True if the tool is ready, False if installation failed.
        """
        if self.is_installed(tool_name):
            logger.info("tool_already_installed", tool=tool_name)
            return True

        if tool_name not in TOOL_REGISTRY:
            logger.warning("tool_unknown", tool=tool_name)
            return False

        async with self._install_lock:
            # Double-check after acquiring lock
            if self.is_installed(tool_name):
                return True

            registry = TOOL_REGISTRY[tool_name]
            install_cmd = registry["install"]
            verify_cmd = registry["verify"]

            logger.info(
                "jit_installing_tool",
                tool=tool_name,
                command=install_cmd,
            )

            try:
                # Run installation
                proc = await asyncio.create_subprocess_shell(
                    install_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

                if proc.returncode != 0:
                    logger.error(
                        "jit_install_failed",
                        tool=tool_name,
                        returncode=proc.returncode,
                        stderr=stderr.decode("utf-8", errors="replace")[:500],
                    )
                    return False

                # Verify installation
                verify_proc = await asyncio.create_subprocess_shell(
                    verify_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(verify_proc.communicate(), timeout=30)

                if verify_proc.returncode == 0:
                    self._installed[tool_name] = True
                    logger.info("jit_install_success", tool=tool_name)
                    return True
                else:
                    logger.error("jit_verify_failed", tool=tool_name)
                    return False

            except asyncio.TimeoutError:
                logger.error("jit_install_timeout", tool=tool_name)
                return False
            except Exception as e:
                logger.error("jit_install_error", tool=tool_name, error=str(e))
                return False

    async def discover_installed_tools(self) -> list[str]:
        """
        Scan the system for all known tools and return which are installed.
        Called during Node 1 (Initialization).
        """
        installed = []
        for tool_name in TOOL_REGISTRY:
            if self.is_installed(tool_name):
                installed.append(tool_name)
                logger.info("tool_discovered", tool=tool_name)
            else:
                logger.debug("tool_not_found", tool=tool_name)

        return installed

    async def install_all_required(self, tool_names: list[str]) -> dict[str, bool]:
        """
        Attempt to install a list of tools.

        Args:
            tool_names: List of tool names to install.

        Returns:
            Dict mapping tool name to installation success.
        """
        results = {}
        for name in tool_names:
            results[name] = await self.ensure_installed(name)
        return results
