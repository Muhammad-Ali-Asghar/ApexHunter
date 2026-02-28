"""
CLI Wrappers

Python wrappers around external CLI tools (Nuclei, Nmap, ffuf, etc.)
that parse their output into structured data for the LangGraph state.

SECURITY NOTE: All user-supplied parameters are passed as discrete
arguments via create_subprocess_exec (never interpolated into a shell
string) to prevent command injection.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import tempfile
import os
from typing import Any, Optional

import structlog

logger = structlog.get_logger("apexhunter.tools.cli_wrappers")


async def _run_command(args: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a command with explicit argument list and return (returncode, stdout, stderr)."""
    logger.debug("cli_exec", cmd=args[0], args_count=len(args))
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            proc.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass
        return -1, "", "Command timed out"


async def run_nuclei(
    target: str,
    templates: Optional[list[str]] = None,
    severity: Optional[str] = None,
    tags: Optional[list[str]] = None,
    rate_limit: int = 50,
    timeout: int = 600,
) -> list[dict[str, Any]]:
    """
    Run Nuclei vulnerability scanner against a target.

    Args:
        target: Target URL or file path containing URLs.
        templates: Specific template paths/directories.
        severity: Filter by severity (critical, high, medium, low, info).
        tags: Filter by tags (e.g., ["cve", "xss", "sqli"]).
        rate_limit: Max requests per second.
        timeout: Command timeout in seconds.

    Returns:
        List of findings as dicts.
    """
    output_file = tempfile.mktemp(suffix=".json")
    args = [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-o",
        output_file,
        "-rate-limit",
        str(rate_limit),
        "-silent",
    ]

    if templates:
        for t in templates:
            args.extend(["-t", t])

    if severity:
        args.extend(["-severity", severity])

    if tags:
        args.extend(["-tags", ",".join(tags)])

    logger.info("nuclei_start", target=target)
    returncode, stdout, stderr = await _run_command(args, timeout=timeout)

    findings = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        os.unlink(output_file)

    logger.info("nuclei_complete", findings_count=len(findings))
    return findings


async def run_nmap(
    target: str,
    ports: str = "1-10000",
    scan_type: str = "-sV",
    timeout: int = 600,
) -> dict[str, Any]:
    """
    Run Nmap port scanner for service detection.

    Args:
        target: Target host or IP.
        ports: Port range to scan.
        scan_type: Nmap scan type flags.
        timeout: Command timeout in seconds.

    Returns:
        Parsed scan results.
    """
    output_file = tempfile.mktemp(suffix=".xml")
    args = ["nmap"]
    # scan_type may contain multiple flags like "-sV -sC", split them
    args.extend(shlex.split(scan_type))
    args.extend(["-p", ports, target, "-oX", output_file, "--open"])

    logger.info("nmap_start", target=target, ports=ports)
    returncode, stdout, stderr = await _run_command(args, timeout=timeout)

    result = {"target": target, "raw_output": stdout, "ports": []}

    if os.path.exists(output_file):
        # Parse XML output for open ports
        try:
            import xml.etree.ElementTree as ET

            tree = ET.parse(output_file)
            root = tree.getroot()

            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": "",
                        "service": "",
                        "version": "",
                    }
                    state = port.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state", "")
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "")
                        port_info["version"] = service.get("version", "")
                    result["ports"].append(port_info)
        except Exception as e:
            logger.error("nmap_parse_error", error=str(e))

        os.unlink(output_file)

    logger.info("nmap_complete", open_ports=len(result["ports"]))
    return result


async def run_ffuf(
    target_url: str,
    wordlist: str,
    fuzz_keyword: str = "FUZZ",
    extensions: Optional[str] = None,
    match_codes: str = "200,204,301,302,307,401,403,405",
    rate_limit: int = 100,
    timeout: int = 600,
) -> list[dict[str, Any]]:
    """
    Run ffuf for directory/parameter brute-forcing.

    Args:
        target_url: URL with FUZZ keyword (e.g., http://target.com/FUZZ).
        wordlist: Path to the wordlist file.
        fuzz_keyword: The keyword to replace in the URL.
        extensions: Comma-separated file extensions to append.
        match_codes: HTTP status codes to report.
        rate_limit: Max requests per second.
        timeout: Command timeout in seconds.

    Returns:
        List of discovered endpoints.
    """
    output_file = tempfile.mktemp(suffix=".json")
    args = [
        "ffuf",
        "-u",
        target_url,
        "-w",
        wordlist,
        "-mc",
        match_codes,
        "-rate",
        str(rate_limit),
        "-o",
        output_file,
        "-of",
        "json",
        "-s",
    ]

    if extensions:
        args.extend(["-e", extensions])

    logger.info("ffuf_start", target=target_url)
    returncode, stdout, stderr = await _run_command(args, timeout=timeout)

    results = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                data = json.load(f)
            for entry in data.get("results", []):
                results.append(
                    {
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "lines": entry.get("lines", 0),
                        "input": entry.get("input", {}).get(fuzz_keyword, ""),
                    }
                )
        except Exception as e:
            logger.error("ffuf_parse_error", error=str(e))
        os.unlink(output_file)

    logger.info("ffuf_complete", discovered=len(results))
    return results


async def run_wafw00f(target: str, timeout: int = 60) -> dict[str, Any]:
    """
    Run wafw00f to detect Web Application Firewalls.

    Returns:
        WAF detection result.
    """
    args = ["wafw00f", target, "-o", "/dev/stdout", "-f", "json"]
    logger.info("wafw00f_start", target=target)
    returncode, stdout, stderr = await _run_command(args, timeout=timeout)

    result = {"target": target, "detected": False, "waf_name": ""}
    try:
        data = json.loads(stdout)
        if isinstance(data, list) and data:
            entry = data[0]
            if entry.get("firewall"):
                result["detected"] = True
                result["waf_name"] = entry.get("firewall", "Unknown")
    except (json.JSONDecodeError, IndexError, KeyError):
        # Try parsing raw output
        if "is behind" in stdout.lower():
            result["detected"] = True
            result["waf_name"] = "Unknown (parsed from output)"

    logger.info("wafw00f_complete", detected=result["detected"], waf=result["waf_name"])
    return result


async def run_custom_nuclei_template(
    target: str,
    template_content: str,
    rate_limit: int = 50,
    timeout: int = 120,
) -> list[dict[str, Any]]:
    """
    Run Nuclei with a dynamically generated YAML template.

    Args:
        target: Target URL.
        template_content: YAML content of the Nuclei template.
        rate_limit: Max requests per second.
        timeout: Command timeout in seconds.

    Returns:
        List of findings.
    """
    template_file = tempfile.mktemp(suffix=".yaml")
    output_file = tempfile.mktemp(suffix=".json")

    with open(template_file, "w") as f:
        f.write(template_content)

    args = [
        "nuclei",
        "-u",
        target,
        "-t",
        template_file,
        "-jsonl",
        "-o",
        output_file,
        "-rate-limit",
        str(rate_limit),
        "-silent",
    ]

    logger.info("nuclei_custom_template_start", target=target)
    returncode, stdout, stderr = await _run_command(args, timeout=timeout)

    findings = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        os.unlink(output_file)

    if os.path.exists(template_file):
        os.unlink(template_file)

    logger.info("nuclei_custom_complete", findings_count=len(findings))
    return findings
