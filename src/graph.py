"""
ApexHunter LangGraph State Machine

The central orchestration graph that wires all agents together
into the autonomous workflow.

New Flow (Page-by-Page Architecture):
  Phase 0: Guardrails (continuous background)
  Phase 1: Init -> OSINT -> Auth -> Crawler -> WAF
  Phase 2: Page Loop:
           -> Page Scanner (capture DOM, network, attack surfaces)
           -> Page Analyzer (AI risk scoring, deep-scan decision)
           -> Planner (generate tasks for this page)
           -> JIT Tools -> Executor (run tasks)
           -> Page Decision (deep scan? next page? done?)
  Phase 3: OOB Check -> Reviewer -> Pivot Loop -> Second-Order -> Janitor -> Report -> Sanitize
"""

from __future__ import annotations

import uuid
import time
import os
from typing import Any

import structlog
from langgraph.graph import StateGraph, END

from src.state import ApexState, create_initial_state
from src.utils.config import ApexConfig
from src.utils.logger import setup_logging
from src.utils.llm_provider import create_planner_llm, create_executor_llm
from src.utils.http_client import GuardedHTTPClient
from src.guardrails.roe_gatekeeper import RoEGatekeeper
from src.guardrails.circuit_breaker import AdaptiveCircuitBreaker
from src.guardrails.flight_recorder import FlightDataRecorder
from src.tools.jit_installer import JITInstaller
from src.tools.rag_engine import RAGEngine
from src.tools.sandbox import ScriptSandbox
from src.agents.osint import OSINTAgent
from src.agents.auth import AuthAgent
from src.agents.crawler import SiteCrawlerAgent
from src.agents.page_scanner import PageScannerAgent
from src.agents.page_analyzer import PageAnalyzerAgent
from src.agents.waf import WAFAgent
from src.agents.planner import PlannerAgent
from src.agents.executor import ExecutorAgent
from src.agents.phase4 import (
    OOBCheckerAgent,
    DifferentialReviewerAgent,
    PivotLoopAgent,
    SecondOrderSweepAgent,
    JanitorAgent,
    DataSanitizerAgent,
)
from src.reporting.reporter import ReportGenerator

logger = structlog.get_logger("apexhunter.graph")


def build_graph(config: ApexConfig) -> StateGraph:
    """
    Build the ApexHunter LangGraph state machine.

    New architecture: page-by-page crawl -> scan -> analyze -> plan -> execute loop.

    Args:
        config: The master configuration object.

    Returns:
        A compiled LangGraph StateGraph ready for execution.
    """
    # ── Initialize Infrastructure ─────────────────────────
    gatekeeper = RoEGatekeeper(config.target.scope_regex)
    circuit_breaker = AdaptiveCircuitBreaker(
        error_threshold_percent=config.agent.circuit_breaker_threshold,
        autosleep_duration=config.agent.autosleep_duration,
        resume_speed_factor=config.agent.resume_speed_factor,
    )
    flight_recorder = FlightDataRecorder(
        warc_dir=config.paths.warc_dir,
        scan_id="pending",  # Will be set at runtime
    )
    http_client = GuardedHTTPClient(
        gatekeeper=gatekeeper,
        circuit_breaker=circuit_breaker,
        flight_recorder=flight_recorder,
        proxy_url=config.get_proxy_url(),
        base_delay=config.agent.request_delay,
    )

    # ── Initialize LLMs ──────────────────────────────────
    planner_llm = create_planner_llm(config.llm)
    executor_llm = create_executor_llm(config.llm)

    # ── Initialize Tools ──────────────────────────────────
    jit_installer = JITInstaller()
    rag_engine = RAGEngine(chroma_dir=config.paths.chroma_dir)
    sandbox = ScriptSandbox(timeout=30)

    # ── Initialize Agents ─────────────────────────────────
    osint_agent = OSINTAgent(
        http_client=http_client,
        max_retries=config.agent.max_retries,
        retry_backoff=config.agent.retry_backoff,
    )
    auth_agent = AuthAgent(http_client=http_client, config=config)
    crawler_agent = SiteCrawlerAgent(http_client=http_client, config=config)
    page_scanner_agent = PageScannerAgent(http_client=http_client, config=config)
    page_analyzer_agent = PageAnalyzerAgent(llm=planner_llm)
    waf_agent = WAFAgent(http_client=http_client, llm=planner_llm)
    planner_agent = PlannerAgent(llm=planner_llm)
    executor_agent = ExecutorAgent(
        http_client=http_client,
        llm=executor_llm,
        rag_engine=rag_engine,
        sandbox=sandbox,
        jit_installer=jit_installer,
        config=config,
    )
    oob_checker = OOBCheckerAgent(http_client=http_client)
    reviewer = DifferentialReviewerAgent(http_client=http_client)
    pivot_loop = PivotLoopAgent()
    second_order = SecondOrderSweepAgent(http_client=http_client)
    janitor = JanitorAgent(http_client=http_client)
    reporter = ReportGenerator(output_dir=config.paths.output_dir)
    sanitizer = DataSanitizerAgent(config=config)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Define Node Functions
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def node_initialization(state: ApexState) -> dict:
        """Node 1: Initialize infrastructure and discover tools."""
        logger.info("node_initialization_start")
        scan_id = state.get("scan_id", uuid.uuid4().hex[:12])

        # Update flight recorder with actual scan ID
        flight_recorder._scan_id = scan_id

        # Initialize RAG engine
        await rag_engine.initialize()

        # Discover installed tools
        installed = await jit_installer.discover_installed_tools()

        return {
            "scan_id": scan_id,
            "installed_tools": installed,
            "current_phase": "initialization_complete",
        }

    async def node_osint(state: ApexState) -> dict:
        """Node 2: OSINT & Historical Context (The Ghost Node)."""
        logger.info("node_osint_start")
        try:
            return await osint_agent.run(state)
        except Exception as e:
            logger.error("node_osint_error", error=str(e))
            return {
                "historical_osint_data": [],
                "hidden_surface_map": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "osint", "error": str(e), "time": time.time()}],
            }

    async def node_auth(state: ApexState) -> dict:
        """Node 3: Multi-Role Authentication (The Forger)."""
        logger.info("node_auth_start")
        try:
            return await auth_agent.run(state)
        except Exception as e:
            logger.error("node_auth_error", error=str(e))
            return {
                "auth_matrix": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "auth", "error": str(e), "time": time.time()}],
            }

    async def node_crawler(state: ApexState) -> dict:
        """Node 4: Site Crawler (The Cartographer) - builds the page tree."""
        logger.info("node_crawler_start")
        try:
            result = await crawler_agent.run(state)

            # Save the site tree for inspection
            scan_id = state.get("scan_id", "unknown")
            tree_path = os.path.join(config.paths.output_dir, f"apex_site_tree_{scan_id}.json")
            site_tree = result.get("site_tree", [])

            import json

            with open(tree_path, "w") as f:
                json.dump(site_tree, f, indent=2, default=str)

            print("\n" + "=" * 60)
            print("  APEXHUNTER - SITE CRAWL COMPLETE")
            print("=" * 60)
            print(f"  Total Pages Discovered: {len(site_tree)}")
            print(f"  Total Endpoints: {len(result.get('discovered_endpoints', []))}")
            print(f"  API Schemas Found: {len(result.get('openapi_schemas', []))}")
            print(f"  Site Tree saved to: {tree_path}")
            print("=" * 60 + "\n")

            return result
        except Exception as e:
            logger.error("node_crawler_error", error=str(e))
            return {
                "site_tree": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "crawler", "error": str(e), "time": time.time()}],
            }

    async def node_waf(state: ApexState) -> dict:
        """Node 5: WAF Detection & Profiling."""
        logger.info("node_waf_start")
        try:
            return await waf_agent.run(state)
        except Exception as e:
            logger.error("node_waf_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "waf", "error": str(e), "time": time.time()}],
            }

    async def node_page_scanner(state: ApexState) -> dict:
        """Node 6: Per-Page Deep Scanner (The Forensic Lens)."""
        logger.info(
            "node_page_scanner_start",
            page_index=state.get("current_page_index", 0),
        )
        try:
            return await page_scanner_agent.run(state)
        except Exception as e:
            logger.error("node_page_scanner_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "page_scanner", "error": str(e), "time": time.time()}],
            }

    async def node_page_analyzer(state: ApexState) -> dict:
        """Node 7: Per-Page AI Analyzer (The Tactician)."""
        logger.info(
            "node_page_analyzer_start",
            page_index=state.get("current_page_index", 0),
        )
        try:
            result = await page_analyzer_agent.run(state)

            # Print analysis summary
            page_analyses = result.get("page_analyses", state.get("page_analyses", []))
            if page_analyses:
                latest = page_analyses[-1]
                print(
                    f"  [{latest.get('interest_level', '?').upper()}] "
                    f"Risk {latest.get('risk_score', 0):.1f}/10 — "
                    f"{latest.get('url', '')} — "
                    f"{len(latest.get('attack_vectors', []))} vectors"
                    f"{' ** DEEP SCAN **' if latest.get('should_deep_scan') else ''}"
                )

            return result
        except Exception as e:
            logger.error("node_page_analyzer_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "page_analyzer", "error": str(e), "time": time.time()}],
            }

    async def node_planner(state: ApexState) -> dict:
        """Node 8: Threat & Logic Planner (Cloud LLM)."""
        logger.info("node_planner_start")
        try:
            result = await planner_agent.run(state)
            task_tree = result.get("task_tree", [])

            # Save the plan to output directory
            scan_id = state.get("scan_id", "unknown")
            page_index = state.get("current_page_index", 0)
            plan_path = os.path.join(
                config.paths.output_dir,
                f"apex_plan_{scan_id}_page{page_index}.json",
            )
            import json

            with open(plan_path, "w") as f:
                json.dump([t for t in task_tree], f, indent=2)

            if task_tree:
                print(f"  Planned {len(task_tree)} tasks for page {page_index}")
                for i, t in enumerate(task_tree[:5], 1):
                    vuln = t.get("vuln_type", "unknown")
                    endpoint = t.get("target_endpoint", "")
                    print(f"    {i}. [{vuln.upper()}] {endpoint[:60]}")
                if len(task_tree) > 5:
                    print(f"    ... and {len(task_tree) - 5} more tasks.")

            return result
        except Exception as e:
            logger.error("node_planner_error", error=str(e))
            return {
                "task_tree": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "planner", "error": str(e), "time": time.time()}],
            }

    async def node_jit_tools(state: ApexState) -> dict:
        """Node 9: JIT Tool Manager."""
        logger.info("node_jit_tools_start")
        task_tree = state.get("task_tree", [])

        # Determine which tools are needed
        needed_tools = set()
        for task in task_tree:
            tool = task.get("recommended_tool", "")
            if tool in ("nuclei", "nmap", "ffuf"):
                needed_tools.add(tool)

        if not needed_tools:
            return {"current_phase": "jit_tools_complete"}

        # Install any missing tools
        results = await jit_installer.install_all_required(list(needed_tools))
        installed = list(state.get("installed_tools", []))
        for tool, success in results.items():
            if success and tool not in installed:
                installed.append(tool)

        return {
            "installed_tools": installed,
            "current_phase": "jit_tools_complete",
        }

    async def node_executor(state: ApexState) -> dict:
        """Node 10: The Multi-Vector Executor."""
        logger.info("node_executor_start")
        try:
            return await executor_agent.run(state)
        except Exception as e:
            logger.error("node_executor_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "executor", "error": str(e), "time": time.time()}],
            }

    def node_page_decision(state: ApexState) -> dict:
        """
        Node 11: Page Decision Point.

        After scanning + analyzing + executing tasks on a page, decides:
        1. DEEP SCAN: Re-analyze this page more thoroughly (if flagged)
        2. NEXT PAGE: Move to the next page in the site tree
        3. DONE: All pages processed, move to Phase 3
        """
        site_tree = state.get("site_tree", [])
        current_index = state.get("current_page_index", 0)
        pages_completed = list(state.get("pages_completed", []))
        deep_scan_pages = state.get("pages_requiring_deep_scan", [])
        deep_scan_active = state.get("deep_scan_active", False)

        if current_index >= len(site_tree):
            logger.info("page_decision_all_done", total=len(pages_completed))
            return {"current_phase": "all_pages_done"}

        current_page = site_tree[current_index]
        page_id = current_page.get("page_id", "")

        # If deep scan was active, we've now completed it — mark as done
        if deep_scan_active:
            if page_id not in pages_completed:
                pages_completed.append(page_id)
            # Move to next page
            return {
                "current_page_index": current_index + 1,
                "pages_completed": pages_completed,
                "deep_scan_active": False,
                "current_phase": "next_page",
            }

        # Mark current page as completed
        if page_id not in pages_completed:
            pages_completed.append(page_id)

        # Check if this page needs deep scanning
        if page_id in deep_scan_pages:
            logger.info("page_decision_deep_scan", page_id=page_id)
            return {
                "pages_completed": pages_completed,
                "deep_scan_active": True,
                "current_phase": "deep_scan",
            }

        # Move to next page
        next_index = current_index + 1
        if next_index < len(site_tree):
            logger.info(
                "page_decision_next_page",
                completed=len(pages_completed),
                remaining=len(site_tree) - next_index,
            )
            return {
                "current_page_index": next_index,
                "pages_completed": pages_completed,
                "current_phase": "next_page",
            }
        else:
            logger.info("page_decision_all_done", total=len(pages_completed))
            return {
                "pages_completed": pages_completed,
                "current_phase": "all_pages_done",
            }

    async def node_oob_checker(state: ApexState) -> dict:
        """Node 12: Async OOB Checker."""
        logger.info("node_oob_checker_start")
        try:
            return await oob_checker.run(state)
        except Exception as e:
            logger.error("node_oob_error", error=str(e))
            return {}

    async def node_reviewer(state: ApexState) -> dict:
        """Node 13: The Differential Reviewer."""
        logger.info("node_reviewer_start")
        try:
            return await reviewer.run(state)
        except Exception as e:
            logger.error("node_reviewer_error", error=str(e))
            return {}

    def node_pivot(state: ApexState) -> dict:
        """Node 14: The Pivot Loop."""
        logger.info("node_pivot_start")
        return pivot_loop.run(state)

    async def node_second_order(state: ApexState) -> dict:
        """Node 15: Second-Order Sweep."""
        logger.info("node_second_order_start")
        try:
            return await second_order.run(state)
        except Exception as e:
            logger.error("node_second_order_error", error=str(e))
            return {}

    async def node_janitor(state: ApexState) -> dict:
        """Node 16: The Janitor (Target Cleanup)."""
        logger.info("node_janitor_start")
        try:
            return await janitor.run(state)
        except Exception as e:
            logger.error("node_janitor_error", error=str(e))
            return {}

    def node_reporter(state: ApexState) -> dict:
        """Node 17: Final Reporting & Export."""
        logger.info("node_reporter_start")
        return reporter.run(state)

    async def node_sanitizer(state: ApexState) -> dict:
        """Node 18: Data Sanitization (Local Cleanup)."""
        logger.info("node_sanitizer_start")
        try:
            return await sanitizer.run(state)
        except Exception as e:
            logger.error("node_sanitizer_error", error=str(e))
            return {}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Conditional Edge Functions
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def route_after_crawler(state: ApexState) -> str:
        """After crawling, decide whether to start page loop or skip."""
        site_tree = state.get("site_tree", [])
        if not site_tree:
            logger.warning("no_pages_discovered_skipping_to_phase3")
            return "oob_checker"
        return "page_scanner"

    def route_after_page_decision(state: ApexState) -> str:
        """
        After the page decision node, route to:
        - page_scanner: for next page or deep scan
        - oob_checker: all pages done, proceed to Phase 3
        """
        phase = state.get("current_phase", "")

        if phase == "deep_scan":
            # Re-enter the page loop for deep analysis
            return "page_scanner"
        elif phase == "next_page":
            # Move to next page
            return "page_scanner"
        else:
            # All pages done — proceed to Phase 3
            return "oob_checker"

    def route_after_pivot(state: ApexState) -> str:
        """Route after the pivot loop: back to planner or to second-order."""
        phase = state.get("current_phase", "")
        if phase == "pivot_to_planner":
            return "planner"
        return "second_order"

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Build the Graph
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    graph = StateGraph(ApexState)

    # Add all nodes
    graph.add_node("initialization", node_initialization)
    graph.add_node("osint", node_osint)
    graph.add_node("auth", node_auth)
    graph.add_node("crawler", node_crawler)
    graph.add_node("waf", node_waf)
    graph.add_node("page_scanner", node_page_scanner)
    graph.add_node("page_analyzer", node_page_analyzer)
    graph.add_node("planner", node_planner)
    graph.add_node("jit_tools", node_jit_tools)
    graph.add_node("executor", node_executor)
    graph.add_node("page_decision", node_page_decision)
    graph.add_node("oob_checker", node_oob_checker)
    graph.add_node("reviewer", node_reviewer)
    graph.add_node("pivot", node_pivot)
    graph.add_node("second_order", node_second_order)
    graph.add_node("janitor", node_janitor)
    graph.add_node("reporter", node_reporter)
    graph.add_node("sanitizer", node_sanitizer)

    # ── Define Edges ──────────────────────────────────────

    # Entry point
    graph.set_entry_point("initialization")

    # Phase 1: Intelligence Gathering
    graph.add_edge("initialization", "osint")
    graph.add_edge("osint", "auth")
    graph.add_edge("auth", "crawler")
    graph.add_edge("crawler", "waf")

    # After WAF, enter the page loop (or skip if no pages)
    graph.add_conditional_edges(
        "waf",
        route_after_crawler,
        {
            "page_scanner": "page_scanner",
            "oob_checker": "oob_checker",
        },
    )

    # Phase 2: Page-by-Page Loop
    # Scanner -> Analyzer -> Planner -> JIT -> Executor -> Decision
    graph.add_edge("page_scanner", "page_analyzer")
    graph.add_edge("page_analyzer", "planner")
    graph.add_edge("planner", "jit_tools")
    graph.add_edge("jit_tools", "executor")
    graph.add_edge("executor", "page_decision")

    # Page Decision: loop back or proceed to Phase 3
    graph.add_conditional_edges(
        "page_decision",
        route_after_page_decision,
        {
            "page_scanner": "page_scanner",
            "oob_checker": "oob_checker",
        },
    )

    # Phase 3: Post-Execution Analysis & Cleanup
    graph.add_edge("oob_checker", "reviewer")
    graph.add_edge("reviewer", "pivot")

    # Pivot Loop: conditional routing
    graph.add_conditional_edges(
        "pivot",
        route_after_pivot,
        {
            "planner": "planner",
            "second_order": "second_order",
        },
    )

    graph.add_edge("second_order", "janitor")
    graph.add_edge("janitor", "reporter")
    graph.add_edge("reporter", "sanitizer")
    graph.add_edge("sanitizer", END)

    return graph.compile()
