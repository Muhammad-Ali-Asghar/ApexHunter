"""
ApexHunter LangGraph State Machine

The central orchestration graph that wires all agents together
into the autonomous workflow defined in the blueprint.

Flow:
  Phase 0: Guardrails (continuous background)
  Phase 1: Init -> OSINT -> Auth -> Recon -> Fuzzer -> WAF
  Phase 2: Reducer -> Planner -> RAG/Mutation
  Phase 3: JIT Tools -> Executor
  Phase 4: OOB Check -> Reviewer -> Pivot Loop -> Second-Order -> Janitor -> Report -> Sanitize
"""

from __future__ import annotations

import uuid
import time
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
from src.agents.recon import ReconAgent
from src.agents.fuzzer import FuzzerAgent
from src.agents.waf import WAFAgent
from src.agents.reducer import ReducerAgent
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
    recon_agent = ReconAgent(http_client=http_client, config=config)
    fuzzer_agent = FuzzerAgent(http_client=http_client, config=config)
    waf_agent = WAFAgent(http_client=http_client)
    reducer_agent = ReducerAgent()
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

    async def node_recon(state: ApexState) -> dict:
        """Node 4: DOM-Aware Reconnaissance (The Spider)."""
        logger.info("node_recon_start")
        try:
            return await recon_agent.run(state)
        except Exception as e:
            logger.error("node_recon_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "recon", "error": str(e), "time": time.time()}],
            }

    async def node_fuzzer(state: ApexState) -> dict:
        """Node 5: Exhaustive Deep Fuzzing."""
        logger.info("node_fuzzer_start")
        try:
            return await fuzzer_agent.run(state)
        except Exception as e:
            logger.error("node_fuzzer_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "fuzzer", "error": str(e), "time": time.time()}],
            }

    async def node_waf(state: ApexState) -> dict:
        """Node 6: WAF Detection & Profiling."""
        logger.info("node_waf_start")
        try:
            return await waf_agent.run(state)
        except Exception as e:
            logger.error("node_waf_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "waf", "error": str(e), "time": time.time()}],
            }

    def node_reducer(state: ApexState) -> dict:
        """Node 7: Semantic Attack Surface Reducer."""
        logger.info("node_reducer_start")
        try:
            return reducer_agent.run(state)
        except Exception as e:
            logger.error("node_reducer_error", error=str(e))
            return {
                "reduced_attack_surface": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "reducer", "error": str(e), "time": time.time()}],
            }

    async def node_planner(state: ApexState) -> dict:
        """Node 8: Threat & Logic Planner (Cloud LLM)."""
        logger.info("node_planner_start")
        try:
            return await planner_agent.run(state)
        except Exception as e:
            logger.error("node_planner_error", error=str(e))
            return {
                "task_tree": [],
                "errors": list(state.get("errors", []))
                + [{"phase": "planner", "error": str(e), "time": time.time()}],
            }

    async def node_jit_tools(state: ApexState) -> dict:
        """Node 10: JIT Tool Manager."""
        logger.info("node_jit_tools_start")
        task_tree = state.get("task_tree", [])

        # Determine which tools are needed
        needed_tools = set()
        for task in task_tree:
            tool = task.get("recommended_tool", "")
            if tool in ("nuclei", "nmap", "ffuf"):
                needed_tools.add(tool)

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
        """Node 11: The Multi-Vector Executor."""
        logger.info("node_executor_start")
        try:
            return await executor_agent.run(state)
        except Exception as e:
            logger.error("node_executor_error", error=str(e))
            return {
                "errors": list(state.get("errors", []))
                + [{"phase": "executor", "error": str(e), "time": time.time()}],
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
    # Build the Graph
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    graph = StateGraph(ApexState)

    # Add all nodes
    graph.add_node("initialization", node_initialization)
    graph.add_node("osint", node_osint)
    graph.add_node("auth", node_auth)
    graph.add_node("recon", node_recon)
    graph.add_node("fuzzer", node_fuzzer)
    graph.add_node("waf", node_waf)
    graph.add_node("reducer", node_reducer)
    graph.add_node("planner", node_planner)
    graph.add_node("jit_tools", node_jit_tools)
    graph.add_node("executor", node_executor)
    graph.add_node("oob_checker", node_oob_checker)
    graph.add_node("reviewer", node_reviewer)
    graph.add_node("pivot", node_pivot)
    graph.add_node("second_order", node_second_order)
    graph.add_node("janitor", node_janitor)
    graph.add_node("reporter", node_reporter)
    graph.add_node("sanitizer", node_sanitizer)

    # ── Define Edges (Sequential Flow) ────────────────────

    # Entry point
    graph.set_entry_point("initialization")

    # Phase 1: Intelligence Gathering
    graph.add_edge("initialization", "osint")
    graph.add_edge("osint", "auth")
    graph.add_edge("auth", "recon")
    graph.add_edge("recon", "fuzzer")
    graph.add_edge("fuzzer", "waf")

    # Phase 2: Strategy & Planning
    graph.add_edge("waf", "reducer")
    graph.add_edge("reducer", "planner")

    # Phase 3: Execution
    graph.add_edge("planner", "jit_tools")
    graph.add_edge("jit_tools", "executor")

    # Phase 4: Analysis & Cleanup
    graph.add_edge("executor", "oob_checker")
    graph.add_edge("oob_checker", "reviewer")

    # Pivot Loop: conditional routing
    graph.add_edge("reviewer", "pivot")
    graph.add_conditional_edges(
        "pivot",
        lambda state: (
            "planner"
            if state.get("current_phase") == "pivot_to_planner"
            else "second_order"
        ),
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
