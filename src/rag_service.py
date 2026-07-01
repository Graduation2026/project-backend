import os
import re
import time
import logging
import threading

from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type, before_sleep_log
from pathlib import Path
from dotenv import load_dotenv

# LangChain LLM imports — Ollama for local LLM, HuggingFace for local embeddings
from langchain_ollama import ChatOllama
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

logger = logging.getLogger(__name__)

# Load environment variables
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Reference Database directory — uses HuggingFace local embeddings.
CHROMA_REF_DIR = Path(os.getenv(
    "CHROMA_REF_DIR",
    str(PROJECT_ROOT / "temp" / "chroma_db_reference")
))

# Ollama base URL — override via OLLAMA_BASE_URL env var if Ollama is on another host.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


class ReportGenerationService:
    def __init__(self):
        self._lock = threading.Lock()
        self.model_name = os.getenv("OLLAMA_MODEL", "qwen3:4b")
        self.embeddings = None
        self.vector_store = None
        self.llm = None
        self._is_initialized = False

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
        retry=retry_if_exception_type((ConnectionError, TimeoutError, OSError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
    def _invoke_llm_with_retry(self, prompt: str):
        """Invoke the local Ollama LLM with retry on connection errors."""
        prompt_chars = len(prompt) if isinstance(prompt, str) else len(str(prompt))
        logger.info(
            f"🧠 [LLM Invoke] Sending request to LOCAL Ollama model '{self.model_name}' "
            f"at {OLLAMA_BASE_URL} (prompt: {prompt_chars} chars / ~{prompt_chars // 4} tokens)..."
        )
        t0 = time.time()
        result = self.llm.invoke(prompt)
        latency = time.time() - t0

        # Confirm the response genuinely came from the local model and log telemetry.
        # ChatOllama returns an AIMessage carrying response_metadata with the model
        # name and token counts straight from the Ollama runtime — this is the
        # ground-truth proof that the local model served the request.
        meta = getattr(result, "response_metadata", {}) or {}
        served_by = meta.get("model", "unknown")
        eval_count = meta.get("eval_count")
        prompt_eval_count = meta.get("prompt_eval_count")
        done_reason = meta.get("done_reason")
        resp_text = self._content_to_text(getattr(result, "content", "")) or ""
        logger.info(
            f"✅ [LLM Invoke] LOCAL model responded in {latency:.2f}s "
            f"(served_by='{served_by}', prompt_tokens={prompt_eval_count}, "
            f"output_tokens={eval_count}, done_reason='{done_reason}', "
            f"response: {len(resp_text)} chars)"
        )
        if served_by == "unknown":
            logger.warning(
                "⚠️ [LLM Invoke] Response carried no model metadata — cannot confirm "
                "which backend served this request. Verify Ollama is the active LLM."
            )
        return result

    def initialize(self):
        """Initializes the embeddings, vector store, and local Ollama LLM (thread-safe)."""
        with self._lock:
            if self._is_initialized:
                return

            logger.info("Initializing context-enriched report generation service (HuggingFace local embeddings)...")
            self.embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2"
            )

            logger.info(f"Using local Ollama LLM '{self.model_name}' at {OLLAMA_BASE_URL}")
            self.llm = ChatOllama(
                model=self.model_name,
                base_url=OLLAMA_BASE_URL,
                temperature=0.2,
                num_predict=4096,
            )
            logger.info(
                f"🔗 [LLM Binding] LLM bound -> class={type(self.llm).__module__}.{type(self.llm).__name__}, "
                f"model='{self.model_name}', base_url='{OLLAMA_BASE_URL}'. "
                f"All report/chat generation will route through this LOCAL model."
            )

            CHROMA_REF_DIR.mkdir(parents=True, exist_ok=True)
            self.vector_store = Chroma(
                persist_directory=str(CHROMA_REF_DIR),
                embedding_function=self.embeddings
            )

            self.seed_db_if_empty()
            self._is_initialized = True
            logger.info("✅ Context-enriched report service initialized successfully.")
            
            # Check Ollama and model health at startup/initialization
            try:
                self.check_llm_health()
            except Exception as ex:
                logger.error(f"❌ LLM health check encountered an error: {str(ex)}")

    def check_llm_health(self) -> dict:
        """
        Check if the local Ollama LLM service is running and the target model is ready/responsive.
        Logs comprehensive details about status, latency, and available models.
        """
        import requests
        status = {
            "ollama_connected": False,
            "model_available": False,
            "model_responsive": False,
            "latency_seconds": 0.0,
            "message": "",
            "available_models": []
        }
        
        url = OLLAMA_BASE_URL.rstrip("/")
        logger.info(f"🔍 [Ollama Health Check] Connecting to Ollama server at: {url}...")
        
        # 1. Check if Ollama service is reachable
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                status["ollama_connected"] = True
                logger.info("✅ [Ollama Health Check] Connected to Ollama server successfully.")
            else:
                status["message"] = f"Ollama base URL returned status code {response.status_code}"
                logger.warning(f"⚠️ [Ollama Health Check] {status['message']}")
                return status
        except requests.exceptions.RequestException as e:
            status["message"] = f"Failed to connect to Ollama server at {url}: {str(e)}"
            logger.error(f"❌ [Ollama Health Check] {status['message']}")
            return status

        # 2. Check if the model is downloaded/available
        try:
            tags_url = f"{url}/api/tags"
            tags_resp = requests.get(tags_url, timeout=5)
            if tags_resp.status_code == 200:
                data = tags_resp.json()
                models = [m["name"] for m in data.get("models", [])]
                status["available_models"] = models
                logger.info(f"📋 [Ollama Health Check] Available models in Ollama: {models}")
                
                target = self.model_name
                found = False
                for m in models:
                    if m == target or m.startswith(target + ":") or target.startswith(m + ":"):
                        found = True
                        break
                
                if found:
                    status["model_available"] = True
                    logger.info(f"✅ [Ollama Health Check] Target model '{target}' is downloaded and ready.")
                else:
                    status["message"] = f"Target model '{target}' is NOT loaded/available in Ollama. Available: {models}"
                    logger.warning(f"⚠️ [Ollama Health Check] {status['message']}")
                    return status
            else:
                status["message"] = f"Failed to fetch tags from Ollama API: HTTP {tags_resp.status_code}"
                logger.warning(f"⚠️ [Ollama Health Check] {status['message']}")
                return status
        except Exception as e:
            status["message"] = f"Error checking models on Ollama: {str(e)}"
            logger.error(f"❌ [Ollama Health Check] {status['message']}")
            return status

        # 3. Test model responsiveness with a lightweight query
        try:
            logger.info(f"⚡ [Ollama Health Check] Testing responsiveness for model '{self.model_name}'...")
            t0 = time.time()
            gen_url = f"{url}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": "respond with 'pong' only",
                "stream": False,
                "options": {
                    "num_predict": 5
                }
            }
            gen_resp = requests.post(gen_url, json=payload, timeout=15)
            latency = time.time() - t0
            status["latency_seconds"] = round(latency, 3)
            
            if gen_resp.status_code == 200:
                resp_json = gen_resp.json()
                response_text = resp_json.get("response", "").strip()
                status["model_responsive"] = True
                status["message"] = f"Model is active and healthy. Response: '{response_text}'"
                logger.info(f"✅ [Ollama Health Check] Model responded in {status['latency_seconds']}s. Response: '{response_text}'")
                logger.info("💚 [Ollama Health Check] ALL SYSTEMS HEALTHY.")
            else:
                status["message"] = f"Test generation failed: HTTP {gen_resp.status_code} - {gen_resp.text}"
                logger.error(f"❌ [Ollama Health Check] {status['message']}")
        except Exception as e:
            status["message"] = f"Test generation threw an exception: {str(e)}"
            logger.error(f"❌ [Ollama Health Check] {status['message']}")

        return status

    def seed_db_if_empty(self):
        """Seeds the vector store from the knowledge_base/ directory.

        This is a curated threat intelligence library of CWE, CERT C, compiler
        hardening, and exploitation mechanics documents stored as Markdown files.
        The collection is designed as a static snapshot for reproducibility — in
        production deployments, this can be dynamically expanded by adding new
        .md files to the knowledge_base/ directory or wiring in external feeds
        (OSV, NVD, VulnDB) without any code changes.
        """
        try:
            count = len(self.vector_store.get()["ids"])
        except Exception:
            count = 0
        if count > 0:
            logger.info(f"Reference database already seeded with {count} documents.")
            return

        kb_dir = PROJECT_ROOT / "knowledge_base"
        if not kb_dir.exists():
            logger.warning(f"knowledge_base/ directory not found at {kb_dir}. Skipping DB seed.")
            return

        logger.info(f"Seeding reference database from {kb_dir}...")
        documents = []
        for md_file in sorted(kb_dir.glob("*.md")):
            content = md_file.read_text(encoding="utf-8")
            parts = content.split("\n", 1)
            title = parts[0].lstrip("# ").strip() if parts else md_file.stem
            body = parts[1] if len(parts) > 1 else content
            cwe_tag = md_file.stem.upper()
            documents.append(Document(
                page_content=body.strip() or content.strip(),
                metadata={"cwe": cwe_tag, "source": md_file.name, "title": title}
            ))

        if documents:
            self.vector_store.add_documents(documents)
            logger.info(f"Reference database seeded with {len(documents)} documents from knowledge_base/.")
        else:
            logger.warning("No markdown files found in knowledge_base/. Database is empty.")

    def _generate_safe_template_report(
        self,
        category_a_functions: list[dict],
        category_b_functions: list[dict],
        filename: str,
        sha256_hash: str,
        total_functions: int,
        actual_count: int,
        boilerplate_count: int,
    ) -> str:
        """Generate a clean, template-based report for files with 0 vulnerabilities.
        Skips the LLM entirely — saves API cost and guarantees consistent structure."""
        report_lines = [
            "# Sentinel AI Security Audit Report",
            "",
            "## Audit Metadata",
            f"- **Filename**: {filename}",
            f"- **SHA-256 Checksum**: {sha256_hash}",
            f"- **Verdict**: 0 vulnerabilities found out of {actual_count} actual code functions",
            f"- **Risk Level**: LOW (Green)",
            f"- **Total Functions Evaluated**: {total_functions}",
            f"- **Boilerplate Functions & Runtime Stubs Filtered**: {boilerplate_count}",
            f"- **Actual Code Functions Scanned**: {actual_count}",
            "",
            "## Executive Summary",
            "",
            f"Sentinel AI performed a comprehensive security audit on **{filename}** using GNN-based "
            f"Control Flow Graph (CFG) analysis. A total of {total_functions} functions were extracted "
            f"via Ghidra reverse engineering, of which {boilerplate_count} were identified as compiler-generated "
            f"boilerplate or runtime stubs and excluded from analysis.",
            "",
            f"The remaining {actual_count} actual code functions were analyzed by the GATv2 Graph Neural Network. "
            f"All function CFGs conform to standard secure coding baselines. No vulnerability patterns were detected.",
            "",
            "## Category B - Actual Code Functions",
            "",
        ]

        for func in category_b_functions:
            fname = func["function_name"]
            source = func.get("decision_source", "gnn")
            if source == "rescue":
                report_lines.append(f"- `{fname}` - Safe (heuristic rescue: uses safe API alternatives, no unsafe calls detected)")
            else:
                report_lines.append(f"- `{fname}` - Safe (CFG conforms to secure baselines)")

        report_lines.extend([
            "",
            "## General Mitigations",
            "",
            "Even when no vulnerabilities are detected, the following compiler hardening flags are recommended for production builds:",
            "",
            "- **Stack Canaries** (`-fstack-protector-strong`): Detects stack buffer overflows at runtime",
            "- **DEP/NX** (`-Wl,-z,noexecstack`): Prevents execution of code on the stack",
            "- **ASLR/PIE** (`-fPIE -pie`): Randomizes memory layout to prevent ROP attacks",
            "- **Full RELRO** (`-Wl,-z,relro,-z,now`): Protects the Global Offset Table from overwrites",
            "- **FORTIFY_SOURCE** (`-D_FORTIFY_SOURCE=2`): Replaces unsafe libc calls with bounds-checked variants",
            "",
        ])

        if category_a_functions:
            cat_a_names = ", ".join([f"`{f['function_name']}`" for f in category_a_functions])
            report_lines.extend([
                "## Category A - Boilerplate & Runtime Stubs",
                "",
                f"The following {boilerplate_count} functions are compiler-generated boilerplate, CRT startup "
                f"stubs, or standard library wrappers and were excluded from vulnerability analysis:",
                "",
                cat_a_names,
                "",
            ])

        return "\n".join(report_lines)

    CHUNK_SIZE = 10

    def _build_metadata(
        self, filename, sha256_hash, verdict, risk_level,
        total_functions, boilerplate_count, actual_count
    ) -> str:
        """Build Title and Audit Metadata sections. Fully deterministic — no LLM needed."""
        return (
            "# Sentinel AI Security Audit Report\n\n"
            "## Audit Metadata\n"
            f"- **Filename**: {filename}\n"
            f"- **SHA-256 Checksum**: {sha256_hash}\n"
            f"- **Verdict**: {verdict}\n"
            f"- **Risk Level**: {risk_level}\n"
            f"- **Total Functions Evaluated**: {total_functions}\n"
            f"- **Boilerplate Functions & Runtime Stubs Filtered**: {boilerplate_count}\n"
            f"- **Actual Code Functions Scanned**: {actual_count}\n\n"
        )

    def _build_mitigations_section(self) -> str:
        """Return static General Mitigations section — identical every time."""
        return (
            "## General Mitigations\n\n"
            "Even when no vulnerabilities are detected, the following compiler hardening "
            "flags are recommended for production builds:\n\n"
            "- **Stack Canaries** (`-fstack-protector-strong`): Detects stack buffer overflows at runtime\n"
            "- **DEP/NX** (`-Wl,-z,noexecstack`): Prevents execution of code on the stack\n"
            "- **ASLR/PIE** (`-fPIE -pie`): Randomizes memory layout to prevent ROP attacks\n"
            "- **Full RELRO** (`-Wl,-z,relro,-z,now`): Protects the Global Offset Table from overwrites\n"
            "- **FORTIFY_SOURCE** (`-D_FORTIFY_SOURCE=2`): Replaces unsafe libc calls with bounds-checked variants\n\n"
        )

    def _build_category_a_section(self, category_a_functions, boilerplate_count) -> str:
        """Build Category A boilerplate section."""
        if not category_a_functions:
            return "## Category A - Boilerplate & Runtime Stubs\n\nNo boilerplate functions filtered.\n\n"
        names = ", ".join([f"`{f['function_name']}`" for f in category_a_functions])
        return (
            "## Category A - Boilerplate & Runtime Stubs\n\n"
            f"The following {boilerplate_count} functions are compiler-generated boilerplate, CRT startup "
            f"stubs, or standard library wrappers and were excluded from vulnerability analysis:\n\n"
            f"{names}\n\n"
        )

    def _retrieve_context_for_chunk(self, chunk: list[dict]) -> str:
        """Query ChromaDB once per batch of flagged functions."""
        query_parts = []
        for func in chunk:
            asm = func.get('decompiled_code', '')
            lines = "\n".join(asm.split('\n')[:10])
            if lines.strip():
                query_parts.append(lines)
        if not query_parts:
            return ""
        combined = "\n\n".join(query_parts[:5])
        docs = self.vector_store.similarity_search(combined, k=5)
        seen = set()
        retrieved = []
        for d in docs:
            if d.page_content not in seen:
                seen.add(d.page_content)
                retrieved.append(d.page_content)
        return "\n\n".join(retrieved)

    @staticmethod
    def _content_to_text(content) -> str:
        """Flatten LangChain message content to plain text, dropping non-text
        parts (e.g. thinking/reasoning blocks that have no 'text' key)."""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text" and item.get("text"):
                        parts.append(item["text"])
                    elif "text" in item and isinstance(item["text"], str):
                        parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        return str(content)

    @staticmethod
    def _extract_cwe_id(block: str) -> str:
        """Pull a human-readable CWE label out of an analysis block.

        Prefers the full 'Threat ID' line (e.g. 'CWE-787: Out-of-bounds Write'),
        falling back to a bare CWE token, then to CWE-119 if nothing parses.
        """
        threat_match = re.search(r'\*\*Threat ID\*\*\s*:\s*(CWE-\d+[^\n]*)', block, re.IGNORECASE)
        if threat_match:
            return threat_match.group(1).strip().rstrip('.').strip()
        bare_match = re.search(r'(CWE-\d+)', block, re.IGNORECASE)
        if bare_match:
            return bare_match.group(1).upper()
        return "CWE-119"

    def _analyze_flagged_chunk(
        self, chunk: list[dict], ref_context: str,
        chunk_num: int, total_chunks: int
    ) -> str:
        """Send a batch of flagged functions to the Google GenAI LLM. Returns formatted markdown."""
        func_contexts = []
        for i, func in enumerate(chunk):
            fname = func["function_name"]
            asm = func.get('decompiled_code', '')
            lines = asm.split('\n')[:150]
            func_contexts.append(
                f"Function {i+1}: {fname}\n```asm\n{chr(10).join(lines)}\n```"
            )
        func_context_str = "\n\n".join(func_contexts)

        prompt = f"""You are a concise expert security engineer analyzing vulnerable functions.

REFERENCE STANDARDS:
{ref_context or "No specific reference context retrieved."}

FUNCTIONS TO ANALYZE (Batch {chunk_num}/{total_chunks}):
{func_context_str}

For EACH function above, return exactly 4 analysis bullet points. Return them in numbered order (1., 2., 3., etc.) matching the order above. Do NOT include function names — I will match them by position.

Expected format:
1.
- **Threat ID**: CWE-XXX: Vulnerability Name
- **Root Cause**: One-line root cause
- **CERT C Rule Violated**: Rule ID
- **Fix Direction**: One-line fix direction

2.
- **Threat ID**: ...

CRITICAL RULES:
- If the pattern is clear, assign the most specific CWE.
- Only use CWE-119 if genuinely ambiguous.
- Return ONLY the numbered bullet blocks — no preamble, no commentary, no markdown headers."""

        logger.info(f"Analyzing flagged functions batch {chunk_num}/{total_chunks}...")
        response = self._invoke_llm_with_retry(prompt)

        analysis_text = self._content_to_text(response.content).strip()

        # Parse numbered blocks (1. ... 2. ... etc.)
        numbered_blocks = re.split(r'\n(?=\d+\.\s)', analysis_text)

        output_parts = []
        for i, func in enumerate(chunk):
            fname = func["function_name"]
            asm = func.get('decompiled_code', '')
            lines = asm.split('\n')[:150]
            asm_block = chr(10).join(lines)

            # Find the corresponding analysis block by position
            block = ""
            for nb in numbered_blocks:
                stripped = nb.strip()
                if stripped.startswith(f"{i+1}."):
                    block = re.sub(r'^\d+\.\s*', '', stripped, count=1).strip()
                    break

            if not block:
                block = (
                    "- **Threat ID**: CWE-119 (Memory Operations)\n"
                    "- **Root Cause**: Vulnerability pattern flagged by GNN\n"
                    "- **CERT C Rule Violated**: Review CERT C guidelines\n"
                    "- **Fix Direction**: Review and remediate the flagged function"
                )

            # Capture the CWE parsed for this function so the UI cards / PDF can
            # display it (predictor.py emits cwe_id=None — this is where it's filled).
            # Mutating `func` updates the shared flagged_functions entry in place.
            func["cwe_id"] = self._extract_cwe_id(block)

            output_parts.append(
                f"- `{fname}` | FLAGGED\n"
                f"```asm\n{asm_block}\n```\n"
                f"{block}"
            )

        return "\n\n".join(output_parts)

    def _generate_executive_summary(
        self, filename, verdict, risk_level, color_tier, severity_level,
        total_functions, boilerplate_count, actual_count
    ) -> str:
        """Generate a qualitative Executive Summary via LLM (<20 flagged functions)."""
        prompt = f"""Write a 3-5 sentence Executive Summary for a security audit report.

SECURITY METADATA:
- Filename: {filename}
- Verdict: {verdict}
- Risk Level: {risk_level} ({color_tier} tier, {severity_level} severity)
- Total Functions: {total_functions} | Boilerplate Filtered: {boilerplate_count} | Actual Scanned: {actual_count}

Write a concise, qualitative executive summary. State the verdict, threat severity, and remediation urgency. No filler."""

        logger.info("Generating qualitative Executive Summary...")
        response = self._invoke_llm_with_retry(prompt)

        return self._content_to_text(response.content).strip()

    def generate_vulnerability_report(
        self,
        category_a_functions: list[dict],
        category_b_functions: list[dict],
        flagged_functions: list[dict],
        filename: str = "Unknown",
        sha256_hash: str = "Unknown",
        total_functions: int = 0,
        actual_count: int = 0,
        boilerplate_count: int = 0,
    ) -> str:
        """
        Generates a concise, actionable Markdown security report using a hybrid
        Python/LLM approach. Python handles deterministic sections (metadata,
        mitigations, safe functions, boilerplate). Flagged functions are chunked
        into small batches to keep prompts focused and maintain output quality.
        """
        self.initialize()

        flagged_count = len(flagged_functions)
        is_vulnerable = flagged_count > 0
        percentage = (flagged_count / actual_count * 100) if actual_count > 0 else 0.0

        # --- Safe file: use template-based report, skip LLM entirely ---
        if not is_vulnerable:
            logger.info("No vulnerabilities detected — generating template-based safe report (no LLM call).")
            return self._generate_safe_template_report(
                category_a_functions, category_b_functions,
                filename, sha256_hash, total_functions, actual_count, boilerplate_count
            )

        # --- Vulnerable file: determine severity tier ---
        if percentage <= 25.0:
            verdict = f"{flagged_count} vulnerabilities found out of {actual_count} actual code functions"
            risk_level = "MEDIUM (Yellow)"
            color_tier = "Yellow"
            severity_level = "MEDIUM"
        elif percentage <= 50.0:
            verdict = f"{flagged_count} vulnerabilities found out of {actual_count} actual code functions"
            risk_level = "HIGH (Orange)"
            color_tier = "Orange"
            severity_level = "HIGH"
        else:
            verdict = f"{flagged_count} vulnerabilities found out of {actual_count} actual code functions"
            risk_level = "CRITICAL (Red)"
            color_tier = "Red"
            severity_level = "CRITICAL"

        # --- Section 1 & 2: Python-driven metadata (deterministic, zero tokens) ---
        metadata_md = self._build_metadata(
            filename, sha256_hash, verdict, risk_level,
            total_functions, boilerplate_count, actual_count
        )

        # --- Section 5: Python-driven mitigations (deterministic, zero tokens) ---
        mitigations_md = self._build_mitigations_section()

        # --- Section 6: Python-driven Category A (deterministic, zero tokens) ---
        category_a_md = self._build_category_a_section(category_a_functions, boilerplate_count)

        # --- Safe functions: Python loop, zero LLM calls ---
        safe_md_lines = []
        for func in category_b_functions:
            if not func["is_vulnerable"]:
                source = func.get("decision_source", "gnn")
                if source == "rescue":
                    safe_md_lines.append(f"- `{func['function_name']}` - Safe (heuristic rescue: uses safe API alternatives, no unsafe calls detected)")
                else:
                    safe_md_lines.append(f"- `{func['function_name']}` - Safe (CFG conforms to secure baselines)")
        safe_md = "\n".join(safe_md_lines)
        if safe_md_lines:
            safe_md += "\n"

        # --- Chunk flagged functions (batch size = CHUNK_SIZE) ---
        chunks = [
            flagged_functions[i:i + self.CHUNK_SIZE]
            for i in range(0, len(flagged_functions), self.CHUNK_SIZE)
        ]
        chunk_results = []
        for i, chunk in enumerate(chunks):
            ref_context = self._retrieve_context_for_chunk(chunk)
            chunk_md = self._analyze_flagged_chunk(chunk, ref_context, i + 1, len(chunks))
            chunk_results.append(chunk_md)

        flagged_md = "\n\n".join(chunk_results)

        # --- Conditional Executive Summary ---
        if flagged_count < 20:
            exec_summary = self._generate_executive_summary(
                filename, verdict, risk_level, color_tier, severity_level,
                total_functions, boilerplate_count, actual_count
            )
        else:
            exec_summary = (
                f"Sentinel AI performed a comprehensive security audit on **{filename}** "
                f"using GNN-based Control Flow Graph (CFG) analysis. A total of {total_functions} "
                f"functions were extracted via Ghidra reverse engineering, of which "
                f"{boilerplate_count} were identified as compiler-generated boilerplate or "
                f"runtime stubs and excluded from analysis. The audit identified **{flagged_count} "
                f"vulnerabilities** out of {actual_count} actual code functions, resulting in a "
                f"**{risk_level}** risk level. Immediate remediation is recommended."
            )

        # --- Assemble final report ---
        report = "\n".join([
            metadata_md.strip(),
            "\n## Executive Summary\n",
            exec_summary,
            "\n## Category B - Actual Code Functions\n",
            safe_md,
            flagged_md,
            mitigations_md.strip(),
            category_a_md.strip(),
        ])

        logger.info(f"Report assembled successfully ({len(chunks)} chunk(s), {flagged_count} flagged functions).")
        return report

    def get_chat_response(self, query: str, decompiled_code: str, chat_history: list[dict] | None = None) -> str:
        """
        Handles real-time chatbot queries. Contextualizes the answer with the preloaded Reference DB
        and the specific decompiled function context under discussion.
        """
        self.initialize()
        if chat_history is None:
            chat_history = []

        # Retrieve relevant CWE standards
        docs = self.vector_store.similarity_search(query, k=4)
        ref_context = "\n\n".join([d.page_content for d in docs])

        # Format history
        history_str = ""
        for msg in chat_history[-6:]:  # Keep last 6 exchanges for concise context
            role = "User" if msg["role"] == "user" else "Assistant"
            history_str += f"{role}: {msg['content']}\n"

        prompt = f"""
You are the Sentinel AI Interactive Security Assistant, a high-fidelity chatbot built inside our security workspace.
Your goal is to help developers remediate vulnerabilities, understand compiler disassembly/CFGs, and write secure code.

Here is some reference security context:
{ref_context}

Here is the disassembled code block under discussion:
```
{decompiled_code}
```

Conversation History:
{history_str}

User's Question: {query}

Important: If the conversation is already underway (i.e., Conversation History contains previous User and Assistant exchanges), do NOT greet the user, do NOT introduce yourself, and do NOT repeat your name. Address the user's question directly and concisely.

Please formulate an elegant, friendly, and expert answer. Structure it with clear paragraphs or bullet points if needed. Ground your response heavily in secure C/C++ coding guidelines and explain concepts in a clear, developer-friendly manner.
"""

        logger.info(f"Invoking Ollama chatbot for query: '{query[:40]}...'")

        response = self._invoke_llm_with_retry(prompt)

        return self._content_to_text(response.content).strip()


# Module singleton
rag_service = ReportGenerationService()
