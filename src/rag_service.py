import os
import logging
import threading

from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception_type, before_sleep_log
from google.api_core.exceptions import ResourceExhausted, TooManyRequests
from pathlib import Path
from dotenv import load_dotenv

# LangChain and Gemini imports
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

logger = logging.getLogger(__name__)

# Load environment variables
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Reference Database directory
CHROMA_REF_DIR = PROJECT_ROOT / "temp" / "chroma_db_reference"

class ReportGenerationService:
    def __init__(self):
        self._lock = threading.Lock()
        self.api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.embeddings = None
        self.vector_store = None
        self.llm = None
        self._is_initialized = False

    @retry(
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(5),
        retry=retry_if_exception_type((ResourceExhausted, TooManyRequests)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
    def _invoke_llm_with_retry(self, prompt: str):
        """Invoke the LLM with exponential backoff on rate-limit errors."""
        return self.llm.invoke(prompt)

    def initialize(self):
        """Initializes the embeddings, vector store, and Gemini LLM (thread-safe)."""
        with self._lock:
            if self._is_initialized:
                return

            if not self.api_key:
                raise ValueError("Google Gemini API Key not found in environment variables.")

            logger.info("Initializing context-enriched report generation service (Gemini Cloud Embeddings)...")
            self.embeddings = GoogleGenerativeAIEmbeddings(
                model="models/gemini-embedding-2",
                google_api_key=self.api_key
            )

            self.llm = ChatGoogleGenerativeAI(
                model="gemini-2.5-flash",
                temperature=0.2,
                max_output_tokens=4096,
                google_api_key=self.api_key
            )

            CHROMA_REF_DIR.mkdir(parents=True, exist_ok=True)
            self.vector_store = Chroma(
                persist_directory=str(CHROMA_REF_DIR),
                embedding_function=self.embeddings
            )

            self.seed_db_if_empty()
            self._is_initialized = True
            logger.info("✅ Context-enriched report service initialized successfully.")

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
        Generates a concise, actionable Markdown security report.
        For safe files (0 vulnerabilities): uses a static template (no LLM call).
        For vulnerable files: retrieves reference standards from knowledge base and
        invokes Gemini with a tightly constrained prompt to prevent word vomit.
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

        # Retrieve reference guidelines from Chroma DB
        # Query by decompiled assembly code rather than CWE ID string
        # so embeddings match the actual vulnerability pattern (e.g. OOB array access)
        # instead of relying on a pre-assigned CWE label.
        retrieved_docs = []
        for func in flagged_functions:
            asm_code = func.get('decompiled_code', '')
            query_lines = "\n".join(asm_code.split('\n')[:20])
            if query_lines.strip():
                docs = self.vector_store.similarity_search(query_lines, k=3)
                for d in docs:
                    retrieved_docs.append(d.page_content)

        reference_context = "\n\n".join(set(retrieved_docs))

        # --- Format Category B context (concise) ---
        category_b_context = ""
        for func in category_b_functions:
            fname = func["function_name"]
            if func["is_vulnerable"]:
                flagged_match = next((f for f in flagged_functions if f["function_name"] == fname), None)
                cwe_id = func.get("cwe_id") or "CWE-119 (to be classified)"
                category_b_context += f"- `{fname}` | FLAGGED | {cwe_id}\n"
                if flagged_match and flagged_match.get("decompiled_code"):
                    # Limit decompiled code to first 15 lines to prevent prompt bloat
                    code_lines = flagged_match['decompiled_code'].split('\n')[:15]
                    category_b_context += f"```\n{chr(10).join(code_lines)}\n```\n"
            else:
                category_b_context += f"- `{fname}` | Safe\n"

        # --- Format Category A (names only, comma-separated) ---
        category_a_names = "None"
        if category_a_functions:
            category_a_names = ", ".join([f"`{f['function_name']}`" for f in category_a_functions])

        prompt = f"""You are a concise, expert security engineer writing a binary vulnerability audit report.

SECURITY METADATA:
- Filename: {filename}
- SHA-256: {sha256_hash}
- Verdict: {verdict}
- Risk Level: {risk_level} ({color_tier} tier, {severity_level} severity)
- Total Functions: {total_functions} | Boilerplate Filtered: {boilerplate_count} | Actual Scanned: {actual_count}

REFERENCE STANDARDS:
{reference_context}

FUNCTION AUDIT DATA:
{category_b_context}

BOILERPLATE NAMES:
{category_a_names}

Write a Markdown report with EXACTLY this structure:

1. `# Sentinel AI Security Audit Report`
2. `## Audit Metadata` — Bolded list (NOT a table) with: Filename, SHA-256, Verdict, Risk Level, Total Functions, Boilerplate Filtered, Actual Scanned.
3. `## Executive Summary` — 3-5 sentences max. State the verdict, threat severity ({color_tier}/{severity_level}), and remediation urgency. No filler.
4. `## Category B - Actual Code Functions` — For each function:
   - SAFE functions: ONE line only. Format: `- function_name - Safe. CFG conforms to secure baselines.`
   - FLAGGED functions: Maximum 4 bullet points. Base the CWE on the assembly/CFG evidence shown — DO NOT guess a CWE number if the pattern is unclear; state "CWE-119 (Memory Operations)".
     1. Threat ID (CWE number and name — classify from the assembly)
     2. One-line root cause
     3. CERT C rule violated
     4. One-line high-level fix direction (no fabricated code snippets — you do not have the source)
5. `## General Mitigations` — 5 bullet points max covering compiler hardening (canaries, DEP, ASLR, RELRO, FORTIFY_SOURCE).
6. `## Category A - Boilerplate & Runtime Stubs` — If "None", write "No boilerplate functions filtered." Otherwise, one explanation sentence, then the comma-separated names list.

CRITICAL RULES:
- Keep the ENTIRE report under 2,500 words.
- Do NOT include confidence percentages or probability scores.
- Do NOT use "VULNERABLE" or "CLEAN" as standalone headers.
- Do NOT pad with general cybersecurity lectures. Be surgical and actionable.
- Do NOT repeat information already stated in other sections.
- Use the verdict "{verdict}" verbatim when referencing the outcome.
- You only have assembly/CFG data, NOT the original source code. Do not fabricate C code snippets."""

        logger.info("Invoking Gemini to compile security report...")
        response = self._invoke_llm_with_retry(prompt)

        content = response.content
        if isinstance(content, list):
            content = "\n".join([str(item) if not isinstance(item, dict) else item.get("text", str(item)) for item in content])
        report_markdown = content.strip()
        logger.info("Vulnerability report successfully compiled!")
        return report_markdown

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

        logger.info(f"Invoking Gemini chatbot for query: '{query[:40]}...'")
        response = self._invoke_llm_with_retry(prompt)
        
        content = response.content
        if isinstance(content, list):
            content = "\n".join([str(item) if not isinstance(item, dict) else item.get("text", str(item)) for item in content])
        return content.strip()


# Module singleton
rag_service = ReportGenerationService()
