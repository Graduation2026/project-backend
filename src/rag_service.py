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
        Retrieves reference standards from the knowledge base and generates a comprehensive Markdown
        security report for the scanned file. Always invoked (both safe and vulnerable verdicts).
        Groups functions into Category B (actual code, detailed) and Category A (boilerplate, names only).
        """
        self.initialize()

        flagged_count = len(flagged_functions)
        is_vulnerable = flagged_count > 0
        percentage = (flagged_count / actual_count * 100) if actual_count > 0 else 0.0

        if percentage == 0.0:
            verdict = f"0 vulnerabilities found out of {actual_count} actual code functions"
            risk_level = "LOW (Green)"
            color_tier = "Green"
            severity_level = "LOW"
        elif percentage <= 25.0:
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
        retrieved_docs = []
        if is_vulnerable:
            # Sort flagged functions by CWE and limit detailed analysis to top 10 critical ones
            top_critical = flagged_functions[:10]
            unique_cwes = set(func.get('cwe_id', 'CWE-119') for func in top_critical)
            for cwe in unique_cwes:
                query = f"CWE memory corruption {cwe} buffer overflow out of bounds write"
                docs = self.vector_store.similarity_search(query, k=1)
                if docs:
                    retrieved_docs.append(docs[0].page_content)
        else:
            # For safe targets, fetch a few general CERT C guidelines to display compliance standards
            query = "CWE memory safety rules buffer overflow stack protection secure coding"
            docs = self.vector_store.similarity_search(query, k=2)
            for d in docs:
                retrieved_docs.append(d.page_content)

        reference_context = "\n\n".join(set(retrieved_docs))

        # --- Format Category B (Actual Code Functions) context ---
        category_b_context = f"**Actual Code Functions Analyzed (Category B): {actual_count}**\n\n"
        for idx, func in enumerate(category_b_functions):
            fname = func["function_name"]
            if func["is_vulnerable"]:
                # Find matching flagged function for full details
                flagged_match = next((f for f in flagged_functions if f["function_name"] == fname), None)
                cwe_id = func.get("cwe_id", "CWE-119")
                category_b_context += (
                    f"### Function {idx + 1}: `{fname}` — ⚠️ VULNERABLE\n"
                    f"- **Status:** Vulnerable\n"
                    f"- **Identified Threat:** {cwe_id} (Memory Safety / Buffer Overflow)\n"
                    f"- **Model Explanation:** {func.get('explanation', 'GNN model classified this function as vulnerable.')}\n"
                )
                if flagged_match and flagged_match.get("decompiled_code"):
                    category_b_context += (
                        f"- **Disassembled CFG Code Blocks:**\n"
                        f"```\n{flagged_match['decompiled_code']}\n```\n\n"
                    )
            else:
                category_b_context += (
                    f"### Function {idx + 1}: `{fname}` — ✅ Safe\n"
                    f"- **Status:** Safe\n"
                    f"- **Security Validation:** {func.get('explanation', 'No unsafe patterns detected.')}\n\n"
                )

        # --- Format Category A (Boilerplate & Runtime Stubs) context ---
        category_a_context = ""
        if category_a_functions:
            category_a_names = ", ".join([f"`{f['function_name']}`" for f in category_a_functions])
            category_a_context = (
                f"**Boilerplate & Runtime Stubs (Category A): {boilerplate_count} functions**\n\n"
                f"The following functions are compiler-generated boilerplate, CRT startup stubs, or standard "
                f"library wrappers and were excluded from vulnerability analysis:\n\n"
                f"{category_a_names}\n"
            )

        prompt = f"""
You are an expert security engineer and binary auditor. You will write a comprehensive, professional, and visually stunning unified vulnerability assessment report.

Below is the context retrieved from secure coding databases (SEI CERT C / CWE) and details on the functions analyzed by our GNN compiler wrapper.

### SECURITY METADATA:
- **Filename**: {filename}
- **SHA-256 Checksum**: {sha256_hash}
- **Verdict**: {verdict}
- **Risk Level**: {risk_level}
- **Total Functions Evaluated**: {total_functions}
- **Boilerplate Functions & Runtime Stubs Filtered**: {boilerplate_count}
- **Actual Code Functions Scanned**: {actual_count}

### SECURITY STANDARDS CONTEXT:
{reference_context}

### CATEGORY B — ACTUAL CODE FUNCTIONS AUDIT:
{category_b_context}

### CATEGORY A — BOILERPLATE & RUNTIME STUBS:
{category_a_context}

Please draft a gorgeous Markdown document including:
1. **Title**: '# Sentinel AI Security Audit Report'
2. **Audit Metadata Labeled List**: Display the security metadata cleanly using a bolded list (do NOT use markdown tables to ensure clean PDF compiling compatibility):
   - **Filename**: {filename}
   - **SHA-256 Checksum**: {sha256_hash}
   - **Verdict**: {verdict}
   - **Risk Level**: {risk_level}
   - **Total Functions Evaluated**: {total_functions}
   - **Boilerplate Functions & Runtime Stubs Filtered**: {boilerplate_count}
   - **Actual Code Functions Scanned**: {actual_count}
3. **Executive Summary**: Write a professional executive summary explaining the verdict and scope of the audit.
   - For 0 vulnerabilities found: explain that all function Control Flow Graphs (CFGs) were checked and conform to standard coding rules. No vulnerabilities were detected.
   - For cases with vulnerabilities (Yellow, Orange, Red tiers): explain the threat vectors found and the urgency of the remediation. Use the custom tier name ({color_tier}) and severity ({severity_level}) appropriately.
   - Do NOT use the big word "VULNERABLE" or "CLEAN" anywhere in the document, especially for headers or big verdicts. Instead, use "{verdict}" to describe the verdict.
4. **Category B — Actual Code Functions (Detailed Analysis)**: This section must appear IMMEDIATELY after the executive summary.
   - List EVERY Category B function.
   - For each SAFE function: provide a concise 2-3 line security validation summary explaining that its CFG patterns conform to secure baselines.
   - For each VULNERABLE function: provide a detailed breakdown containing:
     - Technical breakdown of the exploit vector (how the instructions represent buffer overflows or out-of-bounds writes).
     - The SEI CERT C coding rule violated.
     - **Remediation & Secure Code Fix**: Provide a clear, correct rewrite of the vulnerable concept in C/C++ showing secure library usage (e.g. using `strncat` or boundary bounds checks).
5. **Category A — Boilerplate & Runtime Stubs**: Place this section at the VERY BOTTOM of the report.
   - Include a single short explanation header explaining what these functions are.
   - List only their names in a compact format.
6. **General Mitigations**: Highlight best practices for compilation (canaries, DEP, ASLR, Control Flow Integrity) and security testing.

CRITICAL INSTRUCTIONS:
- Do NOT display or print any confidence levels, model confidence percentages, or probability scores ANYWHERE in the report.
- Do NOT use the big word "VULNERABLE" or "CLEAN" as standalone headers or verdicts.
- Use strong markdown syntax, code snippets, headers, and bullet points. Make it read like a premium security consultancy report.
"""

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
        docs = self.vector_store.similarity_search(query, k=2)
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
