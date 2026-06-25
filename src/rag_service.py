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
        flagged_functions: list[dict],
        filename: str = "Unknown",
        sha256_hash: str = "Unknown",
        total_functions: int = 0
    ) -> str:
        """
        Retrieves reference standards from the knowledge base and generates a comprehensive Markdown
        security report for the scanned file (supporting both safe and vulnerable verdicts).
        """
        self.initialize()

        flagged_count = len(flagged_functions)
        is_vulnerable = flagged_count > 0
        percentage = (flagged_count / total_functions * 100) if total_functions > 0 else 0.0

        if percentage == 0.0:
            verdict = f"0 vulnerabilities found out of {total_functions} functions"
            risk_level = "LOW (Green)"
            color_tier = "Green"
            severity_level = "LOW"
        elif percentage <= 25.0:
            verdict = f"{flagged_count} vulnerabilities found out of {total_functions} functions"
            risk_level = "MEDIUM (Yellow)"
            color_tier = "Yellow"
            severity_level = "MEDIUM"
        elif percentage <= 50.0:
            verdict = f"{flagged_count} vulnerabilities found out of {total_functions} functions"
            risk_level = "HIGH (Orange)"
            color_tier = "Orange"
            severity_level = "HIGH"
        else:
            verdict = f"{flagged_count} vulnerabilities found out of {total_functions} functions"
            risk_level = "CRITICAL (Red)"
            color_tier = "Red"
            severity_level = "CRITICAL"

        # Retrieve reference guidelines from Chroma DB
        retrieved_docs = []
        if is_vulnerable:
            # Sort flagged functions by confidence and limit detailed analysis to top 10 critical ones
            critical_functions = sorted(flagged_functions, key=lambda x: x["confidence"], reverse=True)
            top_critical = critical_functions[:10]
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

        # Format details of functions under analysis
        if is_vulnerable:
            functions_context = f"**Total Flagged Functions:** {len(flagged_functions)}\n"
            if len(flagged_functions) > 10:
                functions_context += f"*(Showing detailed security audit for the top 10 most critical findings)*\n\n"
            for idx, func in enumerate(top_critical):
                functions_context += (
                    f"### Finding {idx + 1}: Function `{func['function_name']}`\n"
                    f"- **Identified Threat:** {func.get('cwe_id', 'CWE-119')} (Memory Safety / Buffer Overflow)\n"
                    f"- **Model Explanation:** {func['brief_explanation']}\n"
                    f"- **Disassembled CFG Code Blocks:**\n"
                    f"```\n{func['decompiled_code']}\n```\n\n"
                )
        else:
            functions_context = (
                f"**Total Flagged Functions:** 0\n"
                f"No functions were flagged as suspicious or vulnerable by the GNN model.\n"
                f"All {total_functions} functions analyzed conform to the secure coding baselines."
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

### SECURITY STANDARDS CONTEXT:
{reference_context}

### FUNCTIONS AUDIT CONTEXT:
{functions_context}

Please draft a gorgeous Markdown document including:
1. **Title**: '# Sentinel AI Security Audit Report'
2. **Audit Metadata Labeled List**: Display the security metadata cleanly using a bolded list (do NOT use markdown tables to ensure clean PDF compiling compatibility):
   - **Filename**: {filename}
   - **SHA-256 Checksum**: {sha256_hash}
   - **Verdict**: {verdict}
   - **Risk Level**: {risk_level}
   - **Total Functions Evaluated**: {total_functions}
3. **Executive Summary**: Write a professional executive summary explaining the verdict and scope of the audit.
   - For 0 vulnerabilities found: explain that all function Control Flow Graphs (CFGs) were checked and conform to standard coding rules. No vulnerabilities were detected.
   - For cases with vulnerabilities (Yellow, Orange, Red tiers): explain the threat vectors found and the urgency of the remediation. Use the custom tier name ({color_tier}) and severity ({severity_level}) appropriately.
   - Do NOT use the big word "VULNERABLE" or "CLEAN" anywhere in the document, especially for headers or big verdicts. Instead, use "{verdict}" to describe the verdict.
4. **Analysis Metrics**: Detail the static analysis parameters, total function count, and number of flagged functions. Do NOT show or include any model confidence levels or percentages.
5. **Detailed Findings Section**:
   - For 0 vulnerabilities found: state "No security flaws or rule violations were flagged." List the checked functions as safe.
   - For cases with vulnerabilities: provide a detailed breakdown for each flagged function, containing:
     - Technical breakdown of the exploit vector (how the instructions represent buffer overflows or out-of-bounds writes).
     - The SEI CERT C coding rule violated.
     - **Remediation & Secure Code Fix**: Provide a clear, correct rewrite of the vulnerable concept in C/C++ showing secure library usage (e.g. using `strncat` or boundary bounds checks).
     - Do NOT display or print any confidence levels or model confidence percentages for the findings.
6. **General Mitigations**: Highlight best practices for compilation (canaries, DEP, ASLR, Control Flow Integrity) and security testing.

Use strong markdown syntax, code snippets, headers, and bullet points. Make it read like a premium security consultancy report.
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
