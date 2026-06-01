import os
import logging
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

class RAGService:
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.embeddings = None
        self.vector_store = None
        self.llm = None
        self._is_initialized = False

    def initialize(self):
        """Initializes the embeddings, vector store, and Gemini LLM."""
        if self._is_initialized:
            return

        if not self.api_key:
            raise ValueError("Google Gemini API Key not found in environment variables.")

        logger.info("Initializing RAG Service (Gemini Cloud Embeddings)...")
        self.embeddings = GoogleGenerativeAIEmbeddings(
            model="models/gemini-embedding-2",
            google_api_key=self.api_key
        )

        self.llm = ChatGoogleGenerativeAI(
            model="gemini-3-flash-preview",
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
        logger.info("✅ RAG Service initialized successfully.")

    def seed_db_if_empty(self):
        """Pre-loads standard CWE security guidelines and CERT C coding standards into ChromaDB."""
        # Check if vector store is already populated (simple count check)
        try:
            count = len(self.vector_store.get()["ids"])
        except Exception:
            count = 0

        if count > 0:
            logger.info(f"Reference database already seeded with {count} documents.")
            return

        logger.info("Seeding Reference database with security guidelines...")
        reference_data = [
            {
                "content": (
                    "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow'). "
                    "This occurs when the program copies an input buffer to a destination buffer without "
                    "verifying that the destination has enough space. Dangers of strcat: The standard strcat(dest, src) "
                    "appends src to dest without bounds checking. If the input exceeds buffer boundaries, it overflows "
                    "the stack, leading to memory corruption, program crash, or execution hijacking. "
                    "CERT C Rule STR31-C: Guarantee that storage for strings has sufficient space for character data "
                    "and the null terminator. Mitigation: Use bounded copy functions like strncat(dest, src, sizeof(dest) - strlen(dest) - 1) "
                    "or perform explicit size checks before copying string characters."
                ),
                "metadata": {"cwe": "CWE-120", "type": "Buffer Overflow", "standard": "CERT C STR31-C"}
            },
            {
                "content": (
                    "CWE-121: Stack-based Buffer Overflow. A stack-based buffer overflow condition exists when a buffer "
                    "allocated on the stack has data written to it that is larger than the buffer. This can corrupt "
                    "the function's stack frame, overwrite local variables, and hijack the instruction pointer (EIP/RIP) "
                    "upon function return. Commonly caused by gets(), strcpy(), strcat(), or unchecked copy loops. "
                    "CERT C Rule STR31-C / ARR30-C: Formulate bounds checks on all buffers. "
                    "Mitigation: Avoid gets() entirely (use fgets instead). Ensure target buffer size is larger than the input "
                    "data size using pre-conditions or bounds checks. Enable compiler protections like stack canaries (-fstack-protector)."
                ),
                "metadata": {"cwe": "CWE-121", "type": "Stack Overflow", "standard": "CERT C ARR30-C"}
            },
            {
                "content": (
                    "CWE-787: Out-of-bounds Write. The software writes data past the end, or before the beginning, of the "
                    "intended buffer. This can lead to heap corruption, local variable overwrite, or system crash. "
                    "Common in manual pointer arithmetic or custom memory copy loops without boundary assertions. "
                    "CERT C Rule ARR30-C: Do not form or use out-of-bounds pointers or array subscripts. "
                    "Mitigation: Always check boundaries. Use secure memory API wrappers. Validate that pointer offsets "
                    "remain within the allocated memory bounds (e.g., bounds verification on array indexing)."
                ),
                "metadata": {"cwe": "CWE-787", "type": "Out-of-bounds Write", "standard": "CERT C ARR30-C"}
            },
            {
                "content": (
                    "CWE-134: Use of Externally-Controlled Format String. The software uses input from an external source "
                    "as the format string argument in formatted output functions like printf, sprintf, fprintf, syslog. "
                    "Attackers can leverage format specifiers (e.g., %x, %s, %n) to dump stack memory or overwrite "
                    "arbitrary memory locations, leading to full code execution. "
                    "CERT C Rule FIO30-C: Exclude user input from format strings. "
                    "Mitigation: Always write formatted functions using explicit specifiers, e.g., use printf(\"%s\", user_input) "
                    "instead of printf(user_input)."
                ),
                "metadata": {"cwe": "CWE-134", "type": "Format String", "standard": "CERT C FIO30-C"}
            },
            {
                "content": (
                    "CWE-416: Use After Free. Referencing memory after it has been freed can lead to undefined behavior, "
                    "program crash, or arbitrary code execution (especially if an attacker re-allocates that same heap block "
                    "to a controlled object structure). "
                    "CERT C Rule MEM30-C: Do not access freed memory. "
                    "Mitigation: After calling free(ptr), immediately assign ptr = NULL. This ensures any subsequent access "
                    "fails immediately with a null pointer dereference rather than silently corrupting memory or enabling exploits."
                ),
                "metadata": {"cwe": "CWE-416", "type": "Use After Free", "standard": "CERT C MEM30-C"}
            }
        ]

        documents = [
            Document(page_content=item["content"], metadata=item["metadata"])
            for item in reference_data
        ]
        self.vector_store.add_documents(documents)
        logger.info("✅ Reference database seeded with 5 security standard guidelines.")

    def generate_vulnerability_report(self, flagged_functions: list[dict]) -> str:
        """
        Retrieves reference standards and generates a comprehensive, beautiful Markdown security report
        for the GNN-flagged functions.
        """
        self.initialize()

        if not flagged_functions:
            return (
                "# Sentinel AI - Security Analysis Report\n\n"
                "## Executive Summary\n\n"
                "**Verdict:** SAFE  \n"
                "**Risk Level:** LOW  \n\n"
                "Our advanced GNN (Graph Neural Network) analysis examined all function Control Flow Graphs (CFGs) "
                "within the uploaded binary/source file. No suspicious patterns representing memory safety or "
                "input validation vulnerabilities were flagged. The application appears compliant with standard CERT C coding rules."
            )

        # Sort flagged functions by confidence and limit detailed analysis to top 10 critical ones
        critical_functions = sorted(flagged_functions, key=lambda x: x["confidence"], reverse=True)
        top_critical = critical_functions[:10]

        # Retrieve reference guidelines for the unique set of CWE IDs flagged (reduces API calls)
        retrieved_docs = []
        unique_cwes = set(func.get('cwe_id', 'CWE-119') for func in top_critical)
        for cwe in unique_cwes:
            query = f"CWE memory corruption {cwe} buffer overflow out of bounds write"
            docs = self.vector_store.similarity_search(query, k=1)
            if docs:
                retrieved_docs.append(docs[0].page_content)

        reference_context = "\n\n".join(set(retrieved_docs))

        # Format details of the top flagged functions
        functions_context = f"**Total Flagged Functions:** {len(flagged_functions)}\n"
        if len(flagged_functions) > 10:
            functions_context += f"*(Showing detailed security audit for the top 10 most critical findings)*\n\n"
        
        for idx, func in enumerate(top_critical):
            functions_context += (
                f"### Finding {idx + 1}: Function `{func['function_name']}`\n"
                f"- **Model Confidence:** {func['confidence']:.2%}\n"
                f"- **Identified Threat:** {func.get('cwe_id', 'CWE-119')} (Memory Safety / Buffer Overflow)\n"
                f"- **Model Explanation:** {func['brief_explanation']}\n"
                f"- **Disassembled CFG Code Blocks:**\n"
                f"```\n{func['decompiled_code']}\n```\n\n"
            )

        prompt = f"""
You are an expert security engineer and binary auditor. You will write a comprehensive, professional, and visually stunning vulnerability assessment report.

Below is the context retrieved from secure coding databases (SEI CERT C / CWE) and details on the functions flagged by our GNN compiler wrapper.

### SECURITY STANDARDS CONTEXT:
{reference_context}

### FLAGGED FUNCTIONS TO AUDIT:
{functions_context}

Please draft a gorgeous Markdown document including:
1. A **Title**: '# Sentinel AI Security Audit Report'
2. An **Executive Summary** with a bold verdict, overall risk level (HIGH/CRITICAL), and summary of finding count.
3. A detailed **Vulnerability Analysis** section for each flagged function, containing:
   - Technical breakdown of the exploit vector (how the instructions represent buffer overflows or out-of-bounds writes).
   - The SEI CERT C coding rule violated.
   - **Remediation & Secure Code Fix**: Provide a clear, correct rewrite of the vulnerable concept in C/C++ showing secure library usage (e.g. using `strncat` or boundary bounds checks).
4. **General Mitigations**: Highlight best practices for compilation (canaries, DEP, ASLR) and security testing.

Use strong markdown syntax, code snippets, headers, and bullet points. Make it read like a premium security consultancy report.
"""

        logger.info("Invoking Gemini to compile vulnerability report...")
        response = self.llm.invoke(prompt)
        
        content = response.content
        if isinstance(content, list):
            content = "\n".join([str(item) if not isinstance(item, dict) else item.get("text", str(item)) for item in content])
        report_markdown = content.strip()
        logger.info("Vulnerability report successfully compiled!")
        return report_markdown

    def get_chat_response(self, query: str, decompiled_code: str, chat_history: list[dict] = []) -> str:
        """
        Handles real-time chatbot queries. Contextualizes the answer with the preloaded Reference DB
        and the specific decompiled function context under discussion.
        """
        self.initialize()

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

Please formulate an elegant, friendly, and expert answer. Structure it with clear paragraphs or bullet points if needed. Ground your response heavily in secure C/C++ coding guidelines and explain concepts in a clear, developer-friendly manner.
"""

        logger.info(f"Invoking Gemini chatbot for query: '{query[:40]}...'")
        response = self.llm.invoke(prompt)
        
        content = response.content
        if isinstance(content, list):
            content = "\n".join([str(item) if not isinstance(item, dict) else item.get("text", str(item)) for item in content])
        return content.strip()


# Module singleton
rag_service = RAGService()
