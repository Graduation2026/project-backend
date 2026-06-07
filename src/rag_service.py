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

        # We have 12 documents now (5 original + 4 new CWEs + 3 non-CWE helper guides)
        if count > 0:
            if count >= 12:
                logger.info(f"Reference database already seeded with {count} documents.")
                return
            else:
                logger.info(f"Reference database has partial seed ({count} docs). Clearing collection to re-seed...")
                try:
                    self.vector_store.delete(ids=self.vector_store.get()["ids"])
                except Exception as e:
                    logger.warning(f"Failed to clear collection: {e}")

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
            },
            {
                "content": (
                    "CWE-190: Integer Overflow or Wraparound. Occurs when a math operation produces a value outside the range "
                    "that can be stored in the integer type. In C, if an integer overflow occurs during memory allocation "
                    "calculations (like malloc(size * count)), it can wrap around to a very small number, causing malloc to "
                    "allocate a tiny buffer while the program still writes the full amount of data, leading to a heap-based buffer overflow. "
                    "CERT C Rule INT30-C: Ensure that operations on unsigned integers do not wrap. "
                    "Mitigation: Check for overflow conditions before multiplication or addition, or use secure library safe math modules."
                ),
                "metadata": {"cwe": "CWE-190", "type": "Integer Overflow", "standard": "CERT C INT30-C"}
            },
            {
                "content": (
                    "CWE-476: NULL Pointer Dereference. Occurs when a program dereferences a pointer that is expected to be valid "
                    "but resolves to NULL. This causes immediate program crash or denial of service, and in some situations "
                    "(such as kernel context or specific runtime environments), it can lead to arbitrary code execution. "
                    "CERT C Rule EXP34-C: Do not dereference null pointers. "
                    "Mitigation: Always check pointers for NULL before dereferencing, especially after memory allocations (malloc/calloc) "
                    "and API library returns."
                ),
                "metadata": {"cwe": "CWE-476", "type": "NULL Pointer Dereference", "standard": "CERT C EXP34-C"}
            },
            {
                "content": (
                    "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). "
                    "Occurs when an application passes unvalidated user inputs directly to command line executors like system() or popen(). "
                    "Attackers can insert shell delimiters (like semicolon, ampersand, pipe) to execute arbitrary commands with the privileges of the binary. "
                    "CERT C Rule ENV33-C: Do not call system(). "
                    "Mitigation: Avoid system() entirely. Use safe APIs like execve() or createProcess() which pass parameters "
                    "as discrete arrays rather than raw shell execution strings."
                ),
                "metadata": {"cwe": "CWE-78", "type": "OS Command Injection", "standard": "CERT C ENV33-C"}
            },
            {
                "content": (
                    "CWE-242: Use of Inherently Dangerous Function. Certain legacy standard library functions like gets() cannot be "
                    "used safely because they do not accept a maximum buffer size. They will copy input characters until a newline "
                    "is found, making stack-based buffer overflows inevitable if user input exceeds the target array bounds. "
                    "CERT C Rule MSC24-C: Do not use gets(). "
                    "Mitigation: Ban gets() completely. Replace with fgets() or secure C11 alternatives like gets_s()."
                ),
                "metadata": {"cwe": "CWE-242", "type": "Dangerous Function", "standard": "CERT C MSC24-C"}
            },
            {
                "content": (
                    "Compiler Hardening Defenses & Binary Protections. Mitigating exploitation in compiled binaries requires "
                    "compiler-enforced flags: Stack Canaries (-fstack-protector-strong) place guard values on the stack to detect overflows "
                    "before returning. DEP/NX (Data Execution Prevention / No-Execute) marks data segments as non-executable to prevent shellcode injection. "
                    "ASLR (Address Space Layout Randomization) compiled with -fPIE -pie randomizes address layouts. Full RELRO (-Wl,-z,relro,-z,now) "
                    "makes global offset tables read-only to prevent redirection hooks."
                ),
                "metadata": {"cwe": "General", "type": "Compiler Protections", "standard": "Binary Hardening"}
            },
            {
                "content": (
                    "Exploitation Mechanics and Code Vulnerability Consequences. Memory safety bugs lead to exploit vectors: Stack Smashing "
                    "overwrites the saved instruction pointer (EIP/RIP) to redirect control. Return-Oriented Programming (ROP) chains execute "
                    "snippets of code (gadgets) already in memory to bypass DEP. Heap sprays flood memory to guide execution flow. "
                    "Understanding these consequences helps engineers prioritize remediation of buffer copies and out-of-bounds writes."
                ),
                "metadata": {"cwe": "General", "type": "Exploitation Mechanics", "standard": "Exploit Context"}
            },
            {
                "content": (
                    "Secure Library Alternatives & API replacements. Legacy C functions (strcpy, strcat, sprintf, gets) should be replaced "
                    "with safe, bounded variants. Use strncpy or strlcpy for copying, strncat for concatenation, snprintf for formatted printing, "
                    "and fgets for line input. Always verify that strings are null-terminated and explicitly validate sizes against destination bounds."
                ),
                "metadata": {"cwe": "General", "type": "API Alternatives", "standard": "Secure APIs"}
            }
        ]

        documents = [
            Document(page_content=item["content"], metadata=item["metadata"])
            for item in reference_data
        ]
        self.vector_store.add_documents(documents)
        logger.info(f"✅ Reference database seeded with {len(documents)} security standard guidelines.")

    def generate_vulnerability_report(
        self,
        flagged_functions: list[dict],
        filename: str = "Unknown",
        sha256_hash: str = "Unknown",
        total_functions: int = 0
    ) -> str:
        """
        Retrieves reference standards and generates a comprehensive, unified Markdown security report
        for the scanned file (supporting both safe and vulnerable verdicts).
        """
        self.initialize()

        is_vulnerable = len(flagged_functions) > 0

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
                    f"- **Model Confidence:** {func['confidence']:.2%}\n"
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
- **Verdict**: {"VULNERABLE" if is_vulnerable else "SAFE"}
- **Risk Level**: {"CRITICAL" if is_vulnerable else "LOW"}
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
   - **Verdict**: {"VULNERABLE" if is_vulnerable else "SAFE"}
   - **Risk Level**: {"CRITICAL" if is_vulnerable else "LOW"}
   - **Total Functions Evaluated**: {total_functions}
3. **Executive Summary**: Write a professional executive summary explaining the verdict and scope of the audit.
   - For SAFE results: explain that all function Control Flow Graphs (CFGs) were checked and conform to standard coding rules.
   - For VULNERABLE results: explain the threat vectors and the urgency of the remediation.
4. **Analysis Metrics**: Detail the static analysis parameters, total function count, and average confidence of the checks.
5. **Detailed Findings Section**:
   - For SAFE results: state "No security flaws or rule violations were flagged." List the checked functions as safe.
   - For VULNERABLE results: provide a detailed breakdown for each flagged function, containing:
     - Technical breakdown of the exploit vector (how the instructions represent buffer overflows or out-of-bounds writes).
     - The SEI CERT C coding rule violated.
     - **Remediation & Secure Code Fix**: Provide a clear, correct rewrite of the vulnerable concept in C/C++ showing secure library usage (e.g. using `strncat` or boundary bounds checks).
6. **General Mitigations**: Highlight best practices for compilation (canaries, DEP, ASLR, Control Flow Integrity) and security testing.

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

Important: If the conversation is already underway (i.e., Conversation History contains previous User and Assistant exchanges), do NOT greet the user, do NOT introduce yourself, and do NOT repeat your name. Address the user's question directly and concisely.

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
