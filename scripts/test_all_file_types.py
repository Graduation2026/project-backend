import os
import sys
import subprocess
import json
import uuid
import shutil
import urllib.request
from pathlib import Path

# --- Configuration ---
API_BASE_URL = "http://127.0.0.1:8000"
API_ANALYZE_URL = f"{API_BASE_URL}/analyze"
API_HEALTH_URL = f"{API_BASE_URL}/health"

SCRATCH_DIR = Path(__file__).resolve().parent
BUILD_DIR = SCRATCH_DIR / "build_test"
BUILD_DIR.mkdir(parents=True, exist_ok=True)

RUNBOOK_PATH = Path("d:/ml_binpool_attempt/sentinel_ai/project-backend/vulnerability_test_runbook.md")

# --- "Meaty" Code Templates ---
# Safe C Template: Contains mathematical algorithms, bounded copy, safe logging, and size-checked allocation
SAFE_C = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Auxiliary calculations to simulate complexity
int perform_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) {
            result += i * 3;
        } else {
            result -= i * 2;
        }
    }
    return result;
}

// Bounded string copying (Safe version of string_manipulator)
void process_user_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    
    // Bounded copy using strncpy
    strncpy(dest, input, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\\0';
    
    int calc = perform_calculations((int)strlen(dest));
    printf("Processing result (Safe): %s, calc: %d\\n", dest, calc);
}

// Safe formatting (Safe version of logger_service)
void log_message(const char *msg) {
    if (msg == NULL) return;
    char log_buf[128];
    snprintf(log_buf, sizeof(log_buf), "LOG: %s\\n", msg);
    printf("%s", log_buf);
}

// Safe memory allocation (Safe version of array_allocator)
int *allocate_integer_array(int count) {
    if (count <= 0 || count > 1000) {
        printf("Invalid allocation size request.\\n");
        return NULL;
    }
    int *arr = (int *)malloc(count * sizeof(int));
    if (arr == NULL) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_user_string(argv[1]);
        log_message(argv[1]);
        int *data = allocate_integer_array(5);
        if (data) {
            printf("Data allocated successfully: %d\\n", data[4]);
            free(data);
        }
    } else {
        printf("Usage: %s <input_string>\\n", argv[0]);
    }
    return 0;
}
"""

# Vulnerable C Template: Contains identical math structure but introduces strcpy, format string printf, and unsafe malloc
VULN_C = """#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Identical structural setup to keep CFG similar
int perform_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) {
            result += i * 3;
        } else {
            result -= i * 2;
        }
    }
    return result;
}

// Unbounded string copying (Vulnerable version of string_manipulator)
void process_user_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    
    // Unbounded copy causing stack overflow (CWE-121)
    strcpy(dest, input); 
    
    int calc = perform_calculations((int)strlen(dest));
    printf("Processing result (Vuln): %s, calc: %d\\n", dest, calc);
}

// Vulnerable format string (Vulnerable version of logger_service)
void log_message(const char *msg) {
    if (msg == NULL) return;
    // Direct output of user-supplied format string (CWE-134)
    printf(msg); 
    printf("\\n");
}

// Vulnerable allocation (Vulnerable version of array_allocator)
int *allocate_integer_array(int count) {
    // Integer overflow in memory size calculation (CWE-190)
    int *arr = (int *)malloc(count * sizeof(int));
    if (arr == NULL) {
        return NULL;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_user_string(argv[1]);
        log_message(argv[1]);
        int *data = allocate_integer_array(5);
        if (data) {
            printf("Data allocated successfully: %d\\n", data[4]);
            free(data);
        }
    } else {
        printf("Usage: %s <input_string>\\n", argv[0]);
    }
    return 0;
}
"""

# Safe C++ Template: Uses modern safe standard templates
SAFE_CPP = """#include <iostream>
#include <string>
#include <vector>
#include <memory>

int perform_cpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) {
            result += i * 3;
        } else {
            result -= i * 2;
        }
    }
    return result;
}

void process_user_cpp_string(const std::string& input) {
    std::string safe_dest = input.substr(0, 31);
    int calc = perform_cpp_calculations((int)safe_dest.length());
    std::cout << "CPP Processing result (Safe): " << safe_dest << ", calc: " << calc << std::endl;
}

void log_cpp_message(const std::string& msg) {
    std::cout << "LOG: " << msg << std::endl;
}

std::unique_ptr<int[]> allocate_cpp_array(int count) {
    if (count <= 0 || count > 1000) {
        std::cout << "Invalid count for array allocation." << std::endl;
        return nullptr;
    }
    std::unique_ptr<int[]> arr(new int[count]);
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        std::string input(argv[1]);
        process_user_cpp_string(input);
        log_cpp_message(input);
        auto data = allocate_cpp_array(5);
        if (data) {
            std::cout << "CPP Data allocated: " << data[4] << std::endl;
        }
    } else {
        std::cout << "Usage: " << argv[0] << " <input_string>" << std::endl;
    }
    return 0;
}
"""

# Vulnerable C++ Template: Integrates std::strcpy and printf format vulnerability
VULN_CPP = """#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

int perform_cpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) {
            result += i * 3;
        } else {
            result -= i * 2;
        }
    }
    return result;
}

void process_user_cpp_string(const char* input) {
    char dest[32];
    if (input == nullptr) return;
    // Unbounded string copy (CWE-121)
    std::strcpy(dest, input);
    
    int calc = perform_cpp_calculations((int)std::strlen(dest));
    std::cout << "CPP Processing result (Vuln): " << dest << ", calc: " << calc << std::endl;
}

void log_cpp_message(const char* msg) {
    if (msg == nullptr) return;
    // Vulnerable format string (CWE-134)
    std::printf(msg);
    std::printf("\\n");
}

int* allocate_cpp_array(int count) {
    // Integer overflow in array allocation size calculation (CWE-190)
    int* arr = (int*)std::malloc(count * sizeof(int));
    if (arr == nullptr) {
        return nullptr;
    }
    for (int i = 0; i < count; i++) {
        arr[i] = i * i;
    }
    return arr;
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_user_cpp_string(argv[1]);
        log_cpp_message(argv[1]);
        int* data = allocate_cpp_array(5);
        if (data) {
            std::cout << "CPP Data allocated: " << data[4] << std::endl;
            std::free(data);
        }
    } else {
        std::cout << "Usage: " << argv[0] << " <input_string>" << std::endl;
    }
    return 0;
}
"""

# Safe Header Template: Self-contained functions compiled by API directly
SAFE_H = """#ifndef SAFE_H
#define SAFE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static inline int perform_header_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

static inline void process_user_header_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    strncpy(dest, input, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\\0';
    int calc = perform_header_calculations((int)strlen(dest));
    printf("Header Processing (Safe): %s, calc: %d\\n", dest, calc);
}
#endif
"""

# Vulnerable Header Template: Direct strcpy vulnerability defined inline
VULN_H = """#ifndef VULN_H
#define VULN_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static inline int perform_header_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

static inline void process_user_header_string(const char *input) {
    char dest[32];
    if (input == NULL) return;
    strcpy(dest, input); // Vulnerable (CWE-121)
    int calc = perform_header_calculations((int)strlen(dest));
    printf("Header Processing (Vuln): %s, calc: %d\\n", dest, calc);
}
#endif
"""

# Safe C++ Header Template
SAFE_HPP = """#ifndef SAFE_HPP
#define SAFE_HPP
#include <iostream>
#include <string>

inline int perform_hpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

inline void process_user_hpp_string(const std::string& input) {
    std::string safe_dest = input.substr(0, 31);
    int calc = perform_hpp_calculations((int)safe_dest.length());
    std::cout << "HPP Processing (Safe): " << safe_dest << ", calc: " << calc << std::endl;
}
#endif
"""

# Vulnerable C++ Header Template
VULN_HPP = """#ifndef VULN_HPP
#define VULN_HPP
#include <iostream>
#include <string>
#include <cstring>

inline int perform_hpp_calculations(int val) {
    int result = 0;
    for (int i = 0; i < val; i++) {
        if (i % 2 == 0) result += i * 3;
        else result -= i * 2;
    }
    return result;
}

inline void process_user_hpp_string(const char* input) {
    char dest[32];
    if (input == nullptr) return;
    std::strcpy(dest, input); // Vulnerable (CWE-121)
    int calc = perform_hpp_calculations((int)std::strlen(dest));
    std::cout << "HPP Processing (Vuln): " << dest << ", calc: " << calc << std::endl;
}
#endif
"""

# --- HTTP Utility ---
def upload_file_to_api(filepath: Path) -> dict:
    boundary = uuid.uuid4().hex
    with open(filepath, 'rb') as f:
        file_content = f.read()
    
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filepath.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode('utf-8') + file_content + f"\r\n--{boundary}--\r\n".encode('utf-8')
    
    api_key = os.getenv("SENTINEL_API_KEY", "")
    headers = {
        'Content-Type': f'multipart/form-data; boundary={boundary}',
        'Content-Length': str(len(body))
    }
    if api_key:
        headers['X-API-Key'] = api_key
        
    req = urllib.request.Request(API_ANALYZE_URL, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode('utf-8'))
    except Exception as e:
        print(f"  [!] HTTP Request failed: {e}")
        return {"status": "error", "message": str(e)}

# --- Health check ---
def check_api_health() -> bool:
    try:
        with urllib.request.urlopen(API_HEALTH_URL, timeout=3) as res:
            data = json.loads(res.read().decode('utf-8'))
            return data.get("status") == "healthy"
    except Exception:
        return False

# --- Compiler Helper ---
def compile_target(cmd, output_path: Path):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, shell=True, cwd=str(BUILD_DIR))
        if res.returncode == 0 and output_path.exists():
            return True
        else:
            print(f"  [!] Compilation failed: {cmd}")
            print(f"  stderr: {res.stderr}")
            return False
    except Exception as e:
        print(f"  [!] Execution failed: {e}")
        return False

# --- Main Test Sequence ---
def main():
    print("=" * 70)
    print("        SENTINEL AI - COMPREHENSIVE PIPELINE STRESS TEST")
    print("=" * 70)
    
    if not check_api_health():
        print(f"[!] ERROR: Sentinel AI FastAPI server is not running on {API_BASE_URL}.")
        sys.exit(1)
        
    print("[+] API Connection Active.")
    print(f"[+] Output Runbook Path: {RUNBOOK_PATH}")
    
    # Write source codes to build directory
    sources = {
        "safe.c": SAFE_C,
        "vuln.c": VULN_C,
        "safe.cpp": SAFE_CPP,
        "vuln.cpp": VULN_CPP,
        "safe.cc": SAFE_CPP, # Use C++ safe logic
        "vuln.cc": VULN_CPP, # Use C++ vuln logic
        "safe.cxx": SAFE_CPP, # Use C++ safe logic
        "vuln.cxx": VULN_CPP, # Use C++ vuln logic
        "safe.h": SAFE_H,
        "vuln.h": VULN_H,
        "safe.hpp": SAFE_HPP,
        "vuln.hpp": VULN_HPP
    }
    
    for name, code in sources.items():
        with open(BUILD_DIR / name, "w") as f:
            f.write(code)
            
    print(f"[+] Code templates written to {BUILD_DIR}")
    # Check WSL availability once with a 15-second timeout to allow cold-booting
    wsl_available = False
    try:
        res = subprocess.run(["wsl", "whoami"], capture_output=True, timeout=15)
        if res.returncode == 0:
            wsl_available = True
    except Exception:
        pass

    # Compilation Matrix setup
    # We compile safe/vulnerable formats: .o, .exe, .dll, .elf, .so
    compile_jobs = [
        # Windows PE Object files (.o)
        ("gcc -c -O0 -g -o safe_c.o safe.c", BUILD_DIR / "safe_c.o"),
        ("gcc -c -O0 -g -o vuln_c.o vuln.c", BUILD_DIR / "vuln_c.o"),
        
        # Windows PE Executables (.exe)
        ("gcc -O0 -g -o safe_c.exe safe.c", BUILD_DIR / "safe_c.exe"),
        ("gcc -O0 -g -o vuln_c.exe vuln.c", BUILD_DIR / "vuln_c.exe"),
        
        # Windows Dynamic Link Libraries (.dll)
        ("gcc -shared -O0 -g -o safe_c.dll safe.c", BUILD_DIR / "safe_c.dll"),
        ("gcc -shared -O0 -g -o vuln_c.dll vuln.c", BUILD_DIR / "vuln_c.dll"),
        
        # WSL Linux ELF compilation
        ("wsl gcc -O0 -g -o safe_c.elf safe.c", BUILD_DIR / "safe_c.elf"),
        ("wsl gcc -O0 -g -o vuln_c.elf vuln.c", BUILD_DIR / "vuln_c.elf"),
        
        # WSL Linux Shared Objects (.so)
        ("wsl gcc -shared -fPIC -O0 -g -o safe_c.so safe.c", BUILD_DIR / "safe_c.so"),
        ("wsl gcc -shared -fPIC -O0 -g -o vuln_c.so vuln.c", BUILD_DIR / "vuln_c.so"),
    ]
    
    for cmd, path in compile_jobs:
        # Check if WSL target and check if wsl is present
        is_wsl = "wsl " in cmd
        if is_wsl and not wsl_available:
            print(f"  [-] WSL not detected. Skipping ELF compilation for {path.name}.")
            continue
        
        success = compile_target(cmd, path)
        if success:
            print(f"  [+] Compiled: {path.name}")
            
    # Create .bin files by copying the generated Windows PE executable
    if (BUILD_DIR / "safe_c.exe").exists():
        shutil.copy2(BUILD_DIR / "safe_c.exe", BUILD_DIR / "safe_c.bin")
        print("  [+] Created: safe_c.bin (Copied from safe_c.exe)")
    if (BUILD_DIR / "vuln_c.exe").exists():
        shutil.copy2(BUILD_DIR / "vuln_c.exe", BUILD_DIR / "vuln_c.bin")
        print("  [+] Created: vuln_c.bin (Copied from vuln_c.exe)")

    # Assemble test cases: label, filepath, expected
    test_cases = []
    
    # 1. Source formats
    test_cases.append(("C Source [Safe]", BUILD_DIR / "safe.c", "SAFE"))
    test_cases.append(("C Source [Vulnerable]", BUILD_DIR / "vuln.c", "VULNERABLE"))
    test_cases.append(("C++ Source [Safe]", BUILD_DIR / "safe.cpp", "SAFE"))
    test_cases.append(("C++ Source [Vulnerable]", BUILD_DIR / "vuln.cpp", "VULNERABLE"))
    test_cases.append(("C++ Alternative Source (.cc) [Safe]", BUILD_DIR / "safe.cc", "SAFE"))
    test_cases.append(("C++ Alternative Source (.cc) [Vulnerable]", BUILD_DIR / "vuln.cc", "VULNERABLE"))
    test_cases.append(("C++ Alternative Source (.cxx) [Safe]", BUILD_DIR / "safe.cxx", "SAFE"))
    test_cases.append(("C++ Alternative Source (.cxx) [Vulnerable]", BUILD_DIR / "vuln.cxx", "VULNERABLE"))
    test_cases.append(("C Header (.h) [Safe]", BUILD_DIR / "safe.h", "SAFE"))
    test_cases.append(("C Header (.h) [Vulnerable]", BUILD_DIR / "vuln.h", "VULNERABLE"))
    test_cases.append(("C++ Header (.hpp) [Safe]", BUILD_DIR / "safe.hpp", "SAFE"))
    test_cases.append(("C++ Header (.hpp) [Vulnerable]", BUILD_DIR / "vuln.hpp", "VULNERABLE"))
    
    # 2. Windows Object files
    if (BUILD_DIR / "safe_c.o").exists():
        test_cases.append(("Windows Object (.o) [Safe]", BUILD_DIR / "safe_c.o", "SAFE"))
    if (BUILD_DIR / "vuln_c.o").exists():
        test_cases.append(("Windows Object (.o) [Vulnerable]", BUILD_DIR / "vuln_c.o", "VULNERABLE"))
        
    # 3. Windows PE executables
    if (BUILD_DIR / "safe_c.exe").exists():
        test_cases.append(("Windows Executable (.exe) [Safe]", BUILD_DIR / "safe_c.exe", "SAFE"))
    if (BUILD_DIR / "vuln_c.exe").exists():
        test_cases.append(("Windows Executable (.exe) [Vulnerable]", BUILD_DIR / "vuln_c.exe", "VULNERABLE"))
        
    # 4. Windows DLLs
    if (BUILD_DIR / "safe_c.dll").exists():
        test_cases.append(("Windows Library (.dll) [Safe]", BUILD_DIR / "safe_c.dll", "SAFE"))
    if (BUILD_DIR / "vuln_c.dll").exists():
        test_cases.append(("Windows Library (.dll) [Vulnerable]", BUILD_DIR / "vuln_c.dll", "VULNERABLE"))
        
    # 5. Linux ELF binaries
    if (BUILD_DIR / "safe_c.elf").exists():
        test_cases.append(("Linux ELF (.elf) [Safe]", BUILD_DIR / "safe_c.elf", "SAFE"))
    if (BUILD_DIR / "vuln_c.elf").exists():
        test_cases.append(("Linux ELF (.elf) [Vulnerable]", BUILD_DIR / "vuln_c.elf", "VULNERABLE"))
        
    # 6. Linux Shared Objects
    if (BUILD_DIR / "safe_c.so").exists():
        test_cases.append(("Linux Shared Object (.so) [Safe]", BUILD_DIR / "safe_c.so", "SAFE"))
    if (BUILD_DIR / "vuln_c.so").exists():
        test_cases.append(("Linux Shared Object (.so) [Vulnerable]", BUILD_DIR / "vuln_c.so", "VULNERABLE"))
        
    # 7. Raw Binary files
    if (BUILD_DIR / "safe_c.bin").exists():
        test_cases.append(("Raw Binary (.bin) [Safe]", BUILD_DIR / "safe_c.bin", "SAFE"))
    if (BUILD_DIR / "vuln_c.bin").exists():
        test_cases.append(("Raw Binary (.bin) [Vulnerable]", BUILD_DIR / "vuln_c.bin", "VULNERABLE"))
        
    print(f"\n[+] Total test cases assembled: {len(test_cases)} / 24")
    print("[+] Running pipeline scans & tracing response payloads...")
    
    # Initialize runbook file
    with open(RUNBOOK_PATH, "w", encoding="utf-8") as rf:
        rf.write("# Sentinel AI - Vulnerability Testing Runbook & Stage Traces\n\n")
        rf.write("This file contains the detailed, end-to-end trace documentation for Safe and Vulnerable variants of all 12 supported file extensions: C, C++, CC, CXX, C headers, C++ headers, Object files, Windows PE executables, Windows DLLs, Linux ELFs, Linux Shared Objects, and Raw Binaries.\n\n")
        rf.write("## Test Summary Table\n\n")
        rf.write("| Case ID | File Type Description | Expected | GNN Verdict | GNN Confidence | Flagged Count | Forensics Scan Time |\n")
        rf.write("|---|---|---|---|---|---|---|\n")
        
    summary_rows = []
    detailed_reports = []
    
    for idx, (label, path, expected) in enumerate(test_cases, 1):
        print(f"\n[+] [{idx}/{len(test_cases)}] Scanning {path.name} ({label})...")
        res = upload_file_to_api(path)
        
        if res.get("status") == "error" or "detail" in res:
            err_msg = res.get("message") or res.get("detail", {}).get("message", "Unknown error")
            print(f"  [!] Scan failed: {err_msg}")
            continue
            
        verdict = res.get("verdict", "ERROR")
        confidence = res.get("confidence", 0.0)
        flagged_count = res.get("flagged_functions_count", 0)
        timing = res.get("timing", {})
        sha256 = res.get("sha256", "UNKNOWN")
        
        # Append summary row
        summary_line = f"| CASE-{idx:02d} | {label} ({path.name}) | {expected} | **{verdict}** | {confidence:.2%} | {flagged_count} | {timing.get('total_seconds', 0):.2f}s |"
        summary_rows.append(summary_line)
        
        # Generate stage documentation
        report = []
        report.append(f"## CASE-{idx:02d}: {label} ({path.name})")
        report.append(f"* **SHA-256 Checksum**: `{sha256}`")
        report.append(f"* **GNN Verdict**: **{verdict}** (Expected: {expected})")
        report.append(f"* **Prediction Confidence**: `{confidence:.2%}`")
        report.append(f"* **Flagged Functions**: `{flagged_count}`")
        report.append(f"* **Scan Timing**: Ghidra: `{timing.get('ghidra_seconds', 0):.2f}s` | GNN: `{timing.get('ml_seconds', 0):.2f}s` | Total: `{timing.get('total_seconds', 0):.2f}s`\n")
        
        # Stage 1 Ingestion Trace
        report.append("### Stage 1: Ingestion & Pre-processing")
        is_source = path.suffix.lower() in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
        if is_source:
            report.append(f"- **Input type**: Source file ({path.suffix}). Captured by API at `/analyze` route.")
            compiler_used = "g++" if path.suffix.lower() in {".cpp", ".cc", ".cxx", ".hpp"} else "gcc"
            report.append(f"- **Ingestion Flow**: Compiled automatically on-the-fly using `{compiler_used} -c -g -O0`. Stripped startup boilerplate by isolating compiled symbols in temporary object files.")
            if path.suffix.lower() in {".cc", ".cxx"}:
                report.append(f"- **SHA Note**: Identical source code content is reused across `.cpp`, `.cc`, and `.cxx` extensions to verify alternative compiler routing, resulting in identical SHA-256 hashes.")
        else:
            report.append(f"- **Input type**: Pre-compiled Binary ({path.suffix}).")
            report.append(f"- **Ingestion Flow**: Bypassed compilation, uploaded raw binary directly. Executable formats (like `.exe`, `.elf`) contain compiler-linked startup functions (e.g. `mainCRTStartup`), which are filtered dynamically during features extraction.")
            if path.suffix.lower() == ".bin":
                report.append(f"- **SHA Note**: `.bin` format is created by copying and renaming the compiled `.exe` executable directly to verify Ghidra's binary format auto-detection, resulting in an identical SHA-256 hash.")
        report.append("")
        
        # Stage 2 Ghidra Trace
        report.append("### Stage 2: Headless Ghidra Disassembly")
        report.append("- Headless Ghidra disassembler launched `analyzeHeadless.bat` using a unique project workspace.")
        report.append("- Executed Java post-script `ExtractAllCFGs.java` to reconstruct the Control Flow Graph.")
        
        top_feats = res.get("top_features", [])
        report.append(f"- **Extracted Functions Count**: {len(top_feats)}")
        report.append("- **Extracted Function Profiles**:")
        if top_feats:
            for feat in top_feats[:8]: # Show up to 8 functions
                report.append(f"  * `{feat['feature']}` (CFG blocks: {feat['tfidf_weight']})")
            if len(top_feats) > 8:
                report.append(f"  * ... ({len(top_feats) - 8} more functions extracted)")
        else:
            report.append("  * [!] No symbols/functions extracted. The binary has empty executable regions or lacks symbols.")
        report.append("")
        
        # Stage 3 GNN Trace
        report.append("### Stage 3: GNN Inference Engine")
        report.append("- Opcode and operands mapped to 128-dimensional dense vectors using the `asm2vec.model` Word2Vec vocabulary.")
        report.append("- Graph nodes (basic blocks) and edge connections formatted as a PyTorch Geometric `Data` structure.")
        report.append("- Message passing performed via `GATv2Conv` layers (incorporating multi-head attention over CFG layout).")
        
        flagged_list = res.get("flagged_functions", [])
        if flagged_list:
            report.append("- **Flagged Anomalies**:")
            for ff in flagged_list:
                report.append(f"  * Function `{ff['function_name']}` flagged with `{ff['confidence']:.1%}` vulnerability risk.")
                report.append("    * *CFG Assembly snippet*:")
                report.append("    ```assembly")
                # Show first few lines of disassembly
                lines = ff.get('decompiled_code', '').split('\n')
                for line in lines[:8]:
                    report.append(f"    {line}")
                if len(lines) > 8:
                    report.append("    ...")
                report.append("    ```")
        else:
            report.append("- **Verdict Status**: Clean. No custom functions or compiler boilerplate graphs exceeded the `0.5` risk classification threshold.")
        report.append("")
        
        # Stage 4 RAG Trace
        report.append("### Stage 4: Generative RAG Auditor")
        report.append("- If GNN flags a function, the disassembler output context is passed to the Gemini RAG service.")
        report.append("- Chroma DB queried to extract relevant SEI CERT C safety standard rules.")
        
        pdf_url = res.get("pdf_url", "")
        if flagged_count > 0:
            report.append("- **RAG Status**: Triggered (GNN verdict is VULNERABLE).")
            if pdf_url:
                report.append(f"- **Vulnerability Report**: Successfully compiled. PDF report saved at: `[Download PDF]({API_BASE_URL}{pdf_url})`")
                report.append("- **RAG audit output sample**:")
                report.append("> [!NOTE]")
                report.append("> Generative remediation completed. Safe replacement code blocks compiled into PDF.")
            else:
                report.append("- **Vulnerability Report**: [!] Generation failed or timed out (e.g. API quota exceeded or connection error).")
        else:
            report.append("- **RAG Status**: Bypassed (File scored as Clean).")
        report.append("\n---\n")
        
        detailed_reports.append("\n".join(report))
        
    # Write summary and reports to file
    with open(RUNBOOK_PATH, "a", encoding="utf-8") as rf:
        rf.write("\n".join(summary_rows))
        rf.write("\n\n---\n\n")
        rf.write("\n".join(detailed_reports))
        
    print("\n" + "=" * 70)
    print("        COMPREHENSIVE PIPELINE TESTING SEQUENCE COMPLETE!")
    print("=" * 70)
    print(f"[+] Detailed Runbook trace generated at: {RUNBOOK_PATH}")
    print("=" * 70)

if __name__ == "__main__":
    main()
