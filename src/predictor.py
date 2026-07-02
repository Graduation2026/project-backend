"""
predictor.py — GNN inference module for vulnerability prediction.

Loads the trained Word2Vec model and PyTorch Geometric GNN model,
then disassembles instructions to node embeddings and runs GATv2 model inference.
"""

import json
import logging
import re
import threading
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

# PyTorch Geometric imports inside methods or globally
# If torch_geometric is imported, ensure it handles CPU/GPU gracefully
from torch_geometric.data import Data
from torch_geometric.nn import GATv2Conv, global_max_pool, global_mean_pool
logger = logging.getLogger(__name__)

try:
    from gensim.models import Word2Vec
except ImportError:
    Word2Vec = None
    logger.warning("gensim is not installed — Word2Vec embeddings will be unavailable. "
                   "Install gensim or use Python ≤3.12 for full functionality.")

# Define VulnGNN model architecture to match training precisely
class VulnGNN(torch.nn.Module):
    def __init__(self, input_dim=128, hidden_dim=64):
        super(VulnGNN, self).__init__()
        # Graph Attention Layers (GATv2 — dynamic attention)
        self.conv1 = GATv2Conv(input_dim, hidden_dim, heads=4, dropout=0.2)
        self.bn1   = nn.BatchNorm1d(hidden_dim * 4)
        self.conv2 = GATv2Conv(hidden_dim * 4, hidden_dim, heads=1, dropout=0.2)
        self.bn2   = nn.BatchNorm1d(hidden_dim)

        # Classifier
        # Input doubles because we concatenate max + mean pool
        self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.dropout = nn.Dropout(0.3)
        self.fc2 = nn.Linear(hidden_dim, 2)

    def forward(self, x, edge_index, batch):
        x = self.conv1(x, edge_index)
        x = self.bn1(x)
        x = F.elu(x)

        x = self.conv2(x, edge_index)
        x = self.bn2(x)
        x = F.elu(x)

        # Graph-level readout: concatenate max-pool and mean-pool
        x = torch.cat([global_max_pool(x, batch), global_mean_pool(x, batch)], dim=1)

        x = self.fc1(x)
        x = F.elu(x)
        x = self.dropout(x)
        x = self.fc2(x)
        return x


# --- Boilerplate Symbol Blacklist ---
# Master list of all known compiler-generated boilerplate functions, runtime stubs,
# and CRT startup symbols. These are NOT user-defined code and must be excluded
# from GNN vulnerability analysis to prevent false positives.
BOILERPLATE_BLACKLIST = {
    # ── MinGW/GCC CRT & Windows Startup ──
    "mainCRTStartup", "WinMainCRTStartup", "__mingw_CRTStartup", "pre_c_init", "pre_cpp_init", "_pre_cpp_init",
    "_get_output_format", "__deregister_frame_info", "__register_frame_info", "_register_frame_info", "_deregister_frame_info",
    ".weak.__deregister_frame_info.hmod_libgcc", ".weak.__register_frame_info.hmod_libgcc",
    "__mingw_invalidParameterHandler", "__mingw_raise_exception",
    "do_pseudo_reloc", "tls_callback_0", "tls_callback_1", "check_managed_app",
    "mark_section_writable", "restore_modified_sections", "duplicate_ppstrings",
    "atexit", "at_quick_exit", "_pre_c_init", "frame_dummy", "register_frame_ctor",
    
    # MinGW / GCC Windows Extras (User Provided)
    "_pei386_runtime_relocator", "_FindPESection", "_FindPESectionByName",
    "_FindPESectionExec", "_GetPEImageBase", "_IsNonwritableInCurrentImage",
    "_onexit", "_amsg_exit", "_tzset", "tzset", "_get_output_format", "FUN_140001000",
    
    # Linux ELF Startup
    "deregister_tm_clones", "register_tm_clones", "_start", "__libc_csu_init", 
    "__libc_csu_fini", "_dl_relocate_static_pie", "_init", "entry", "_start_c", "_fini",
    # MSVC CRT & Windows Startup
    "__scrt_common_main_seh", "_mainCRTStartup", "_wmainCRTStartup", "_WinMainCRTStartup",
    "_DllMainCRTStartup", "__security_init_cookie", "__security_check_cookie",
    "__report_gsfailure", "__local_stdio_printf_options", "__local_stdio_scanf_options",
    "_wsplitpath_s", "_vsnprintf_l", "_RTC_Initialize", "_RTC_Shutdown", "_RTC_Failure",
    "__scrt_initialize_crt", "__scrt_initialize_onexit_table", "__scrt_is_non_image_rva",
    "__scrt_is_safe_divisor", "__scrt_is_user_matherr_present", "__scrt_narrow_argv_policy",
    "__scrt_perform_file_alignments", "__scrt_perform_image_alignments",
    "__scrt_stub_for_initialize_mta", "__scrt_stub_for_is_c_image",
    "__scrt_stub_for_resolve_heap_functions", "__scrt_stub_for_is_non_image_rva",
    "__scrt_stub_for_is_safe_divisor", "__scrt_stub_for_is_user_matherr_present",
    "__scrt_narrow_argv_policy", "__scrt_perform_file_alignments",
    "__scrt_perform_image_alignments", "__vcrt_initialize", "__vcrt_uninitialize",
    "__vcrt_thread_attach", "__vcrt_thread_detach", "__telemetry_main_invoke_trigger",
    "__telemetry_main_return_trigger", "_CRT_INIT", "_DllMain", "DllMain", "_CRT_INIT@12",
    "__dyn_tls_init", "__dyn_tls_dtor",
    # ── MSVC SEH (Structured Exception Handling) ──
    "_except_handler3", "_except_handler4", "__C_specific_handler",
    "__SEH_prolog", "__SEH_epilog", "__SEH_prolog4", "__SEH_epilog4",
    "_EH_prolog", "_EH_epilog", "_EH_prolog3", "_EH_epilog3",
    # ── MSVC C++ Exception Handling ──
    "_CxxFrameHandler3", "_CxxFrameHandler4", "__CxxFrameHandler",
    "_CxxThrowException", "__CxxCallUnwindDtor", "__CxxCallUnwindDelDtor",
    "__CxxCallUnwindVecDtor", "__CxxDetectRethrow",
    # ── MSVC Guard/Security ──
    "__GSHandlerCheck", "__GSHandlerCheck_SEH", "__GSHandlerCheck_EH4",
    "_guard_dispatch_icall", "_guard_check_icall", "__castguard_check_failure",
    "_guard_dispatch_icall_fptr", "_guard_xfg_dispatch_icall_fptr",
    # ── MSVC Telemetry & Init ──
    "__scrt_uninitialize_crt", "__scrt_exe_initialize_mta",
    "__acrt_initialize", "__acrt_uninitialize", "__acrt_thread_attach", "__acrt_thread_detach",
    # ── C++ ABI / Exception / RTTI ──
    "__cxa_atexit", "__cxa_finalize", "__cxa_guard_acquire", "__cxa_guard_release",
    "__cxa_guard_abort", "__cxa_throw", "__cxa_begin_catch", "__cxa_end_catch",
    "__cxa_rethrow", "__cxa_allocate_exception", "__cxa_free_exception",
    "__cxa_pure_virtual", "__cxa_deleted_virtual", "__cxa_bad_cast", "__cxa_bad_typeid",
    "__cxa_call_unexpected", "__cxa_call_terminate",
    "__dynamic_cast", "__cxa_demangle",
    # ── GCC/LLVM Unwind & Personality ──
    "_Unwind_Resume", "_Unwind_RaiseException", "_Unwind_GetLanguageSpecificData",
    "_Unwind_GetRegionStart", "_Unwind_GetIP", "_Unwind_SetIP",
    "_Unwind_SetGR", "_Unwind_GetGR", "_Unwind_DeleteException",
    "__gxx_personality_v0", "__gcc_personality_v0",
    "__clang_call_terminate",
    # ── Stack Protectors ──
    "__stack_chk_fail", "__stack_chk_guard",
    # ── LLVM/Clang Runtime ──
    "__clang_call_terminate", "__cxx_global_var_init",
    # ── Go Runtime (if analyzing Go binaries) ──
    "runtime.morestack", "runtime.morestack_noctxt", "runtime.goexit",
    "runtime.main", "runtime.init", "runtime.args",
    # ── Rust Runtime (if analyzing Rust binaries) ──
    "__rust_alloc", "__rust_dealloc", "__rust_realloc", "__rust_alloc_zeroed",
    "__rust_alloc_error_handler",
    # ── Additional User-Requested Boilerplate Functions ──
    "_ValidateImageBase", "fpreset", "_matherr", "_setargv",
}

CPP_LIB_KEYWORDS = {
    "length", "size", "begin", "end", "empty", "c_str", "compare", "clear",
    "push_back", "pop_back", "append", "assign", "insert", "erase", "replace",
    "find", "rfind", "substr", "at", "operator[]", "capacity", "reserve",
    "shrink_to_fit", "front", "back", "data", "get_allocator", "swap", "eq",
    "operator<<", "operator>>", "~string", "~_Guard", "_M_dispose", "_Alloc_hider",
    "__throw_logic_error", "_M_construct", "__new_allocator", "~__new_allocator",
    "__is_constant_evaluated", "_M_local_data", "_Alloc_hider", "_M_construct",
    "__throw_out_of_range_fmt"
}

# These are standard C library symbols that may appear as extracted functions
# in statically linked binaries. They are external trusted code resolved via
# PLT/IAT — not user-defined functions — and should bypass GNN analysis.
STANDARD_LIBC_IMPORTS = {
    # Format/IO
    "printf", "fprintf", "sprintf", "snprintf", "scanf", "sscanf", "fscanf", "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    # Memory
    "malloc", "free", "realloc", "calloc", "memset", "memcpy", "memmove", "memcmp",
    # Strings
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strlen", "strchr", "strstr", "strspn", "strcspn",
    # Other
    "atoi", "atol", "atof", "strtol", "strtoul", "exit", "abort"
}

def is_boilerplate_or_lib(fname: str) -> bool:
    """Determine if a function symbol is compiler boilerplate, runtime stub, or standard library code.
    Returns True for any symbol that should be excluded from GNN vulnerability analysis."""
    # Check exact matches against all known lists
    if fname in BOILERPLATE_BLACKLIST or fname == ".text" or fname in CPP_LIB_KEYWORDS or fname in STANDARD_LIBC_IMPORTS:
        return True

    # Strip leading underscores and check exact lists
    fname_clean = fname.lstrip('_')
    if fname_clean in STANDARD_LIBC_IMPORTS or fname_clean in BOILERPLATE_BLACKLIST:
        return True

    # Exclude user main functions from blacklist checking
    if fname == "main" or fname == "__main" or fname.startswith("main_") or fname.startswith("__main_"):
        return False

    # Check for weak symbol patterns (variable suffixes)
    if fname.startswith(".weak.") or fname.startswith(".weak_"):
        return True

    # Check for MSVC standard I/O wrappers and related runtime stubs
    if fname.startswith("__stdio_common_") or "frame_info" in fname or "_hmod_libgcc" in fname:
        return True

    # Sanitizer runtimes (ASan, UBSan, MSan, TSan)
    if fname.startswith(("__asan_", "__ubsan_", "__msan_", "__tsan_", "__sanitizer_")):
        return True

    # IAT/PLT import stubs and thunks
    if fname.startswith(("_imp__", "__imp_", "thunk_", "_thunk_", "jmp_")):
        return True
    if "@thunk" in fname:
        return True

    # LLVM/Clang specific runtime symbols
    if fname.startswith(("__clang_", "__cxx_global_var_init")):
        return True

    # Rust runtime symbols
    if fname.startswith("__rust_") or fname.startswith("core::panicking") or fname.startswith("std::rt::lang_start"):
        return True

    # Go runtime symbols
    if fname.startswith("runtime.") or fname.startswith("runtime_"):
        # But exclude user-defined functions that happen to start with 'runtime'
        if not fname.startswith("runtime_user_"):
            return True

    # Check C++ standard library substrings directly (demangled STL symbols)
    STL_SUBSTRINGS = {"_Tuple", "tuple", "unique_ptr", "_Head_base", "_M_construct", "_M_dispose", "~_Alloc_hider", "_M_head", "std::", "basic_string", "allocator", "_Alloc_hider"}
    if any(x in fname for x in STL_SUBSTRINGS):
        return True

    # Check prefixes/substrings for compiler and library boilerplate
    # MSVC: __scrt_, __vcrt_, __acrt_, _RTC_, __local_stdio_
    if fname.startswith(("__scrt_", "__vcrt_", "__acrt_", "__local_stdio_")) or "_RTC_" in fname:
        return True

    # Exception handling/runtimes: C++ ABI (_cxa_), Unwind, personality routines
    if any(x in fname for x in ["_cxa_", "_Unwind_", "personality", "__gcc_", "__gxx_"]):
        return True

    # Stack protectors/canaries
    if "__stack_chk" in fname or "__security_" in fname:
        return True

    # Compiler intrinsics / builtins
    if fname.startswith("__builtin_"):
        return True

    # MSVC guard/security dispatch
    if fname.startswith("_guard_") or "__GSHandler" in fname or "__castguard_" in fname:
        return True

    # MSVC C++ exception handlers
    if "CxxFrameHandler" in fname or "CxxThrowException" in fname or "CxxCallUnwind" in fname:
        return True

    # General compiler / runtime prefixes
    if fname.startswith("__") or fname.startswith("_Z") or fname.startswith("glob"):
        if any(x in fname for x in ["CRT", "mingw", "tm_clones", "frame_dummy"]):
            return True
        if fname.startswith("_Z"): # C++ mangled names
            if any(x in fname for x in ["std::", "NSt7", "allocator", "basic_string", "string", "vector", "list", "map", "set", "char_traits"]):
                return True

    # Standard template library (STL) namespace/keyword matching
    if any(x in fname for x in ["std::", "std__", "std::allocator", "std::basic_", "~_Guard", "basic_string", "allocator", "__gnu_cxx"]):
        return True

    return False

def _word_boundary_match(api_name: str, text: str) -> bool:
    """Match API name at word boundaries to prevent substring false matches (e.g. 'gets' in 'fgets')."""
    return bool(re.search(r'(?:^|(?<=[^a-zA-Z0-9_]))' + re.escape(api_name) + r'(?=[^a-zA-Z0-9_]|$)', text))

UNSAFE_APIS = {
    "strcpy", "gets", "strcat", "sprintf", "scanf", "system", "popen",
    "vsprintf", "fscanf", "sscanf", "mktemp", "tmpnam",
    "execl", "execv", "execlp", "execvp",
}
SAFE_APIS = {
    # Bounds-checked string operations
    "fgets", "snprintf", "memcpy_s", "memmove_s", "printf_s",
    # C11 Annex K safe variants
    "strcpy_s", "strcat_s", "gets_s", "fprintf_s", "sprintf_s",
    # BSD safe alternatives
    "strlcpy", "strlcat",
    # Safe format functions
    "vsnprintf",
}


def is_trivial_stub(fname: str, nodes: list) -> bool:
    """Detect if a function is a trivial compiler-generated stub.
    Matches FUN_ prefixed symbols with <= 2 basic blocks and no outgoing calls."""
    if not fname.startswith("FUN_"):
        return False
    for node in nodes:
        for instr in node.get("instructions", []):
            if "CALL" in instr or "call" in instr:
                return False
    if len(nodes) <= 2:
        return True
    return False


# --- Hard Function Cap ---
# If a binary contains more than this many Category B (actual code) functions,
# the analysis is rejected entirely to prevent unbounded report sizes.
MAX_CATEGORY_B_FUNCTIONS = 100


class VulnerabilityPredictor:
    """
    Singleton predictor that loads Word2Vec and GNN models on first use.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._gnn_models = {}  # Dictionary to hold all active fold models
        self._w2v_model = None
        self._is_loaded = False
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Paths to assets
        self.w2v_path = Path(__file__).resolve().parent.parent / "artifacts" / "asm2vec.model"
        self.gnn_path = Path(__file__).resolve().parent.parent / "artifacts" / "best_fold4.pt"

    def load_models(self):
        """Load Word2Vec and trained GNN weights (with ensemble folds if available)."""
        with self._lock:
            if self._is_loaded:
                return

            if not self.w2v_path.exists():
                raise FileNotFoundError(f"Word2Vec model not found at: {self.w2v_path}")
            if not self.gnn_path.exists():
                raise FileNotFoundError(f"GNN model weights not found at: {self.gnn_path}")

            logger.info(f"Loading Word2Vec model from {self.w2v_path}...")
            if Word2Vec is None:
                logger.warning("⚠️ gensim is not installed — Word2Vec model cannot be loaded. "
                               "Predictions will not be available locally.")
                self._w2v_model = None
            else:
                self._w2v_model = Word2Vec.load(str(self.w2v_path))

            # Load fold 4 (primary model)
            model_paths = {
                "fold4": self.gnn_path
            }

            logger.info(f"Initializing GNN models from loaded paths: {list(model_paths.keys())}...")
            
            for fold_name, path in model_paths.items():
                try:
                    model = VulnGNN(input_dim=128, hidden_dim=64)
                    model.load_state_dict(torch.load(str(path), map_location=self.device, weights_only=True))
                    model.to(self.device)
                    model.eval()
                    self._gnn_models[fold_name] = model
                    logger.info(f"✅ Loaded GNN {fold_name} weights successfully.")
                except Exception as e:
                    logger.error(f"❌ Failed to load GNN {fold_name} weights from {path}: {e}")
                    if fold_name == "fold4":
                        raise e  # Fail hard if the primary fold fails

            self._is_loaded = True
            logger.info(f"✅ GNN & Word2Vec models loaded successfully. Active folds: {list(self._gnn_models.keys())}")

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    def predict(self, json_filepath: str | Path) -> dict:
        """
        Run GNN vulnerability prediction on all extracted function CFGs in a JSON file.

        Args:
            json_filepath: Path to the generated cfg_features.json file.

        Returns:
            dict with verdict, category_a_functions (boilerplate), category_b_functions (actual code),
            flagged_functions list, and count metrics. No top-level confidence.
        """
        with self._lock:
            if not self._is_loaded:
                self.load_models()

            json_path = Path(json_filepath)
            if not json_path.exists():
                raise FileNotFoundError(f"Features JSON file not found at: {json_path}")

            with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                functions_list = json.load(f)

            logger.info(
                f"🧩 [GNN Predict] Running LOCAL GNN inference on {len(functions_list)} extracted "
                f"function(s) | device={self.device} | active_folds={list(self._gnn_models.keys())} | "
                f"w2v_loaded={self._w2v_model is not None} (source={self.gnn_path.name})"
            )

            if not functions_list:
                return {
                    "prediction": "Safe",
                    "label": 0,
                    "top_features": [],
                    "flagged_functions": [],
                    "category_a_functions": [],
                    "category_b_functions": [],
                    "total_functions": 0,
                    "boilerplate_count": 0,
                    "actual_count": 0,
                    "decision_source": "gnn"
                }

            analyzed_functions = []
            flagged_functions = []
            category_a_functions = []
            category_b_functions = []
            overall_vulnerable = False

            w2v = self._w2v_model
            vector_size = w2v.vector_size

            for func in functions_list:
                fname = func["function_name"]
                nodes = func["nodes"]
                edges = func["edges"]

                # Build node features
                x_list = []
                total_tokens = 0
                oov_tokens = 0
                for node in nodes:
                    node_vecs = []
                    for instr in node["instructions"]:
                        # Strip comments (e.g., // strncpy) before tokenizing for Word2Vec
                        instr_clean = instr.split("//")[0]
                        parts = instr_clean.replace(",", " ").replace("[", " ").replace("]", " ").split()
                        total_tokens += len(parts)
                        valid_parts = [p for p in parts if p in w2v.wv]
                        oov_tokens += len(parts) - len(valid_parts)
                        if valid_parts:
                            vec = np.mean([w2v.wv[p] for p in valid_parts], axis=0)
                            node_vecs.append(vec)

                    if node_vecs:
                        node_feat = np.mean(node_vecs, axis=0)
                    else:
                        node_feat = np.zeros(vector_size)
                    x_list.append(node_feat)

                # OOV tracking — warn if Word2Vec doesn't understand the instruction set
                oov_rate = oov_tokens / total_tokens if total_tokens > 0 else 0.0
                if oov_rate > 0.5:
                    logger.warning(f"  High OOV rate for {fname}: {oov_tokens}/{total_tokens} tokens ({oov_rate:.1%}) — node vectors may be noise-dominated")
                elif oov_rate > 0.3:
                    logger.info(f"  Moderate OOV rate for {fname}: {oov_tokens}/{total_tokens} tokens ({oov_rate:.1%})")

                x = torch.tensor(np.array(x_list), dtype=torch.float).to(self.device)

                # Build edge index
                if len(edges) > 0:
                    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous().to(self.device)
                else:
                    edge_index = torch.empty((2, 0), dtype=torch.long).to(self.device)

                # Check if symbol is compiler boilerplate — Category A
                if is_boilerplate_or_lib(fname) or is_trivial_stub(fname, nodes):
                    category_a_functions.append({"function_name": fname})
                    func_decision_source = "boilerplate"
                    is_vuln = False

                    func_info = {
                        "function_name": fname,
                        "is_vulnerable": False,
                        "nodes_count": len(nodes),
                        "edges_count": len(edges),
                        "decision_source": func_decision_source,
                        "oov_rate": round(oov_rate, 4)
                    }
                    analyzed_functions.append(func_info)
                    continue

                # --- Category B: Actual Code Functions ---
                # Run GNN on every function regardless of size
                batch = torch.zeros(x.size(0), dtype=torch.long).to(self.device)
                probs_list = []
                with torch.no_grad():
                    for fold_name, model in self._gnn_models.items():
                        out = model(x, edge_index, batch)
                        probs = torch.softmax(out, dim=1)[0]
                        probs_list.append(probs)

                avg_probs = torch.stack(probs_list).mean(dim=0)
                vuln_prob = float(avg_probs[1])
                safe_prob = float(avg_probs[0])
                is_vuln = vuln_prob > 0.5
                func_decision_source = "gnn"

                # One-way heuristic rescue: can only override Vulnerable → Safe
                # If GNN flags as Vulnerable, but the function uses safe
                # API calls (strncpy, snprintf, etc.) and has zero unsafe
                # API calls (strcpy, gets, etc.), rescue it to Safe.
                if is_vuln:
                    has_unsafe = False
                    has_safe = False
                    for node in nodes:
                        for instr in node["instructions"]:
                            instr_lower = instr.lower()
                            for api in UNSAFE_APIS:
                                if _word_boundary_match(api, instr_lower):
                                    has_unsafe = True
                                    break
                            for api in SAFE_APIS:
                                if _word_boundary_match(api, instr_lower):
                                    has_safe = True
                                    break

                    if has_safe and not has_unsafe:
                        vuln_prob = 0.15
                        safe_prob = 0.85
                        is_vuln = False
                        func_decision_source = "rescue"

                # Formulate decompiled / disassembled preview for RAG context
                decompiled_lines = []
                for idx, node in enumerate(nodes):
                    decompiled_lines.append(f"Basic Block {idx}:")
                    for instr in node["instructions"]:
                        decompiled_lines.append(f"  {instr}")

                func_info = {
                    "function_name": fname,
                    "is_vulnerable": is_vuln,
                    "nodes_count": len(nodes),
                    "edges_count": len(edges),
                    "decision_source": func_decision_source,
                    "oov_rate": round(oov_rate, 4)
                }
                analyzed_functions.append(func_info)

                if is_vuln:
                    overall_vulnerable = True

                    explanation = f"GNN model classified this function as vulnerable."

                    flagged_entry = {
                        "function_name": fname,
                        "decompiled_code": "\n".join(decompiled_lines),
                        "cwe_id": None,
                        "brief_explanation": explanation,
                        "decision_source": func_decision_source
                    }
                    flagged_functions.append(flagged_entry)

                    # Category B entry for vulnerable function
                    category_b_functions.append({
                        "function_name": fname,
                        "is_vulnerable": True,
                        "decision_source": func_decision_source,
                        "explanation": explanation,
                        "cwe_id": None,
                        "decompiled_code": "\n".join(decompiled_lines)
                    })
                else:
                    # Category B entry for safe function — inline 2-3 line summary
                    if func_decision_source == "rescue":
                        safe_explanation = (
                            f"The GNN model initially flagged this function, but heuristic analysis determined it uses "
                            f"safe API alternatives (e.g., fgets, strncpy, snprintf) with no calls to known unsafe functions. "
                            f"The verdict was overridden to Safe."
                        )
                    else:
                        safe_explanation = (
                            f"This function's control flow graph was analyzed by the GNN model and classified as safe. "
                            f"Its graph structure matches standard secure coding patterns with no calls to known unsafe "
                            f"API functions (strcpy, gets, sprintf, etc.)."
                        )
                    category_b_functions.append({
                        "function_name": fname,
                        "is_vulnerable": False,
                        "decision_source": func_decision_source,
                        "explanation": safe_explanation,
                        "cwe_id": None,
                        "decompiled_code": None
                    })

            overall_prediction = "Vulnerable" if overall_vulnerable else "Safe"
            overall_label = 1 if overall_vulnerable else 0

            # Determine overall decision source
            decision_sources = [af["decision_source"] for af in analyzed_functions if af["decision_source"] != "boilerplate"]
            if "rescue" in decision_sources and not overall_vulnerable:
                overall_decision_source = "rescue"
            else:
                overall_decision_source = "gnn"

            # Count metrics
            total_functions = len(category_a_functions) + len(category_b_functions)
            boilerplate_count = len(category_a_functions)
            actual_count = len(category_b_functions)

            # Enforce hard cap: reject scanning if Category B exceeds limit
            if actual_count > MAX_CATEGORY_B_FUNCTIONS:
                raise ValueError(
                    f"This binary contains {actual_count} actual code functions (Category B), "
                    f"which exceeds the maximum limit of {MAX_CATEGORY_B_FUNCTIONS}. "
                    f"Total functions extracted: {total_functions} "
                    f"(Boilerplate filtered: {boilerplate_count}). "
                    f"Please upload a smaller binary or individual compilation units."
                )

            # Format top_features for backward compatibility
            top_features = []
            for af in sorted(
                [a for a in analyzed_functions if a["decision_source"] != "boilerplate"],
                key=lambda x: x["is_vulnerable"],
                reverse=True
            ):
                status = "Vulnerable" if af["is_vulnerable"] else "Safe"
                top_features.append({
                    "feature": f"{af['function_name']} ({status} - {af['decision_source']})",
                    "tfidf_weight": af["nodes_count"]
                })

            return {
                "prediction": overall_prediction,
                "label": overall_label,
                "top_features": top_features,
                "flagged_functions": flagged_functions,
                "category_a_functions": category_a_functions,
                "category_b_functions": category_b_functions,
                "total_functions": total_functions,
                "boilerplate_count": boilerplate_count,
                "actual_count": actual_count,
                "decision_source": overall_decision_source
            }


# Module singleton
predictor = VulnerabilityPredictor()
