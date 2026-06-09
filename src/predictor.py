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
from gensim.models import Word2Vec

logger = logging.getLogger(__name__)

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
BOILERPLATE_BLACKLIST = {
    # MinGW/GCC CRT & Windows Startup
    "mainCRTStartup", "WinMainCRTStartup", "__mingw_CRTStartup", "pre_c_init",
    "do_pseudo_reloc", "tls_callback_0", "tls_callback_1", "check_managed_app",
    "mark_section_writable", "restore_modified_sections", "duplicate_ppstrings",
    "atexit", "at_quick_exit", "_pre_c_init", "frame_dummy", "register_frame_ctor",
    # Linux ELF Startup
    "deregister_tm_clones", "register_tm_clones", "_start", "__libc_csu_init", 
    "__libc_csu_fini", "_dl_relocate_static_pie",
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
    "__scrt_stub_for_narrow_argv_policy", "__scrt_stub_for_perform_file_alignments",
    "__scrt_stub_for_perform_image_alignments", "__vcrt_initialize", "__vcrt_uninitialize",
    "__vcrt_thread_attach", "__vcrt_thread_detach", "__telemetry_main_invoke_trigger",
    "__telemetry_main_return_trigger", "_CRT_INIT", "_DllMain", "DllMain", "_CRT_INIT@12",
    "__dyn_tls_init", "__dyn_tls_dtor",
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

def is_boilerplate_or_lib(fname: str) -> bool:
    # Check exact matches
    if fname in BOILERPLATE_BLACKLIST or fname == ".text" or fname in CPP_LIB_KEYWORDS:
        return True
    
    # Exclude user main functions from blacklist checking
    if fname.startswith("__main") or fname.startswith("main"):
        return False

    # Check prefixes/substrings for compiler and library boilerplate
    # MSVC: __scrt_, __vcrt_, _RTC_, __local_stdio_
    if fname.startswith("__scrt_") or fname.startswith("__vcrt_") or fname.startswith("__local_stdio_") or "_RTC_" in fname:
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

def verify_vulnerability_heuristic(nodes) -> bool:
    """
    [Deprecated] Returns True if the GNN flagged vulnerability should be kept.
    Returns False if it is a verified safe implementation (e.g. only safe APIs, no unsafe APIs).
    """
    has_unsafe_call = False
    has_safe_call = False
    has_cpp_safe_call = False
    
    for node in nodes:
        for instr in node["instructions"]:
            instr_lower = instr.lower()
            if "call" in instr_lower or "jmp" in instr_lower:
                # Check for unsafe functions
                if any(x in instr_lower for x in ["strcpy", "strcat", "gets", "sprintf", "scanf"]):
                    is_safe_alternative = any(safe_alt in instr_lower for safe_alt in ["strncpy", "strncat", "snprintf", "sprintf_s", "strcpy_s"])
                    if not is_safe_alternative:
                        has_unsafe_call = True
                
                # Check for safe functions
                if any(x in instr_lower for x in ["strncpy", "strncat", "fgets", "snprintf", "memcpy", "memcpy_s", "memmove"]):
                    has_safe_call = True
                    
                # Check for C++ safe standard functions/operators
                if any(x in instr_lower for x in ["std::", "operator<<", "operator>>", "basic_string", "allocator", "length", "substr", "size"]):
                    has_cpp_safe_call = True

    if (has_safe_call or has_cpp_safe_call) and not has_unsafe_call:
        return False # Verified Safe
        
    return True # Keep GNN Verdict

def detect_vulnerability_heuristic(nodes) -> bool:
    """
    [Deprecated] Returns True if the function contains known unsafe calls without safe alternatives,
    indicating it should be classified as Vulnerable regardless of GNN score.
    """
    has_unsafe_call = False
    for node in nodes:
        for instr in node["instructions"]:
            instr_lower = instr.lower()
            if "call" in instr_lower or "jmp" in instr_lower:
                if any(x in instr_lower for x in ["strcpy", "strcat", "gets", "sprintf", "scanf"]):
                    is_safe_alternative = any(safe_alt in instr_lower for safe_alt in ["strncpy", "strncat", "snprintf", "sprintf_s", "strcpy_s"])
                    if not is_safe_alternative:
                        has_unsafe_call = True
    return has_unsafe_call

def _word_boundary_match(api_name: str, text: str) -> bool:
    """Match API name at word boundaries to prevent substring false matches (e.g. 'gets' in 'fgets')."""
    return bool(re.search(r'(?:^|(?<=[^a-zA-Z0-9_]))' + re.escape(api_name) + r'(?=[^a-zA-Z0-9_]|$)', text))

UNSAFE_APIS = ["strcpy", "strcat", "gets", "sprintf", "scanf"]
SAFE_APIS = ["strncpy", "strncat", "fgets", "snprintf", "memcpy", "memcpy_s", "memmove"]
SAFE_CPP_INDICATORS = ["std::", "operator<<", "operator>>", "basic_string", "allocator", "length", "substr", "size"]

# API-to-CWE mapping for dynamic CWE assignment (replaces hardcoded CWE-119)
CWE_MAPPING = {
    "strcpy": "CWE-121", "strcat": "CWE-121", "gets": "CWE-121",
    "sprintf": "CWE-121", "scanf": "CWE-120",
    "memcpy": "CWE-787", "memmove": "CWE-787",
    "printf": "CWE-134",
    "system": "CWE-78", "popen": "CWE-78",
    "free": "CWE-416", "realloc": "CWE-416",
    "malloc": "CWE-190", "calloc": "CWE-190",
}

def detect_cwe_from_code(decompiled_lines: list[str]) -> str:
    """Scan decompiled code for known API calls and return the most specific CWE."""
    text = " ".join(decompiled_lines).lower()
    detected = set()
    for api, cwe in CWE_MAPPING.items():
        if _word_boundary_match(api, text):
            detected.add(cwe)
    return ", ".join(sorted(detected)) if detected else "CWE-119"

def compute_heuristic_delta(nodes) -> float:
    """
    Checks for unsafe or safe API calls in assembly nodes and returns a probability delta:
    +0.35 if unsafe call is found without safe alternatives.
    -0.25 if only safe calls/CPP containers are found and no unsafe calls.
    0.0 otherwise.
    Uses word-boundary matching to prevent false matches (e.g. 'gets' vs 'fgets').
    """
    has_unsafe_call = False
    has_safe_call = False
    
    for node in nodes:
        for instr in node["instructions"]:
            instr_lower = instr.lower()
            if "call" in instr_lower or "jmp" in instr_lower:
                # Check for unsafe API calls using word-boundary matching
                if any(_word_boundary_match(api, instr_lower) for api in UNSAFE_APIS):
                    is_safe_alternative = any(_word_boundary_match(sa, instr_lower) for sa in ["strncpy", "strncat", "snprintf", "sprintf_s", "strcpy_s"])
                    if not is_safe_alternative:
                        has_unsafe_call = True
                
                # Check for safe/hardened APIs
                if any(_word_boundary_match(api, instr_lower) for api in SAFE_APIS):
                    has_safe_call = True
                
                # Check for C++ standard library safe containers/streams
                if any(x in instr_lower for x in SAFE_CPP_INDICATORS):
                    has_safe_call = True

    if has_unsafe_call:
        return 0.35
    elif has_safe_call:
        return -0.25
    return 0.0


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
            self._w2v_model = Word2Vec.load(str(self.w2v_path))

            # Determine folds to load with graceful fallback
            model_paths = {
                "fold4": self.gnn_path  # Fold 4 is always required
            }
            fold0_path = self.gnn_path.parent / "best_fold0.pt"
            fold1_path = self.gnn_path.parent / "best_fold1.pt"
            
            if fold0_path.exists():
                model_paths["fold0"] = fold0_path
            if fold1_path.exists():
                model_paths["fold1"] = fold1_path

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
            dict with verdict, confidence, top_features (list of analyzed functions), and flagged_functions list.
        """
        with self._lock:
            if not self._is_loaded:
                self.load_models()

            json_path = Path(json_filepath)
            if not json_path.exists():
                raise FileNotFoundError(f"Features JSON file not found at: {json_path}")

            with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
                functions_list = json.load(f)

            if not functions_list:
                return {
                "prediction": "Safe",
                "label": 0,
                "confidence": 1.0,
                "top_features": [],
                "flagged_functions": [],
                "decision_source": "gnn"
            }

            analyzed_functions = []
            flagged_functions = []
            overall_vulnerable = False
            max_vuln_confidence = 0.0
            max_safe_confidence = 0.0

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

                # Check if symbol is compiler boilerplate
                if is_boilerplate_or_lib(fname):
                    vuln_prob = 0.0
                    safe_prob = 1.0
                    is_vuln = False
                    confidence = 1.0
                    func_decision_source = "gnn"
                else:
                    # Run ensemble GNN models
                    batch = torch.zeros(x.size(0), dtype=torch.long).to(self.device)
                    probs_list = []
                    with torch.no_grad():
                        for fold_name, model in self._gnn_models.items():
                            out = model(x, edge_index, batch)
                            probs = torch.softmax(out, dim=1)[0]
                            probs_list.append(probs)
                    
                    # Average probabilities across loaded folds
                    avg_probs = torch.stack(probs_list).mean(dim=0)
                    gnn_avg_vuln_prob = float(avg_probs[1])
                    gnn_avg_safe_prob = float(avg_probs[0])

                    # Compute soft heuristic fusion with GNN uncertainty gating
                    heuristic_delta = compute_heuristic_delta(nodes)
                    
                    # GNN Uncertainty: 1.0 when at 0.5 (perfect uncertainty), 0.0 when at 0.0 or 1.0 (perfect certainty)
                    uncertainty = 1.0 - abs(gnn_avg_vuln_prob - 0.5) * 2.0
                    effective_delta = heuristic_delta * uncertainty
                    
                    # Final blended probability (clamped to [0.01, 0.99] to avoid absolute certainty claims)
                    vuln_prob = max(0.01, min(0.99, gnn_avg_vuln_prob + effective_delta))
                    safe_prob = 1.0 - vuln_prob
                    
                    is_vuln = vuln_prob > 0.5
                    confidence = vuln_prob if is_vuln else safe_prob
                    
                    # Decision source tracking: hybrid if delta shifted/nudge was applied significantly (>0.02)
                    func_decision_source = "hybrid" if abs(vuln_prob - gnn_avg_vuln_prob) > 0.02 else "gnn"

                # Formulate decompiled / disassembled preview for RAG context
                decompiled_lines = []
                for idx, node in enumerate(nodes):
                    decompiled_lines.append(f"Basic Block {idx}:")
                    for instr in node["instructions"]:
                        decompiled_lines.append(f"  {instr}")

                func_info = {
                    "function_name": fname,
                    "confidence": round(confidence, 4),
                    "is_vulnerable": is_vuln,
                    "nodes_count": len(nodes),
                    "edges_count": len(edges),
                    "decision_source": func_decision_source,
                    "oov_rate": round(oov_rate, 4)
                }
                analyzed_functions.append(func_info)

                if is_vuln:
                    overall_vulnerable = True
                    if vuln_prob > max_vuln_confidence:
                        max_vuln_confidence = vuln_prob

                    # Dynamic explanation based on active folds
                    num_folds = len(self._gnn_models)
                    if num_folds > 1:
                        folds_list = sorted([k.replace("fold", "") for k in self._gnn_models.keys()])
                        active_folds_str = ",".join(folds_list)
                        explanation = f"Ensemble of {num_folds} GATv2 models (folds {active_folds_str}) with heuristic confidence weighting classified this function as vulnerable with {confidence:.1%} confidence."
                    else:
                        explanation = f"GATv2 GNN model (fold 4) with heuristic confidence weighting classified this function as vulnerable with {confidence:.1%} confidence."

                    flagged_functions.append({
                        "function_name": fname,
                        "confidence": round(vuln_prob, 4),
                        "decompiled_code": "\n".join(decompiled_lines),
                        "cwe_id": detect_cwe_from_code(decompiled_lines),
                        "brief_explanation": explanation,
                        "decision_source": func_decision_source
                    })
                else:
                    if safe_prob > max_safe_confidence:
                        max_safe_confidence = safe_prob

            overall_prediction = "Vulnerable" if overall_vulnerable else "Safe"
            overall_label = 1 if overall_vulnerable else 0
            overall_confidence = max_vuln_confidence if overall_vulnerable else max_safe_confidence

            # Determine overall decision source (hybrid if any flagged function is hybrid)
            overall_decision_source = "gnn"
            if flagged_functions:
                if any(f["decision_source"] == "hybrid" for f in flagged_functions):
                    overall_decision_source = "hybrid"

            # Format top_features to display analyzed functions in the frontend dashboard
            top_features = []
            for af in sorted(analyzed_functions, key=lambda x: x["confidence"], reverse=True):
                status = "Vulnerable" if af["is_vulnerable"] else "Safe"
                top_features.append({
                    "feature": f"{af['function_name']} ({status})",
                    "importance": af["confidence"],
                    "tfidf_weight": af["nodes_count"]
                })

            return {
                "prediction": overall_prediction,
                "label": overall_label,
                "confidence": round(overall_confidence, 4),
                "top_features": top_features,
                "flagged_functions": flagged_functions,
                "decision_source": overall_decision_source
            }


# Module singleton
predictor = VulnerabilityPredictor()
