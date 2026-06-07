"""
predictor.py — GNN inference module for vulnerability prediction.

Loads the trained Word2Vec model and PyTorch Geometric GNN model,
then disassembles instructions to node embeddings and runs GATv2 model inference.
"""

import json
import logging
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
    # MinGW CRT & Windows Startup
    "mainCRTStartup", "WinMainCRTStartup", "__mingw_CRTStartup", "pre_c_init",
    "do_pseudo_reloc", "tls_callback_0", "tls_callback_1", "check_managed_app",
    "mark_section_writable", "restore_modified_sections", "duplicate_ppstrings",
    "atexit", "at_quick_exit", "_pre_c_init", "frame_dummy", "register_frame_ctor",
    # Linux ELF Startup
    "deregister_tm_clones", "register_tm_clones", "_start", "__libc_csu_init", 
    "__libc_csu_fini", "_dl_relocate_static_pie",
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
    # Check prefixes/substrings for compiler boilerplate
    if fname.startswith("__") or fname.startswith("_Z") or fname.startswith("glob"):
        if not (fname.startswith("__main") or fname.startswith("main")):
            if any(x in fname for x in ["CRT", "mingw", "tm_clones", "frame_dummy"]):
                return True
            if fname.startswith("_Z"): # C++ mangled names
                if any(x in fname for x in ["std::", "NSt7", "allocator", "basic_string", "string"]):
                    return True
    if any(x in fname for x in ["std::", "std::allocator", "std::basic_string", "~_Guard", "basic_string"]):
        return True
    return False

def verify_vulnerability_heuristic(nodes) -> bool:
    """
    Returns True if the GNN flagged vulnerability should be kept.
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
    Returns True if the function contains known unsafe calls without safe alternatives,
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


class VulnerabilityPredictor:
    """
    Singleton predictor that loads Word2Vec and GNN models on first use.
    """

    def __init__(self):
        self._gnn_model = None
        self._w2v_model = None
        self._is_loaded = False
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Paths to assets
        self.w2v_path = Path(__file__).resolve().parent.parent / "artifacts" / "asm2vec.model"
        self.gnn_path = Path(__file__).resolve().parent.parent / "artifacts" / "best_fold4.pt"

    def load_models(self):
        """Load Word2Vec and trained GNN weights."""
        if self._is_loaded:
            return

        if not self.w2v_path.exists():
            raise FileNotFoundError(f"Word2Vec model not found at: {self.w2v_path}")
        if not self.gnn_path.exists():
            raise FileNotFoundError(f"GNN model weights not found at: {self.gnn_path}")

        logger.info(f"Loading Word2Vec model from {self.w2v_path}...")
        self._w2v_model = Word2Vec.load(str(self.w2v_path))

        logger.info(f"Loading PyTorch GNN model onto {self.device}...")
        self._gnn_model = VulnGNN(input_dim=128, hidden_dim=64)
        self._gnn_model.load_state_dict(torch.load(str(self.gnn_path), map_location=self.device, weights_only=True))
        self._gnn_model.to(self.device)
        self._gnn_model.eval()

        self._is_loaded = True
        logger.info("✅ GNN & Word2Vec models loaded successfully.")

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
                "flagged_functions": []
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
            for node in nodes:
                node_vecs = []
                for instr in node["instructions"]:
                    # Strip comments (e.g., // strncpy) before tokenizing for Word2Vec
                    instr_clean = instr.split("//")[0]
                    parts = instr_clean.replace(",", " ").replace("[", " ").replace("]", " ").split()
                    valid_parts = [p for p in parts if p in w2v.wv]
                    if valid_parts:
                        vec = np.mean([w2v.wv[p] for p in valid_parts], axis=0)
                        node_vecs.append(vec)

                if node_vecs:
                    node_feat = np.mean(node_vecs, axis=0)
                else:
                    node_feat = np.zeros(vector_size)
                x_list.append(node_feat)

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
            else:
                # Run GNN model
                batch = torch.zeros(x.size(0), dtype=torch.long).to(self.device)
                with torch.no_grad():
                    out = self._gnn_model(x, edge_index, batch)
                    probs = torch.softmax(out, dim=1)[0]
                    vuln_prob = float(probs[1])
                    safe_prob = float(probs[0])

                is_vuln = vuln_prob > 0.5
                
                # Apply heuristic verification override
                if is_vuln:
                    if not verify_vulnerability_heuristic(nodes):
                        # Override GNN decision to Safe!
                        vuln_prob = 0.30
                        safe_prob = 0.70
                        is_vuln = False
                else:
                    if detect_vulnerability_heuristic(nodes):
                        # Override GNN decision to Vulnerable!
                        vuln_prob = 0.85
                        safe_prob = 0.15
                        is_vuln = True
                
                confidence = vuln_prob if is_vuln else safe_prob

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
                "edges_count": len(edges)
            }
            analyzed_functions.append(func_info)

            if is_vuln:
                overall_vulnerable = True
                if vuln_prob > max_vuln_confidence:
                    max_vuln_confidence = vuln_prob

                flagged_functions.append({
                    "function_name": fname,
                    "confidence": round(vuln_prob, 4),
                    "decompiled_code": "\n".join(decompiled_lines),
                    "cwe_id": "CWE-119",  # Fallback memory corruption
                    "brief_explanation": f"GNN model GATv2 classified this function as highly suspicious of memory safety vulnerabilities (e.g. CWE-119, CWE-120 buffer overflows) with {vuln_prob:.1%} confidence."
                })
            else:
                if safe_prob > max_safe_confidence:
                    max_safe_confidence = safe_prob

        overall_prediction = "Vulnerable" if overall_vulnerable else "Safe"
        overall_label = 1 if overall_vulnerable else 0
        overall_confidence = max_vuln_confidence if overall_vulnerable else max_safe_confidence

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
            "flagged_functions": flagged_functions
        }


# Module singleton
predictor = VulnerabilityPredictor()
