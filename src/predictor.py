"""
predictor.py — Hybrid GNN + Heuristic Vulnerability Prediction Engine.

Architecture:
  This module implements a confidence-weighted ensemble of two complementary approaches:
  1. GNN (GATv2): Graph Attention Network analyzes Control Flow Graphs (CFGs) extracted
     by Ghidra, learning structural patterns of vulnerable vs safe code.
  2. Heuristic Scorer: Continuous API-call analysis using weighted risk scoring for known
     unsafe/safe function patterns.

  The ensemble dynamically adjusts weights based on GNN confidence:
  - When GNN is confident (far from 0.5), it dominates the final score
  - When GNN is uncertain (near 0.5), the heuristic has more influence

  This hybrid design leverages GNN pattern recognition for novel vulnerabilities while
  maintaining precision on known vulnerability patterns via expert-defined heuristics.
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


# --- Boilerplate Symbol Filter ---
# Set to False to disable filtering entirely (all functions analyzed)
BOILERPLATE_FILTER_ENABLED = True

# Regex patterns for auto-generated compiler/linker labels
BOILERPLATE_REGEX = [
    re.compile(r'^_?GLOBAL_'),          # GCC global init
    re.compile(r'^_?sub_'),             # IDA Pro default names
    re.compile(r'^_?LABEL_'),           # Compiler-generated labels
    re.compile(r'^_?loc_[0-9a-f]'),     # Ghidra/IDA location labels
    re.compile(r'^_?L[C$]\d+'),         # Windows CRT labels
    re.compile(r'^_?\.L[BC]\d+'),       # GCC local labels
]

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
    if not BOILERPLATE_FILTER_ENABLED:
        return False
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
    # Regex-based detection for auto-generated labels
    for pattern in BOILERPLATE_REGEX:
        if pattern.match(fname):
            return True
    return False

# --- Heuristic Feature Scoring (Continuous, 0.0 – 1.0) ---

# CWE mapping for known dangerous API calls
CWE_MAPPING = {
    "gets":    "CWE-242",  # Use of Inherently Dangerous Function
    "strcpy":  "CWE-121",  # Stack-based Buffer Overflow
    "strcat":  "CWE-121",  # Stack-based Buffer Overflow
    "sprintf": "CWE-134",  # Format String
    "system":  "CWE-78",   # OS Command Injection
    "scanf":   "CWE-120",  # Buffer Copy without Checking Size
}

# Weighted risk scores for known dangerous API calls
UNSAFE_API_WEIGHTS = {
    "gets":    1.0,   # Unconditionally dangerous — no safe usage exists
    "strcpy":  0.9,   # Classic buffer overflow vector
    "strcat":  0.9,   # Unbounded concatenation
    "sprintf": 0.7,   # Dangerous unless format-controlled
    "scanf":   0.6,   # Dangerous with %s without width
    "system":  0.5,   # OS command injection risk
}

# API calls that indicate safe, bounded coding practices
SAFE_API_INDICATORS = {
    "strncpy", "strncat", "fgets", "snprintf", "memcpy_s",
    "memmove", "sprintf_s", "strcpy_s", "gets_s",
    "std::", "operator<<", "operator>>", "basic_string",
    "allocator", "length", "substr", "size",
}

# Safe alternatives that share substrings with unsafe APIs (e.g. "strncpy" contains "strcpy")
SAFE_ALTERNATIVES = {"strncpy", "strncat", "snprintf", "sprintf_s", "strcpy_s", "gets_s"}


def compute_heuristic_score(nodes) -> tuple[float, dict]:
    """
    Computes a continuous heuristic vulnerability score from 0.0 (definitely safe)
    to 1.0 (definitely vulnerable) by analyzing API calls in the disassembled CFG.

    Returns:
        (score, details): The heuristic score and a dict of found unsafe/safe calls.
    """
    unsafe_hits = []     # (api_name, weight) tuples
    safe_hit_count = 0
    total_calls = 0

    for node in nodes:
        for instr in node["instructions"]:
            instr_lower = instr.lower()
            if "call" not in instr_lower and "jmp" not in instr_lower:
                continue

            total_calls += 1

            # Check if this is a safe alternative first (e.g. strncpy before strcpy)
            is_safe_alt = any(sa in instr_lower for sa in SAFE_ALTERNATIVES)

            # Check for unsafe API calls using word-boundary matching
            # This prevents "gets" from matching "fgets" or "strcpy" from matching "strncpy"
            if not is_safe_alt:
                for api, weight in UNSAFE_API_WEIGHTS.items():
                    if re.search(r'(?:^|(?<=[^a-zA-Z0-9]))' + re.escape(api) + r'(?=[^a-zA-Z0-9]|$)', instr_lower):
                        unsafe_hits.append((api, weight))

            # Check for safe API indicators (word-boundary matching too)
            if any(re.search(r'(?:^|(?<=[^a-zA-Z0-9]))' + re.escape(si) + r'(?=[^a-zA-Z0-9]|$)', instr_lower) for si in SAFE_API_INDICATORS):
                safe_hit_count += 1

    # Compute the score
    if not unsafe_hits and safe_hit_count == 0:
        # No recognizable API calls → heuristic is neutral (0.5 = "I don't know")
        return 0.5, {"unsafe": [], "safe_count": 0, "verdict": "neutral"}

    if unsafe_hits:
        # Take the max risk weight among all detected unsafe calls
        max_risk = max(w for _, w in unsafe_hits)
        # Scale up slightly if multiple different unsafe APIs are found
        unique_unsafe = len(set(api for api, _ in unsafe_hits))
        multi_penalty = min(0.1 * (unique_unsafe - 1), 0.1)  # +0.1 max for variety
        raw_score = min(max_risk + multi_penalty, 1.0)

        # If safe APIs are also present, dampen the score slightly
        # (the function may be partially patched)
        if safe_hit_count > 0:
            dampen = 0.1 * min(safe_hit_count, 3)  # Up to -0.3
            raw_score = max(raw_score - dampen, 0.4)

        return raw_score, {
            "unsafe": [(api, w) for api, w in unsafe_hits],
            "safe_count": safe_hit_count,
            "verdict": "vulnerable"
        }
    else:
        # Only safe calls found, no unsafe calls → lean safe
        safe_score = max(0.1, 0.4 - 0.1 * min(safe_hit_count, 3))
        return safe_score, {
            "unsafe": [],
            "safe_count": safe_hit_count,
            "verdict": "safe"
        }


def ensemble_gnn_heuristic(gnn_vuln_prob: float, heuristic_score: float,
                           heuristic_details: dict | None = None) -> float:
    """
    Combines GNN probability and heuristic score using context-aware ensembling.

    Strategy:
      - When the heuristic has NO signal (neutral, no API calls found), we require
        much stronger GNN evidence to flag. The ensemble biases toward safe because
        there is no observable evidence of dangerous API usage.
      - When the heuristic has signal (unsafe or safe API calls detected), normal
        confidence-weighted blending applies:
          * GNN confident → GNN dominates
          * GNN uncertain → heuristic has more influence

    Args:
        gnn_vuln_prob:   GNN's raw softmax probability for the 'vulnerable' class (0–1).
        heuristic_score: Heuristic vulnerability score (0–1).
        heuristic_details: Dict from compute_heuristic_score, used to detect neutral verdict.

    Returns:
        Final blended vulnerability probability (0–1).
    """
    is_neutral = heuristic_details and heuristic_details.get("verdict") == "neutral"

    if is_neutral:
        # No API evidence at all — bias toward safe
        # GNN gets equal weight, then final is pulled 15% toward safe
        gnn_confidence = abs(gnn_vuln_prob - 0.5) * 2.0
        gnn_weight = 0.5 + 0.2 * gnn_confidence  # ranges 0.5–0.7
        heuristic_weight = 1.0 - gnn_weight
        final_prob = gnn_weight * gnn_vuln_prob + heuristic_weight * heuristic_score
        neutral_pull = 0.15 * (2.0 * final_prob - 1.0)  # negative when >0.5, positive when <0.5
        final_prob = final_prob - neutral_pull
    else:
        # Heuristic has signal — standard confidence-weighted ensemble
        gnn_confidence = abs(gnn_vuln_prob - 0.5) * 2.0
        gnn_weight = 0.65 + (1.0 - 0.65) * gnn_confidence * 0.7  # 0.65 → ~0.90
        heuristic_weight = 1.0 - gnn_weight
        final_prob = gnn_weight * gnn_vuln_prob + heuristic_weight * heuristic_score

    return max(0.01, min(0.99, final_prob))


class VulnerabilityPredictor:
    """
    Singleton predictor that loads Word2Vec and GNN models on first use.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._gnn_model = None
        self._w2v_model = None
        self._is_loaded = False
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Paths to assets
        self.w2v_path = Path(__file__).resolve().parent.parent / "artifacts" / "asm2vec.model"
        self.gnn_path = Path(__file__).resolve().parent.parent / "artifacts" / "best_fold4.pt"

    def load_models(self):
        """Load Word2Vec and trained GNN weights (thread-safe)."""
        with self._lock:
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
            logger.warning("No function CFGs extracted from binary. Ghidra may have failed to disassemble.")
            return {
                "prediction": "Safe",
                "label": 0,
                "confidence": 0.0,
                "top_features": [],
                "flagged_functions": [],
                "_warning": "No CFGs were extracted from this binary. Ghidra may not support this file format or the binary may be stripped beyond analysis."
            }

        with self._lock:
            analyzed_functions = []
            flagged_functions = []
            overall_vulnerable = False
            has_heuristic_vuln_evidence = False
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

                    oov_rate = oov_tokens / total_tokens if total_tokens > 0 else 0.0
                if oov_rate > 0.5:
                    logger.warning(f"  High OOV rate for {fname}: {oov_tokens}/{total_tokens} tokens ({oov_rate:.1%}) — node vector may be zero or noise-dominated")
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
                    heuristic_details = None
                else:
                    # Run GNN model
                    batch = torch.zeros(x.size(0), dtype=torch.long).to(self.device)
                    with torch.no_grad():
                        out = self._gnn_model(x, edge_index, batch)
                        probs = torch.softmax(out, dim=1)[0]
                        vuln_prob = float(probs[1])
                        safe_prob = float(probs[0])

                    # --- Confidence-Weighted Ensemble ---
                    # Step 1: Get raw GNN prediction
                    raw_gnn_vuln = vuln_prob

                    # Step 2: Get continuous heuristic score
                    heuristic_score, heuristic_details = compute_heuristic_score(nodes)

                    # Step 3: Blend via context-aware ensemble (conservative when heuristic has no signal)
                    vuln_prob = ensemble_gnn_heuristic(raw_gnn_vuln, heuristic_score, heuristic_details)
                    safe_prob = 1.0 - vuln_prob
                    is_vuln = vuln_prob > 0.5
                    confidence = vuln_prob if is_vuln else safe_prob

                    # Log all ensemble decisions (not just disagreements)
                    gnn_verdict = "Vulnerable" if raw_gnn_vuln > 0.5 else "Safe"
                    final_verdict = "Vulnerable" if is_vuln else "Safe"
                    gnn_confidence_score = abs(raw_gnn_vuln - 0.5) * 2.0
                    gnn_weight_used = 0.65 + (1.0 - 0.65) * gnn_confidence_score * 0.7
                    heuristic_weight_used = 1.0 - gnn_weight_used
                    logger.info(
                        f"  ENSEMBLE {fname}: GNN={raw_gnn_vuln:.3f} "
                        f"Heuristic={heuristic_score:.3f} → Final={vuln_prob:.3f} "
                        f"(gnn_w={gnn_weight_used:.2f}, heur_w={heuristic_weight_used:.2f}) "
                        f"| {heuristic_details}"
                    )

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
                    "oov_rate": round(oov_rate, 4)
                }
                analyzed_functions.append(func_info)

                if is_vuln:
                    overall_vulnerable = True
                    # Track whether heuristic found actual vulnerability evidence (unsafe API calls)
                    heuristic_verdict = heuristic_details.get("verdict") if heuristic_details else None
                    if heuristic_verdict == "vulnerable":
                        has_heuristic_vuln_evidence = True
                    if vuln_prob > max_vuln_confidence:
                        max_vuln_confidence = vuln_prob

                    # Detect all unsafe API(s) present to assign best CWE(s)
                    detected_cwes = set()
                    detected_apis = []
                    for node in nodes:
                        for instr in node["instructions"]:
                            instr_lower = instr.lower()
                            for api, cwe in CWE_MAPPING.items():
                                if re.search(r'(?:^|(?<=[^a-zA-Z0-9]))' + re.escape(api) + r'(?=[^a-zA-Z0-9]|$)', instr_lower):
                                    detected_apis.append(api)
                                    detected_cwes.add(cwe)
                    detected_cwe = ", ".join(sorted(detected_cwes)) if detected_cwes else "CWE-119"
                    brief = (
                        f"Ensemble (GNN+heuristic) flagged this function at {vuln_prob:.1%} confidence. "
                        f"Detected API calls: {', '.join(set(detected_apis)) or 'suspicious CFG patterns'}. "
                        f"Associated weakness: {detected_cwe}."
                    )

                    flagged_functions.append({
                        "function_name": fname,
                        "confidence": round(vuln_prob, 4),
                        "decompiled_code": "\n".join(decompiled_lines),
                        "cwe_id": detected_cwe,
                        "brief_explanation": brief
                    })
                else:
                    if safe_prob > max_safe_confidence:
                        max_safe_confidence = safe_prob

            # Override: overall verdict requires heuristic vulnerability evidence (unsafe API calls)
            # This prevents CRT/startup routines (GNN-only false positives) from triggering Vulnerable
            verdict_overridden = overall_vulnerable and not has_heuristic_vuln_evidence
            overall_vulnerable = has_heuristic_vuln_evidence

            overall_prediction = "Vulnerable" if overall_vulnerable else "Safe"
            overall_label = 1 if overall_vulnerable else 0
            if overall_vulnerable:
                overall_confidence = max_vuln_confidence
            elif verdict_overridden:
                # Override: report inverse of top GNN flag as safe confidence
                overall_confidence = 1.0 - max_vuln_confidence
            else:
                overall_confidence = max_safe_confidence

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
