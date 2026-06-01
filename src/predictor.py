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
                    parts = instr.replace(",", " ").replace("[", " ").replace("]", " ").split()
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

            # Run GNN model
            batch = torch.zeros(x.size(0), dtype=torch.long).to(self.device)
            with torch.no_grad():
                out = self._gnn_model(x, edge_index, batch)
                probs = torch.softmax(out, dim=1)[0]
                vuln_prob = float(probs[1])
                safe_prob = float(probs[0])

            is_vuln = vuln_prob > 0.5
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
