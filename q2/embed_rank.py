"""Q2: nomic-embed-text vs mxbai-embed-large via Ollama, two FAISS IndexFlatIP, Spearman rho.

Usage:  python q2/embed_rank.py [--prefix]
  --prefix  add the task prefixes some guides recommend (nomic: search_document:/search_query:,
            mxbai: "Represent this sentence for searching relevant passages: " on queries).
            The default embeds raw text, as in the exam's starter script.
"""
import json
import sys
import urllib.request
from pathlib import Path

import faiss
import numpy as np
from scipy.stats import spearmanr

OLLAMA = "http://127.0.0.1:11434"
HERE = Path(__file__).resolve().parent
data = json.loads((HERE / "dataset.json").read_text("utf-8"))
SENTS, QUERIES = data["sentences"], data["queries"]
PREFIX = "--prefix" in sys.argv


def embed(model: str, texts):
    req = urllib.request.Request(
        f"{OLLAMA}/api/embed",
        data=json.dumps({"model": model, "input": list(texts)}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        vecs = np.array(json.loads(r.read())["embeddings"], dtype="float32")
    faiss.normalize_L2(vecs)
    return vecs


def build(model, doc_prefix="", query_prefix=""):
    docs = embed(model, [doc_prefix + s for s in SENTS])
    qs = embed(model, [query_prefix + q for q in QUERIES])
    index = faiss.IndexFlatIP(docs.shape[1])
    index.add(docs)
    return index, qs


if PREFIX:
    A = build("nomic-embed-text", "search_document: ", "search_query: ")
    B = build("mxbai-embed-large", "", "Represent this sentence for searching relevant passages: ")
else:
    A = build("nomic-embed-text")
    B = build("mxbai-embed-large")

n = len(SENTS)
rows = []
for qi in range(len(QUERIES)):
    sa, ia = A[0].search(A[1][qi : qi + 1], n)
    sb, ib = B[0].search(B[1][qi : qi + 1], n)
    # similarity of every doc, in doc order, for each model
    full_a = np.empty(n); full_a[ia[0]] = sa[0]
    full_b = np.empty(n); full_b[ib[0]] = sb[0]
    rho = spearmanr(full_a, full_b).correlation
    rows.append([*map(int, ia[0][:3]), *map(int, ib[0][:3]), round(float(rho), 4)])

print(json.dumps(rows))
