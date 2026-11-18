# TDS 2026-09 GA5

One deployable service answering Q1 and Q4, plus the Q2/Q3 scripts.

| Q | What to paste into the exam |
|---|---|
| 1 — RAG Colosseum | `<BASE>` (route is `POST /query`) |
| 2 — Ollama/FAISS rank correlation | output of `python q2/embed_rank.py` |
| 3 — Track the red ball | output of the Q3 tracker |
| 4 — Harness safety router | `<BASE>/classify` |

## Run and deploy

```bash
pip install -r requirements.txt
uvicorn main:app --port 8000
```

Deploy on Render with `render.yaml` (free plan; the build step bakes the MiniLM
embedding model in so cold starts don't download it), or as a Docker / HF Space
with the `Dockerfile` (port 7860). Health check: `GET /healthz`.

The free plan sleeps when idle: open `<BASE>/healthz` about a minute before a Check.

| Variable | Purpose |
|---|---|
| `GA5_DEBUG_TOKEN` | when set, `GET /debug/requests?token=…&kind=query|classify` returns the last grader bodies (in memory) |
| `FASTEMBED_CACHE` | where the embedding model is cached |

## Layout

```
main.py            FastAPI app: POST /query, POST /classify, /healthz, debug capture
ga5/rag.py         Q1 hybrid retrieval (MiniLM + BM25 + alias table) and extractive answers
ga5/safety.py      Q4 harness policy, encoded as deterministic rules
q2/embed_rank.py   Q2 nomic-embed-text vs mxbai-embed-large, FAISS IndexFlatIP, Spearman rho
tests/             simulated graders for Q1 and Q4
```

## Tests

```bash
python tests/test_rag.py      # Q1: factual, confounder, synthesis, abstain, injection probes
python tests/test_safety.py   # Q4: one case per policy clause
```
