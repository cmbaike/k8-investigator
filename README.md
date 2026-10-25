# Private AI Operations Platform

Hackathon demo: open [http://147.12.193.157:8080/console](http://147.12.193.157:8080/console).
There is no login.

An on-call engineer asks what is wrong with a workload. Today they search
runbooks, cluster output, and chat. This console runs one read-only
investigation and shows a cited report, or it refuses when the evidence is
not there.

A self-hosted, evidence-grounded assistant for DevOps/SRE operational
knowledge.

The platform retrieves approved operational documentation, determines whether
the retrieved evidence is sufficient to answer a question, refuses questions
that are not supported by the evidence, and generates cited answers when the
evidence is sufficient.

v0.6.0 is a read-only knowledge and decision-support system. It does not
execute production-changing actions.

## Architecture

The current stack consists of:

- FastAPI API
- PostgreSQL + pgvector document and vector store
- BGE embeddings
- Vector candidate retrieval
- BGE reranking
- Typed atomic evidence-sufficiency assessment
- Specialised value and procedure grounding
- Qwen3-4B answer generation through vLLM
- gpt-oss specialised semantic assessment through Ollama
- Deterministic insufficient-evidence refusal
- Source provenance and citations
- PostgreSQL-backed request audit trail
- Per-request latency instrumentation
- Offline semantic groundedness evaluation

The production request path is approximately:

```text
Question
  |
  v
Vector candidate retrieval
  |
  v
BGE reranking
  |
  v
Typed atomic evidence sufficiency
  |
  +-- insufficient --> deterministic refusal
  |
  +-- sufficient ----> Qwen3-4B generation
                           |
                           v
                       cited answer
```

Evidence sufficiency routes atomic requirements according to requirement type.
Value and procedure requirements use specialised semantic extraction and
deterministic grounding checks. Other supported requirement types use the
generic sufficiency route.

## API

The development server can be started with:

```bash
uv run uvicorn app.api:app --host 0.0.0.0 --port 8080
```

FastAPI exposes interactive API documentation at `/docs`.

### Health

```http
GET /health
```

Reports service health.

### Search

```http
POST /search
```

Provides direct retrieval/search access. This endpoint is useful for
inspection and debugging and is separate from the evidence-controlled
`/ask` path.

### Ask

```http
POST /ask
Content-Type: application/json

{
  "question": "What does red Elasticsearch cluster health mean?"
}
```

A supported question returns an answered response containing:

- a unique request ID
- the original question
- generated answer
- retrieved source provenance
- evidence-sufficiency status
- retrieval latency
- sufficiency latency
- generation latency
- total AI-pipeline latency

Conceptually:

```json
{
  "request_id": "<uuid>",
  "status": "answered",
  "question": "What does red Elasticsearch cluster health mean?",
  "answer": "<evidence-grounded answer>",
  "sources": [
    {
      "filename": "<document>",
      "chunk_index": 0,
      "page_number": 1,
      "content": "<retrieved chunk>",
      "similarity": 0.0,
      "label": "<document>#page-1-chunk-0",
      "excerpt": "<supporting excerpt>"
    }
  ],
  "sufficiency": {
    "sufficient": true
  },
  "timings": {
    "retrieval_ms": 0.0,
    "sufficiency_ms": 0.0,
    "generation_ms": 0.0,
    "total_ms": 0.0
  }
}
```

When retrieved evidence is insufficient, the endpoint returns:

```json
{
  "status": "insufficient_evidence",
  "answer": "I don't have sufficient evidence in the retrieved sources to answer this question.",
  "sufficiency": {
    "sufficient": false
  },
  "timings": {
    "generation_ms": null
  }
}
```

The full response still contains the request ID, question, retrieved sources,
and the other latency measurements.

The refusal is deterministic. Answer generation is not invoked when evidence
sufficiency fails.

### Documents

The API provides document lifecycle endpoints for:

- ingest/upload
- list
- inspect
- delete

Persisted documents are considered ready because ingestion is synchronous:
document metadata and chunks are committed only after extraction, chunking,
and embedding have completed successfully.

Document metadata includes filename, SHA-256 digest, content type, size,
chunk/page information, creation timestamp, and status.

Deleting a document removes its associated chunks through the database
foreign-key cascade.

## Evidence and provenance

Generated answers are constrained to retrieved evidence.

Retrieved evidence exposes provenance including:

- document filename
- page number
- chunk index
- source label
- supporting content/excerpt

Citation validity and semantic grounding are intentionally treated as
different properties. A syntactically valid citation proves that the cited
chunk was retrieved; it does not by itself prove that every generated claim
is semantically supported by that chunk.

Semantic groundedness is evaluated offline.

## Audit trail

Every completed `/ask` result is persisted to PostgreSQL with:

- request ID
- timestamp
- question
- status
- answer/refusal
- evidence-sufficiency result
- retrieved source labels
- answer-generation model
- error type where applicable
- retrieval latency
- sufficiency latency
- generation latency
- total AI-pipeline latency

Audit persistence is fail-closed for completed answers/refusals: an audit
write failure prevents the API from returning a successful result.

The audit trail deliberately does not store chain-of-thought, hidden model
reasoning, embeddings, or internal prompts.

## Latency telemetry

`/ask` reports:

- `retrieval_ms`
- `sufficiency_ms`
- `generation_ms`
- `total_ms`

`generation_ms` is `null` for insufficient-evidence refusals because the
generation model is not invoked.

`total_ms` measures the AI request pipeline through answer generation or the
refusal decision. Audit-database write latency is intentionally excluded.

The timings are operational telemetry, not a formal performance benchmark.

## Evaluation

The project maintains frozen evaluation suites for:

- typed atomic evidence sufficiency
- answer generation
- value binding
- procedure grounding
- groundedness judging
- generated-answer semantic grounding

See [`BASELINE.md`](BASELINE.md) for frozen results and known regressions.

Evaluation datasets that have already been used for model or architecture
decisions are treated as spent holdouts and are not subsequently tuned against
while still being described as fresh holdouts.

## Safety boundary

v0.6.0 is an evidence-grounded read-only assistant.

The following capabilities are intentionally outside the v0.6.0 production
boundary:

- Kubernetes agent execution
- production-changing tool execution
- autonomous restart or deletion of workloads
- database failover or destructive recovery execution
- arbitrary shell execution
- OpenClaw integration
- multi-user authentication and authorisation
- production semantic-groundedness judging

The system can retrieve operational knowledge and describe documented
procedures, but it is not yet an autonomous production operator.

## Known limitations

- Generated language can still contain unsupported elaboration.
- Evidence sufficiency does not guarantee that every generated claim is
  semantically grounded.
- Semantic groundedness evaluation is offline rather than part of `/ask`.
- Citation validity and semantic citation support are separate concerns.
- Retrieval is vector + reranker based; hybrid/BM25 retrieval is not
  implemented.
- Document ingestion is synchronous.
- Latency has been instrumented but not systematically performance-benchmarked.
- There is no multi-user authentication or authorisation layer.
- There is no production tool-execution or approval workflow.

## Development

Install/synchronise the project environment:

```bash
uv sync
```

Run tests:

```bash
uv run pytest -q
```

Run the API:

```bash
uv run uvicorn app.api:app --host 0.0.0.0 --port 8080
```

The platform also requires its configured PostgreSQL/pgvector database and
local model-serving infrastructure.

### Web console

A read-only investigation console lives in [`frontend/`](frontend/README.md).
Build it once, and the same API process serves it at `/console/`:

```bash
(cd frontend && npm ci && npm run build)
scripts/run_lab_api.sh      # open http://127.0.0.1:8080/console/
```

The browser signs in with an API key that is exchanged for a server-side
session cookie; it uses `/api/*` routes and the API-key routes are unchanged.

Environment-specific configuration is supplied through `.env` and should not
be committed.

## Release baseline

The validated release and evaluation history is maintained in
[`BASELINE.md`](BASELINE.md).

- **v0.5.0** established the grounded-RAG baseline.
- **v0.6.0** adds the usable and observable API layer around that baseline:
  structured responses, document inspection, improved generation grounding,
  durable auditing, and latency telemetry.