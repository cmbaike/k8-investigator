# Private AI Platform Baseline

## v0.5.0

Tag: `v0.5.0`

v0.5.0 establishes the validated grounded-RAG baseline for the
Private AI Platform.

### Architecture

- PostgreSQL + pgvector document store
- BGE embeddings
- vector candidate retrieval
- BGE reranking
- typed atomic evidence sufficiency
- specialised value grounding
- specialised procedure grounding
- deterministic refusal when evidence is insufficient
- Qwen answer generation through vLLM
- source citations
- offline semantic groundedness evaluation

### Frozen evaluation results

#### Typed atomic sufficiency v2

- TP: 20
- TN: 19
- FP: 1
- FN: 0
- Accuracy: 97.5%
- Recall: 100%

Known regression:
- `v2-28-red-yellow-only`

#### Answer generation

Final answer-generation baseline:

- PASS: 10
- FAIL: 0
- Pass rate: 100%

This benchmark validates retrieval, sufficiency, refusal behaviour,
required answer content, citation validity, and removal of reasoning
blocks.

It does not establish semantic grounding of every generated claim.

#### Groundedness judge

Model: `gpt-oss:20b`

Configuration:

- temperature: 0
- max_tokens: 800
- strict textual-grounding contract
- fail closed on judge/parser failure

Development benchmark:

- 20/20
- 100%

Targeted stability:

- 30/30

Fresh holdout:

- TP: 11
- TN: 12
- FP: 0
- FN: 1
- Accuracy: 95.8%
- Precision: 100%
- Recall: 91.7%
- Judge errors: 0

The single holdout failure was `gh17-supported-numeric`, where the
judge distinguished desired replica count from actual replica state.

#### Generated-answer semantic grounding

Seven substantive generated answers were manually decomposed into
28 atomic claims.

Frozen judge versus manual labels:

- TP: 18
- TN: 7
- FP: 2
- FN: 1
- Accuracy: 89.3%
- Precision: 90.0%
- Recall: 94.7%
- Judge errors: 0

Known disagreements:

- `ag02-c3`: manual-label ambiguity around AI actor/scope
- `ag07-c3`: strict-grounding judge false positive
- `ag09-c4`: strict-grounding judge false positive

The evaluation demonstrates that syntactically valid citations do not
guarantee that every generated factual claim is supported by the cited
evidence.

### Known limitations

- Generated answers can contain unsupported elaboration.
- The groundedness judge is offline only.
- The groundedness judge is not part of production `/ask`.
- Citation validity and semantic citation support are separate concerns.
- Evidence sufficiency does not guarantee fully grounded generation.
- Retrieval and generation latency have not yet been systematically
  instrumented.
- Document lifecycle management is still engineering-oriented.
- No autonomous production-changing actions are permitted.

---

## v0.6.0 milestone

Goal: turn the validated v0.5 RAG core into a usable and observable
DevOps/SRE assistant.

### Acceptance criteria

- [x] Structured `/ask` response contract
- [x] Request ID
- [x] Explicit `answered` / `insufficient_evidence` status
- [x] Inspectable source provenance
- [x] Improved evidence-only generation contract
- [x] Re-evaluate unsupported generated claims
- [x] Document ingest/list/inspect/delete lifecycle
- [x] Document metadata and ingestion status
- [x] PostgreSQL-backed audit trail
- [x] Retrieval/reranking/sufficiency/generation latency measurements
- [x] Existing v0.5 regression suites remain passing
- [x] API examples documented
- [x] Known limitations documented
- [ ] Tag `v0.6.0`

### Out of scope for v0.6.0

- Kubernetes agent execution
- production-changing tool execution
- OpenClaw integration
- Redis
- Qdrant
- BM25/hybrid retrieval
- groundedness judge in production `/ask`
- automatic claim extraction
- multi-user authentication
- major frontend rewrite

### v0.6 development results

#### Stricter grounded generation

The answer-generation system prompt was tightened so that every factual
statement must be explicitly supported by retrieved context. The model is
instructed not to infer consequences, causes, guarantees, operational
behaviour, availability, safety, timing, or recommendations unless those
claims are explicitly present in the evidence.

Frozen answer-generation regression:

- 10/10 passing on the captured v0.6 run
- one earlier run produced a transient invalid citation label on `ag07`
- no retrieval, reranking, sufficiency, or groundedness-judge changes were
  made for this experiment

Manual semantic assessment of the captured substantive answers:

- 18 atomic claims
- 17 manually grounded
- 1 manually unsupported
- unsupported proposition rate: 5.6%

The remaining unsupported proposition was an added rationale in `ag07`:
the answer claimed that the prohibition on modifying persistent data exists
to avoid data loss or unintended modifications during diagnosis. The cited
evidence contains the prohibition but does not explicitly state that
rationale.

For comparison, the v0.5 generated-answer snapshot contained:

- 28 atomic claims
- 19 manually grounded
- 9 manually unsupported
- unsupported proposition rate: 32.1%

These snapshots have different generated answers and claim counts and are
therefore engineering comparisons rather than a controlled statistical
benchmark.

Frozen groundedness judge on the v0.6 snapshot:

- TP: 16
- TN: 1
- FP: 0
- FN: 1
- Accuracy: 94.4%
- Precision: 100%
- Recall: 94.1%
- Judge errors: 0

The single semantic disagreement was `v060-ag07-c1`. The judge correctly
rejected the deliberately unsupported `v060-ag07-c3` rationale.

The groundedness judge remains offline and is not part of production `/ask`.

### v0.6 operational API baseline

The production `/ask` contract now exposes:

- UUID request ID
- explicit `answered` or `insufficient_evidence` status
- answer or deterministic refusal
- retrieved evidence and provenance
- evidence-sufficiency summary
- retrieval latency
- sufficiency latency
- generation latency
- total AI-pipeline latency

Insufficient-evidence requests bypass answer generation and therefore expose
`generation_ms: null`.

Completed answer and refusal results are persisted in PostgreSQL through the
`ask_audit` table. Audit records contain request metadata, result status,
source labels, generation model, and stage latency measurements.

Audit persistence is fail-closed for completed API results.

Document ingestion remains synchronous. A persisted document has successfully
completed extraction, chunking, embedding, and database insertion and is
therefore exposed with `status: ready`.

### v0.6 observed latency smoke tests

Latency instrumentation was validated using live local requests.

Supported Elasticsearch question:

- retrieval/reranking: approximately 472 ms
- sufficiency: approximately 432 ms
- generation: approximately 1,390 ms
- total AI pipeline: approximately 2,294 ms

Insufficient-evidence RTO question:

- retrieval/reranking: approximately 64 ms
- sufficiency: approximately 6,277 ms
- generation: not invoked
- total AI pipeline: approximately 6,342 ms

These are individual operational smoke-test observations and are not presented
as a performance benchmark. No latency optimisation was performed based on
these measurements.

### v0.6 known limitations

- Generated language can still contain unsupported elaboration.
- Evidence sufficiency does not guarantee semantic grounding of every
  generated claim.
- The semantic groundedness judge remains offline.
- Citation validity does not establish semantic citation correctness.
- Retrieval is vector + reranker based; BM25/hybrid retrieval is not included.
- Document ingestion is synchronous.
- Latency is instrumented but has not been systematically benchmarked.
- Sufficiency latency can vary substantially by question and semantic route.
- There is no multi-user authentication or authorisation.
- There is no production-changing tool execution.
- There is no Kubernetes agent execution.
- There is no OpenClaw integration.

### v0.6.0 release validation

The v0.6.0 release candidate was validated without changes to retrieval,
reranking, sufficiency architecture, generation prompts, evaluation datasets,
or semantic judges during the release evaluation.

Unit/API regression:

- 36/36 tests passing

Typed atomic sufficiency v2:

- TP: 20
- TN: 19
- FP: 1
- FN: 0
- Accuracy: 97.5%
- Precision: 95.2%
- Recall: 100.0%
- Known failure: `v2-28-red-yellow-only`

Answer-generation release run:

- PASS: 9
- FAIL: 1
- Pass rate: 90.0%
- Failure: `ag07-pvc`

The `ag07-pvc` failure was caused solely by an invalid generated citation
label. The generated answer cited `page-12-chunk-19` where the retrieved
source label was `page-9-chunk-19`. Sufficiency, required answer content,
refusal behaviour, and reasoning-block removal all passed.

This is consistent with the citation-label copying instability observed
during earlier v0.6 development. The release result was retained as observed;
the evaluator was not repeatedly rerun to obtain the previous captured 10/10
result.

Groundedness judge fresh holdout:

- Total cases: 24
- Scored cases: 24
- TP: 11
- TN: 12
- FP: 0
- FN: 1
- Accuracy: 95.8%
- Precision: 100.0%
- Recall: 91.7%
- Judge errors: 0
- Known semantic failure: `gh17-supported-numeric`

v0.6 generated-answer groundedness snapshot:

- Total claims: 18
- Scored claims: 18
- TP: 16
- TN: 1
- FP: 0
- FN: 1
- Accuracy: 94.4%
- Precision: 100.0%
- Recall: 94.1%
- Judge errors: 0
- Substantive answers: 7
- Fully grounded answers: 6
- Answers containing at least one unsupported claim: 1
- Known semantic disagreement: `v060-ag07-c1`

The groundedness evaluations were executed with sufficient GPU capacity after
earlier infrastructure-constrained attempts produced judge execution errors.
The corrected runs scored every case and exactly reproduced the frozen
semantic baselines.

### Release assessment

v0.6.0 satisfies the milestone acceptance criteria subject to the documented
known limitations.

The most important remaining generation limitation is stochastic copying of
opaque source labels. A future version should move citation attachment toward
a deterministic or structured mechanism rather than relying entirely on the
generation model to reproduce source identifiers.

---

## v0.7.0 milestone

Goal: extend the evidence-grounded DevOps/SRE assistant with controlled,
auditable read-only operational tooling and a policy boundary suitable for
future human-approved state-changing actions.

### Acceptance criteria

- [ ] Typed tool definition and invocation contract
- [ ] Explicit tool risk classification
- [ ] Allow-listed read-only Kubernetes tools
- [ ] Tool input validation
- [ ] Tool execution timeout
- [ ] Tool output size limits
- [ ] Tool execution audit trail
- [ ] Request ID propagated through tool execution
- [ ] Assistant can use tool observations alongside retrieved documentation
- [ ] Tool observations are distinguishable from documentation evidence
- [ ] State-changing tools cannot execute autonomously
- [ ] Approval-required result contract
- [ ] Deterministic policy enforcement outside the language model
- [ ] Tool and policy unit tests
- [ ] End-to-end read-only incident investigation
- [ ] Known limitations documented
- [ ] Tag `v0.7.0`

### Initial read-only Kubernetes tools

- get pods
- describe pod
- get events
- get deployment
- get logs
- get previous container logs

### Explicitly prohibited in v0.7.0

- arbitrary shell execution
- kubectl exec
- kubectl apply
- kubectl patch
- kubectl delete
- scaling workloads
- restarting workloads
- database state changes
- Elasticsearch state changes
- credential changes
- autonomous production mutation

### Design principle

The language model may propose an operation but does not decide whether that
operation is permitted to execute.

Authorization and risk classification are deterministic application policy.

Read-only allow-listed operations may execute automatically.

State-changing or destructive operations must fail closed and return an
approval-required result. v0.7.0 establishes this boundary but does not enable
production-changing execution.
