# Diagnostic-quality results: what each directory is

All graded with the SAME frozen rubric (`eval/diagnostic_quality/rubric.py`,
v2, sha256 recorded in each `summary.json`). 13 scenarios x 2 repeats = 26 runs.
Each arm directory holds `inputs/` (exact messages sent), `raw/` (raw model
output), `results.json`, `summary.json`, `system_prompt.txt`.

| directory | model output | application code that validated it |
|---|---|---|
| `baseline` | live Qwen3-4B run, ORIGINAL prompt | original validators |
| `baseline-same-outputs-final-validators` | the SAME raw outputs as `baseline` | final validators (validator-only effect, no model variance) |
| `arm-a-prior-validators` | live run, revised prompt | validators before the last rule additions (see report) |
| `arm-b` | live run, revised prompt | final validators |
| `live-v1`, `live-v2` | live API runs on the lab cluster (restricted ServiceAccount); `live-v2` also holds the exact hypothesis-stage messages and raw outputs | v1: before the live-run fixes; v2: after |

Notes
- The model is sampled, so two arms with identical code differ. Compare ranges,
  not single numbers.
- The rubric is an independent grader and is not a perfect oracle. The escapes
  and false positives in each `summary.json` were reviewed by hand; the report
  says which were rubric errors.
- Two intermediate arms (`after`, `after2`) were deleted during clean-up before
  this note was written; their headline numbers appear only in the report.
- `baseline` oom_killed #1 was lost to the model mis-copying the 36-character
  investigation id (a whole-response provenance rejection, unchanged).

## Close-out increment (lifecycle, memory terminology, probe state, `reported`)

15 scenarios (the original 13 plus `restart_history` and `oom_recovered`) x 3
repeats. Graded with the frozen v2 rubric AND the additive
`eval/diagnostic_quality/lifecycle_rubric.py` (never-started, request-blamed-for-OOM,
request/limit confusion, restart-count-proves-cause, restart-count-shows-failure-now,
not-ready-but-ready). The lifecycle rubric was written alongside the application
rules, so its independence is limited.

| directory | what it is |
|---|---|
| `closeout` | live Qwen run, final prompt; validators as of the run. `raw/` includes `model_attempts` (retries are visible only here) |
| `closeout-revalidated` | the SAME raw outputs re-validated with the final validators (one later fix: "prevents it from running properly" is no longer read as a healthy claim) |
| `closeout-replay-baseline`, `closeout-replay-arm-b` | earlier arms' raw outputs re-validated with the final validators and graded with the lifecycle rubric |
| `closeout-comparison-original13.json`, `closeout-comparison-all15.json` | side-by-side tables (original 13 only, and all 15) |
| `closeout-iteration-1` | an earlier prompt/validator iteration, kept for the record |
| `closeout-live` | live API investigations on the lab cluster with the restricted investigator (`timings.json` included) |
| `reported-probe.json`, `reported-probe-balanced.json` | prompt-arm probe for the unsupported `reported` field on the saved `live-v2` inputs (12/36 -> 0/36) |

Limitations
- Replay re-validates saved outputs; it cannot measure retries.
- (Superseded by the relevance increment below: `describe_pod` now observes the
  readiness probe too, so a standalone Pod's readiness probe is declared / verified absent.)
- The v2 rubric has known false alarms ("whether ... is ready"; imperative "Confirm that").
- Sampling variance: compare ranges, not single numbers.

## Relevance increment (abnormality-aware generation, stage checks, probe completeness)

Same 15 scenarios x 3 repeats. Metrics come from `eval/diagnostic_quality/relevance_report.py`,
which applies the same grader (`relevance_rubric.py`: relevant / generic / irrelevant per
scenario, from word families and each scenario's recorded facts) to every arm. The v2 and
lifecycle rubrics are unchanged and still reported.

| directory | what it is |
|---|---|
| `relevance-replay-closeout`, `relevance-replay-closeout-final` | the SAME raw outputs as `closeout` (old prompt), re-validated with the new validators (first and final form). Candidate ids are remapped to the new positional ids, because the new readiness observation shifts later ids. Validator-only effect. |
| `relevance-iter1`, `relevance-iter2` | live generation with the new prompt/payload, earlier iterations kept for the record (iter1 lost responses to `too_many_references` and a leaked `not_yet_established` field; iter2 fixed both) |
| `relevance-final` | live generation, final prompt, validators as of the run |
| `relevance-final-revalidated` | the SAME raw outputs as `relevance-final` with the final validators (three small fixes made after the run) |
| `relevance-comparison.json` | the side-by-side table |
| `relevance-live` | live API investigations (restricted investigator) of 7 lab workloads, four of them standalone Pods; `hypothesis-calls.jsonl` holds the exact hypothesis-stage messages |

`eval/diagnostic_quality/relevance_review.json` is a hand review (read before looking at the
grader's label): 4 random accepted hypotheses per abnormal scenario (55) and EVERY rejected
hypothesis of `relevance-final-revalidated` (20).

Limitations (see also the report)
- Generic explanations that contradict nothing are accepted; nothing judges whether an
  explanation is good. Near-duplicate paraphrases are accepted (only exact duplicates are omitted).
- A capacity or placement constraint the scheduler did not report is accepted for an
  unschedulable pod (ranked lower only): the scheduler stops at the first failing filter per
  node, so an unreported constraint is not provably absent.
- With several restarts only the latest termination is visible, so rival mechanisms for the
  earlier ones are not rejected.
- A request blamed for an OOM kill is still accepted when the sentence also mentions the limit
  ("insufficient memory request ... despite the limit"). Startup probes remain UNKNOWN.
- The frozen v2 rubric flags "before the application is ready" as a contradiction; the
  application now accepts it (a temporal condition, not a claim about current readiness).
- Relevant hypotheses are still lost to form rules (`too_long`, an unhedged limitation sentence,
  more than six citations). These are unchanged.
