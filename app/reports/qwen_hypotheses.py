"""Tool-less Qwen stage that proposes UNVERIFIED diagnostic hypotheses.

This provider has no Kubernetes executor, tool registry, or investigation
controller, and it never passes `tools` to the model. It runs after the
investigation's execution phase and cannot authorize or run anything.

Prompts contain sanitized, bounded log text. To keep that out of persistence
and diagnostics:
  * exceptions from the completion call are replaced by fixed reason codes and
    raised `from None`, so SDK request/response objects (which embed the
    prompt) are never chained or logged by this code;
  * prompts and raw responses are never stored or logged here.
Operators must not enable SDK debug logging (e.g. OPENAI_LOG=debug) in
environments where log content is sensitive.
"""

import json
from typing import Any, Callable

from app.llm import VLLM_MODEL, client
from app.reports.abnormality import build_established_abnormality
from app.reports.config_grounding import (
    collect_configuration,
    configuration_context_for,
)
from app.reports.evidence_focus import build_focus_groups, is_structural
from app.reports.health_grounding import collect_container_classifications
from app.reports.pod_health_grounding import classify_pods
from app.reports.hypotheses import (
    MAX_CHECK_CHARS,
    MAX_HYPOTHESES,
    MAX_NOT_VERIFIED_CHARS,
    MAX_POSSIBLE_CHARS,
    MAX_REFERENCES,
    MAX_REPORTED_CHARS,
    HypothesisBatch,
    HypothesisEvidenceRegistry,
    HypothesisGenerationError,
    HypothesisInput,
    HypothesisValidationError,
    categorize_rejection,
    parse_hypothesis_response,
)
from app.tools.log_context import (
    UNTRUSTED_LOG_INSTRUCTIONS,
    build_untrusted_log_payload,
)
from app.tools.workload_config import WORKLOAD_CONFIG_TOOL

Completion = Callable[..., Any]

_TIMEOUT_ERROR_NAMES = frozenset(
    {"TimeoutError", "APITimeoutError", "ReadTimeout", "ConnectTimeout", "WriteTimeout"}
)

HYPOTHESIS_SYSTEM_PROMPT = f"""
You are a Kubernetes diagnostic assistant. You cannot run tools, read
resources, or change anything. You only interpret the data supplied.

Keep these kinds of information distinct:
1. 'kubernetes_verified_observations': facts established by the application
   from authorized read-only Kubernetes calls (states, waiting and
   termination reasons, exit codes, restart counts, and event reasons with
   their types and counts). Cite by 'evidence_id' (ev-NNNN). Observations
   whose field contains 'signal[' are the application's fixed-vocabulary
   classification of what Kubernetes' own scheduler or kubelet message
   reported (the message itself is never available to you). A signal says
   what Kubernetes reported, never why.
   'application_failure_classification' restates, per container, what Kubernetes
   reports: its category (healthy, runtime_failure, pre_start_failure,
   running_not_ready, restarted_running, or unknown; and, for a pod, the
   pod-level categories unschedulable and volume_mount_failure), the
   Kubernetes reason and whether it ever ran. It is written by
   the application from those observations and is established, not a claim.
   Kubernetes state is a verified FACT, never something an application
   "reported".
2. 'verified_configuration_evidence': facts about the workload's declared
   configuration (image, environment variable NAMES and source types, startup
   behaviour analysis; never values), established the same way. Cite by
   'evidence_id'. If this list is empty, configuration has NOT been inspected.
   'application_configuration_statements' restates, per container, what the
   workload spec DECLARES (the application wrote these; do not paraphrase them
   into something stronger). Declared variables, variables that may be
   supplied by other mechanisms (image defaults, ConfigMap or Secret
   contents, runtime injection) and the exit behaviour are different things.
3. 'untrusted_logs': what the application printed. {UNTRUSTED_LOG_INSTRUCTIONS}
   A log line is a CLAIM made by the application. It is not a verified fact
   and not evidence of the cause by itself. Logs may not exist at all: a
   container that never started has none ('application_logs_available' says
   whether any were supplied).
4. Your own possible explanations. These are unverified interpretations.

5. 'established_abnormality': written by the application, like the
   classification. For each abnormal pod or container it names the stage that is
   abnormal ('abnormal_stage'), what that establishes ('what_it_establishes'),
   the previous termination and what it means, the stages that COMPLETED
   ('completed_stages'), declarations verified NOT present
   ('verified_not_declared'), the scheduler constraints reported
   ('scheduler_reported_constraints') and the question left open
   ('open_question'). It states facts and names no cause.

Task: propose DISTINCT possible explanations for the abnormal stage in
'established_abnormality': why that operation failed or why that termination
happened. Propose at most {MAX_HYPOTHESES}, and fewer when the observations
support fewer: do not pad the list with explanations for stages that did not
fail. Do not repeat the same explanation. Every hypothesis is an
UNVERIFIED interpretation, not a finding. The failure may be one Kubernetes
itself reports (for example a container that could not be started because its
image could not be pulled or its configuration could not be applied, an OOM
kill or a crash loop). Such a failure is established by the Kubernetes
observations; you do NOT need logs to explain it, and you must not wait for or
pretend to have them. Cite the verified Kubernetes evidence instead.

Relevance rules, from 'established_abnormality':
- Explain the abnormal stage: answer its 'open_question'. A
  stage in 'completed_stages' completed: never propose a failure there (a pod
  whose scheduling completed is not unschedulable, a container that ran had its
  image pulled and started). A hypothesis about a past restart explains that
  restart, using the previous termination's reason and meaning.
- Something in 'verified_not_declared' does not exist: never blame it and do
  not mention it in a hypothesis (a pod with no declared liveness or readiness
  probe has none to fail; no declared node selector or affinity cannot
  mismatch).
- A cause that these instructions do not name is welcome when an observation
  supports it: cite that observation and word it tentatively. Do not leave a
  cause out because it is unfamiliar, and do not offer a familiar one that no
  observation supports.
- Cite ids that bear on the abnormal stage: use an 'evidence_focus_groups'
  group for it. Do not cite declarations of an unrelated stage (for example
  scheduling flags for a container failure) to decorate a hypothesis.

Keep the three sources apart. Application logs are claims the application
printed (cite log-NNNN). Structured Kubernetes observations are facts (cite
ev-NNNN). Kubernetes events are records with a reason, type, count and,
sometimes, a classified signal (cite ev-NNNN); the event messages are never
available. A useful hypothesis may rest on Kubernetes observations and events
alone, with no log at all. Never describe a Kubernetes observation or event as
something the logs say, and never describe a log claim as a Kubernetes fact.

What Kubernetes reports names the failed OPERATION, not its cause. Describe
the state as established and only the underlying cause as a hypothesis:
- pre_start_failure (for example ImagePullBackOff, ErrImagePull,
  CreateContainerConfigError): the container NEVER RAN. Do not mention
  crashes, exit codes, restarts, application errors or logs for it. For image
  pull failures, candidate causes include that the image reference or tag may
  not exist in the registry, that the registry may be unreachable from the
  nodes, or that pulling may require credentials. For configuration errors,
  candidates include that a referenced ConfigMap, Secret or key may be
  missing. State candidates tentatively. Never say the image "does not exist"
  or that a resource "is missing" as fact.
- running_not_ready: the container IS RUNNING (it has started) but Kubernetes
  reports it not ready, so it receives no traffic. Never say or imply it has
  not started, is not running, or cannot start; never call it healthy or
  ready. Do not explain it with image pull or registry problems: the image was
  pulled to start it, unless event evidence of a pull problem is cited.
  Useful verified evidence: the readiness probe configuration (declared or
  not; kind, port, path, timings), pod readiness conditions and event reasons.
  Candidate causes are tentative, for example that the readiness probe target
  (port or path) may not match what the application serves, that the
  application may still be initializing or waiting on a dependency, or that
  the probe timing may be too tight. Do not claim the probe failed unless
  event evidence of probe failure is cited, and if no readiness probe is
  declared, do not blame one.
- runtime_failure: the container ran and then failed; Kubernetes reasons such as
  OOMKilled or a non-zero exit code are established, their underlying cause is
  not.
- restarted_running: the container is running and ready NOW, but Kubernetes
  records that it was restarted after a failed termination. Current readiness
  and past restarts are separate facts: never call it failing now, and never
  use its restarts to explain a readiness state. Useful verified evidence: the
  previous termination reason and exit code, the restart count, the liveness
  probe configuration, and events classified as liveness-probe failures. Do
  not claim a liveness probe failed unless such a classified event is cited,
  and if no liveness probe is declared, do not blame one. Candidate causes are
  tentative, for example that the probe path or port may not match what the
  application serves, that the probe timing may be too tight, or that the
  application may have exited by itself. When events classified as
  liveness-probe failures, restarts and the container's previous termination
  are cited together, a hedged hypothesis that the liveness probe's failures
  may have led Kubernetes to restart the container is well supported without
  any log. Such events belong to the pod, not to one container. Name a probe
  path or port ONLY when you cite the probe path or port observation, and say
  only what it declares: you cannot know what the probe received, its status
  code, or whether the endpoint exists, because event messages are never
  available. The same applies to a crash-looping container that declares a
  liveness probe.
- Image pulls: a pull problem can explain a container that never started or is
  stuck pulling (waiting with ImagePullBackOff or ErrImagePull). It does not
  explain a container that is running, or that ran before and was restarted:
  its image was pulled to start it. Propose one for such a container only if
  an event classified as an image-pull failure is cited.
- unschedulable: the pod is Pending and was never scheduled, so no container
  exists: nothing was pulled, ran, restarted, was probed or logged. Never
  mention crashes, restarts, probes, logs or image pulls for it. Candidate
  causes come from the classified scheduler constraints (insufficient CPU or
  memory, an untolerated node taint, a node selector or affinity mismatch, an
  unbound volume claim), stated tentatively. The constraints are separate
  signals and may be present together.
- volume_mount_failure: the pod was scheduled but its containers cannot be
  created because Kubernetes records volume mount failures; no container ran.
  Never mention crashes, restarts, probes, logs or image pulls for it.
  Candidate causes are tentative, for example that a ConfigMap, Secret or
  PersistentVolumeClaim the declared volume refers to may not exist in the
  namespace, or that its name may be misspelled. Never suggest reading Secret
  values.
Event evidence gives a reason, a type, a count and, where Kubernetes' own
message was recognised, classified signals: you have no event
messages and must not guess what one said.

Reasoning rules, with common errors to avoid:
- Use Kubernetes terms exactly. Nodes have taints, labels and allocatable
  capacity; pods have tolerations and resource requests. A pod never has a
  taint and a node never tolerates anything: write "node taints the pod does
  not tolerate", never "the pod contains a taint" or "tolerations on the nodes". The scheduler compares a pod's requests (not its
  limits) with a node's allocatable capacity. Nodes belong to no namespace.
- A readiness probe only controls traffic. It never restarts a container and
  does not show that the process failed to start; only a failing liveness or
  startup probe causes a restart. Running is not ready. A past restart is
  history, not a current failure.
- Say only what the evidence establishes. ImagePullBackOff means a pull failed,
  not that the image does not exist. OOMKilled is a termination reason
  Kubernetes reports; the application did not log it. FailedScheduling is an
  event Kubernetes recorded. Attribute each statement to its source
  (Kubernetes status, Kubernetes event, application log, or your own
  interpretation), and never present an interpretation as a finding.
- Explain THIS failure. A pod that was never scheduled has no probes, logs,
  restarts or pulled image, and a container that never started has no logs or
  exit code. Name only a cause the observations report.
- Several scheduler constraints can be reported together (for example CPU,
  memory and a taint). Write one hypothesis per reported constraint, cite only
  that constraint's observations, and never call one of them the only cause.
  Do not add a constraint the signals do not report.
- "verification_check" inspects the named resource's own state to settle what
  remains unverified. Good: "Compare the taints on the nodes with the
  tolerations the pod declares." Bad: "Inspect the taints on the pod." and any
  action: "Increase the memory request", "Add a toleration", "Adjust the probe
  timing".

Each hypothesis has separate fields:
- "reported" paraphrases what an APPLICATION LOG says, and nothing else.
  * If an entry in 'untrusted_logs' bears on the hypothesis, put its log_ref
    (log-NNNN) in "evidence" and set "reported" to a brief clause completing
    "The application logs report that ..." (do not repeat the lead-in) that
    paraphrases that entry only. Do not restate it as fact.
  * If no log entry bears on the hypothesis, cite none and "reported" MUST be
    null, even when logs exist. Focus groups never contain log ids, so a
    hypothesis copied from a focus group has "reported": null.
  A "reported" value without a log-NNNN id in "evidence" is discarded together
  with the hypothesis.
  Kubernetes states, reasons, exit codes, restart counts, probe configuration
  and events (including "Liveness probe failed" and "Back-off restarting")
  are Kubernetes observations, never logs, and never go in "reported": cite
  their ev-NNNN ids and say nothing about them there. Despite its name, "reported" is not what
  Kubernetes reported.
  Wrong: "evidence": ["ev-0012"], "reported": "the container is restarting
  because the liveness probe fails". Right: "evidence": ["ev-0012"],
  "reported": null.
  If 'untrusted_logs' has no entries, "reported" MUST be null and you must not
  say or imply what any log contains.
- "possible_explanation": one or two tentative sentences. EVERY sentence must
  contain a hedge such as may, might, could, possibly or perhaps, placed
  before any "because" or "due to". Never add a sentence that only says
  something is unverified or restates what a termination "may indicate": that
  belongs in "not_yet_verified" or is already established.
- "not_yet_verified": one complete sentence saying what remains unverified,
  for example "The underlying cause has not been verified." or "The startup
  behaviour has not been inspected." Mention a logged claim only if you cite a
  log. Do not write
  a bare fragment such as "Whether ...". Never claim anything is verified.
  Use the verified configuration evidence when it is present, and cite it:
  compare it with what the logs claim (for example, whether a named
  environment variable appears among the declared names when the name list is
  complete) and with the observed exit behaviour. Say tentatively where it
  agrees, where it conflicts, and where it cannot decide the question. If the
  startup analysis shows an exit that does not depend on the environment, say
  that a changed configuration alone may not change the outcome. Environment
  values are never available, so never speculate about them.
  If configuration evidence is supplied for the resource, the configuration
  and its declarations HAVE been inspected: never say they have not been
  inspected, examined or verified. State instead what is still unestablished:
  variable values, variables supplied by other mechanisms, and whether a
  logged claim is accurate. A spec that declares no variables does not prove
  that the runtime environment is empty: never state or imply that.
- "evidence", "resource", "verification_check": a read-only check aimed at the
  actual failure category (for an image pull failure: look at the error
  Kubernetes recorded for the pull and confirm the image reference exists in
  its registry and the registry is reachable; never read Secret values).

Length limits (characters): reported {MAX_REPORTED_CHARS}, possible_explanation
{MAX_POSSIBLE_CHARS}, not_yet_verified {MAX_NOT_VERIFIED_CHARS},
verification_check {MAX_CHECK_CHARS}. Be concise; over-long hypotheses are
discarded.

Rules:
- Cite only supplied ids: ev-NNNN or log-NNNN. Never invent ids.
- Cite at most {MAX_REFERENCES} distinct ids per hypothesis: choose the few
  that matter most, and count them before answering. A probe is represented
  well enough by its 'declared', 'kind', 'path' and 'port' observations: do
  not cite every timing value. A hypothesis that cites more is discarded, never trimmed.
  'evidence_focus_groups' lists, per topic of the established failure, the
  application's selection of the most relevant ids (each group has at most
  {MAX_REFERENCES}). Support each hypothesis with the ids of ONE group, or
  with a few ids chosen from several, never more than {MAX_REFERENCES} in
  total. Do not cite everything that is related.
- All citations in one hypothesis must concern the same pod. Do not combine
  evidence from different pods.
- 'resource' is derived by the application from the ids you cite, so set it
  to null. (If you set it anyway, every non-null part must match exactly what
  your cited ids name, 'container' only when a cited field names that
  container, and a response whose 'resource' does not match is discarded as a
  whole.) Each 'evidence_focus_groups' entry states its 'pod' and 'container'
  for reference only.
- If the input contains 'correction_required', your previous response was
  discarded in full for the stated reason. Write a complete new response that
  fixes exactly that, for example by listing each cited id once.
- Do not state confidence levels or percentages.
- Do not reproduce log lines, credentials, tokens, or long log passages.
- If 'application_configuration_statements' show that the workload declares
  no environment sources, then no ConfigMap or Secret is referenced by it:
  do not suggest inspecting them, and do not mention ConfigMaps or Secrets at
  all in 'verification_check', not even as an example of where a value might
  come from. Direct 'verification_check' at how the workload is INTENDED to
  receive its configuration, for example: "Ask the workload owner how
  <setting> is meant to be supplied and review the Deployment manifest or
  deployment tooling for it." Never suggest reading Secret values, decoding
  anything, using other credentials or bypassing authorization.
- 'verification_check' must be a read-only inspection suggestion in plain
  words. No commands that change state, no shell syntax.
- Do not output findings, severities, titles, a status field, or a free-text
  'explanation' field.
- Prefer fewer, cautious hypotheses. If you cannot word one cautiously, omit
  it. If the data supports none, return an empty list.
- Return exactly one JSON object and nothing else.

Required JSON structure (placeholders only):
{{
  "investigation_id": "<copy from input>",
  "hypotheses": [
    {{
      "reported": "<what a cited log claims; null unless you cite a log-NNNN>",
      "possible_explanation": "<tentative sentence that may ...>",
      "not_yet_verified": "<what has not been verified>",
      "evidence": ["ev-0001", "ev-0002"],
      "resource": null,
      "verification_check": "<read-only inspection suggestion>"
    }}
  ]
}}
"""


def _observation(item) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "tool": item.tool,
        "field": item.field,
        "value": item.value,
        "namespace": item.namespace,
        "pod": item.pod,
    }


def _configuration_statements(data: HypothesisInput) -> list[dict[str, Any]]:
    """Per-container declared-configuration statements, written by the
    application (never by a model)."""
    pods, _ = collect_configuration(data.snapshot)
    items: list[dict[str, Any]] = []

    for (namespace, pod), config in sorted(pods.items()):
        for container in sorted(config.containers):
            context = configuration_context_for(
                data.snapshot, namespace, pod, container
            )

            if context is None or not context.text:
                continue

            items.append(
                {
                    "namespace": namespace,
                    "pod": pod,
                    "container": container,
                    "statement": context.text,
                    "evidence_ids": list(context.refs),
                }
            )

    return items[:10]


def _established_abnormality(data: HypothesisInput) -> dict[str, Any]:
    items = build_established_abnormality(data.snapshot)
    block: dict[str, Any] = {
        "trust": "written_by_the_application_from_verified_evidence",
        "items": items,
    }

    if not items:
        block["note"] = (
            "No pod or container abnormality was established from Kubernetes "
            "state. Do not propose a failure of any Kubernetes stage; explain "
            "only what a cited application log reports, otherwise return an "
            "empty list."
        )

    return block


def _scope(data: HypothesisInput) -> dict[str, Any]:
    """What was asked about and covered, written by the application. Explain
    only resources within it; never speculate about other workloads."""
    scope = data.snapshot.scope

    if scope is None:
        return {"mode": "namespace"}

    return {
        "mode": scope.mode,
        "requested_workload": scope.requested,
        "workload": scope.workload_name,
        "pods_in_scope": list(scope.pods[:20]),
    }


def _failure_classification(data: HypothesisInput) -> list[dict[str, Any]]:
    """Per-container Kubernetes health classification, application-written
    from verified observations (fixed vocabulary, no free text)."""
    items: list[dict[str, Any]] = []

    for (namespace, pod, container), assessment in sorted(
        collect_container_classifications(data.snapshot).items()
    ):
        items.append(
            {
                "namespace": namespace,
                "pod": pod,
                "container": container,
                "category": assessment.category.value,
                "kubernetes_reason": assessment.reason,
                "ever_ran": assessment.ran_before,
            }
        )

    for (namespace, pod), (assessment, _facts) in sorted(
        classify_pods(data.snapshot).items()
    ):
        items.append(
            {
                "namespace": namespace,
                "pod": pod,
                "container": None,
                "category": assessment.category.value,
                "kubernetes_reason": (
                    "Unschedulable"
                    if assessment.category.value == "unschedulable"
                    else "ContainerCreating"
                ),
                "ever_ran": False,
            }
        )

    return items[:10]


# A whole response is discarded for a few purely FORMAT mistakes that the model
# can fix. Only these get one more attempt, with a fixed notice naming the
# mistake (no model output is fed back). Anything that suggests an unknown,
# foreign or fabricated reference, a mismatched resource or a secret is never
# retried: the second attempt would be validated exactly like the first, but
# there is no reason to offer one. (A mis-copied 36-character investigation id
# is a copying slip: the model cannot know another investigation's id, and the
# retried echo must match exactly.)
RETRYABLE_CODES: dict[str, str] = {
    "duplicate_reference": (
        "An 'evidence' list named the same id more than once. List every "
        "cited id exactly once."
    ),
    "reference_count": (
        "A hypothesis had an empty 'evidence' list. Cite one to "
        f"{MAX_REFERENCES} supplied ids, or leave the hypothesis out."
    ),
    "too_many_references": (
        f"Hypotheses that cited more than {MAX_REFERENCES} ids were "
        f"discarded and nothing was left. Cite at most {MAX_REFERENCES} distinct ids per "
        "hypothesis, preferably the ids of one evidence focus group."
    ),
    "cross_investigation": (
        "'investigation_id' did not match the input. Copy the input's "
        "'investigation_id' exactly, character for character."
    ),
    "malformed_json": (
        "The response was not one complete JSON object (it may have been "
        f"cut off). Return one short, complete JSON object; cite at most "
        f"{MAX_REFERENCES} distinct ids per hypothesis."
    ),
}
MAX_ATTEMPTS = 2


def build_hypothesis_messages(
    data: HypothesisInput,
    *,
    correction: str | None = None,
) -> list[dict[str, str]]:
    """Messages with explicit provenance/trust labels. Data is JSON-encoded,
    never concatenated into instruction text."""

    payload: dict[str, Any] = {
        "investigation_id": data.snapshot.investigation_id,
        "authorized_namespace": data.authorized_namespace,
        "established_abnormality": _established_abnormality(data),
        "kubernetes_verified_observations": {
            "trust": "verified_by_application_from_authorized_read_only_tools",
            "items": [
                _observation(item)
                for item in data.snapshot.evidence
                if item.tool != WORKLOAD_CONFIG_TOOL and not is_structural(item.field)
            ],
        },
        "evidence_focus_groups": {
            "trust": "selected_by_the_application_for_relevance_only",
            "items": build_focus_groups(data.snapshot),
        },
        "verified_configuration_evidence": {
            "trust": "verified_by_application_from_authorized_read_only_tools",
            "values_are_never_included": True,
            "items": [
                _observation(item)
                for item in data.snapshot.evidence
                if item.tool == WORKLOAD_CONFIG_TOOL
            ],
        },
        "investigation_scope": _scope(data),
        "application_logs_available": bool(data.log_entries),
        # The ONLY ids that make "reported" legitimate. Focus groups hold
        # structured-observation ids and never include one.
        "log_refs_available": [entry.log_ref for entry in data.log_entries],
        "application_failure_classification": {
            "trust": "written_by_the_application_from_verified_evidence",
            "items": _failure_classification(data),
        },
        "application_configuration_statements": {
            "trust": "written_by_the_application_from_verified_evidence",
            "items": _configuration_statements(data),
        },
        **build_untrusted_log_payload(
            data.log_entries, omitted_entries=data.omitted_log_entries
        ),
    }

    if correction is not None:
        payload["correction_required"] = RETRYABLE_CODES[correction]

    return [
        {"role": "system", "content": HYPOTHESIS_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
        },
    ]


class QwenHypothesisProvider:
    """Callable: HypothesisInput -> validated, unverified hypotheses (plus the
    count omitted for insufficiently cautious wording)."""

    def __init__(
        self,
        *,
        completion: Completion | None = None,
        model: str = VLLM_MODEL,
        timeout: float = 30.0,
        # Four fully populated hypotheses (each field is bounded by the parser)
        # measured 860-900 tokens, so 900 truncated the JSON at random and the
        # whole analysis was reported as malformed. 1500 covers the bounded
        # worst case; the parser's own 8000-character cap still limits input.
        max_tokens: int = 1500,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive.")

        self._completion = (
            completion if completion is not None else client.chat.completions.create
        )
        self._model = model
        self._timeout = timeout
        self._max_tokens = max_tokens

    def __call__(self, data: HypothesisInput) -> HypothesisBatch:
        registry = HypothesisEvidenceRegistry(
            investigation_id=data.snapshot.investigation_id,
            authorized_namespace=data.authorized_namespace,
            snapshot=data.snapshot,
            log_entries=data.log_entries,
        )
        correction: str | None = None

        for attempt in range(MAX_ATTEMPTS):
            try:
                batch = self._attempt(data, registry, correction)

                # Nothing survived and some hypotheses were discarded for
                # citing too many ids (a size rule, not a provenance failure):
                # one more attempt. A response with any accepted hypothesis is
                # never retried.
                if (
                    attempt + 1 < MAX_ATTEMPTS
                    and not batch.hypotheses
                    and batch.omission_reasons.get("too_many_references")
                ):
                    correction = "too_many_references"
                    continue

                return batch
            except _RetryableFormatError as failed:
                # One more attempt, with a fixed notice naming the mistake. The
                # new response goes through exactly the same validation; if it
                # fails too, the stage is reported unavailable as before.
                if attempt + 1 >= MAX_ATTEMPTS:
                    raise failed.final from None

                correction = failed.code

        raise AssertionError("unreachable")  # pragma: no cover

    def _attempt(
        self,
        data: HypothesisInput,
        registry: HypothesisEvidenceRegistry,
        correction: str | None,
    ) -> HypothesisBatch:
        messages = build_hypothesis_messages(data, correction=correction)

        try:
            response = self._completion(
                model=self._model,
                messages=messages,
                temperature=0,
                max_tokens=self._max_tokens,
                timeout=self._timeout,
                extra_body={"chat_template_kwargs": {"enable_thinking": False}},
            )
        except Exception as exc:
            reason = (
                "timeout"
                if type(exc).__name__ in _TIMEOUT_ERROR_NAMES
                else "provider_error"
            )
            # Drop the exception chain: SDK errors can embed the request body.
            raise HypothesisGenerationError(reason) from None

        try:
            choices = response.choices

            if len(choices) != 1:
                raise ValueError

            content = choices[0].message.content

            if not isinstance(content, str):
                raise ValueError
        except Exception:
            raise HypothesisGenerationError("malformed_response") from None

        try:
            return parse_hypothesis_response(
                content,
                registry=registry,
                expected_investigation_id=data.snapshot.investigation_id,
            )
        except HypothesisValidationError as exc:
            if exc.code in {"malformed_json", "response_size"}:
                final = HypothesisGenerationError("malformed_response")
            else:
                final = HypothesisGenerationError(
                    "validation_failed", categorize_rejection(exc.code)
                )

            if exc.code in RETRYABLE_CODES and exc.code != "too_many_references":
                raise _RetryableFormatError(exc.code, final) from None

            raise final from None


class _RetryableFormatError(Exception):
    """Internal: a whole-response failure the model may fix on one more try."""

    def __init__(self, code: str, final: HypothesisGenerationError) -> None:
        super().__init__(code)
        self.code = code
        self.final = final
