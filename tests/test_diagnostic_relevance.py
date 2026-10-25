"""Diagnostic relevance and probe-evidence completeness.

Pinned here:

* the relevance corpus (`eval/diagnostic_quality/relevance_cases.json`):
  demonstrable contradictions of a completed lifecycle stage are omitted, and
  qualified, historical, rule-out or unfamiliar-but-supported statements are
  kept (false-positive rejections are the failure mode being guarded);
* `stage_consistency` and the facts the registry feeds it;
* the `established_abnormality` the model is shown;
* the readiness-probe observation (declared / verified absent / unknown), for
  a standalone Pod too, within the bounded evidence schema;
* the grader used by the benchmark, independently of the validator;
* that real log-based claims still populate `reported` and Kubernetes-only
  investigations leave it null.
"""

import json
from pathlib import Path

import pytest

from app.reports.abnormality import STAGE_MEANING, build_established_abnormality
from app.reports.evidence_focus import build_focus_groups
from app.reports.hypotheses import (
    MAX_REFERENCES,
    HypothesisEvidenceRegistry,
    HypothesisInput,
    HypothesisToneError,
    validate_hypothesis_fields,
)
from app.reports.probe_declarations import (
    describe_pod_probe,
    describe_readiness,
    readiness_declared,
)
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT, build_hypothesis_messages
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.stage_consistency import CONTRADICTS_EVIDENCE, StageFacts, stage_violation
from app.tools.observations import MAX_DESCRIBE_OBSERVATIONS, MAX_SPEC_OBSERVATIONS
from eval.diagnostic_quality import relevance_rubric
from eval.diagnostic_quality.scenarios import ALL_SCENARIOS, NS, build_cluster
from tests.pod_scenarios import (
    Cluster,
    container_spec,
    container_status,
    event,
    http_probe,
    investigate,
    ns,
    pod,
)

CORPUS = json.loads(
    (Path(__file__).parent.parent / "eval/diagnostic_quality/relevance_cases.json").read_text()
)
CASES = CORPUS["cases"]
NOT_VERIFIED = "It has not been verified whether this is the cause."
CHECK = "Review the pod's events and status (read-only)."
_BUILT: dict[str, tuple] = {}


def built(scenario_id: str):
    if scenario_id not in _BUILT:
        ctx, snapshot, _, _ = investigate(build_cluster(scenario_id))
        registry = HypothesisEvidenceRegistry(
            investigation_id=ctx.investigation_id,
            authorized_namespace=NS,
            snapshot=snapshot,
            log_entries=ctx.log_entries,
        )
        _BUILT[scenario_id] = (ctx, snapshot, registry)

    return _BUILT[scenario_id]


def cited(snapshot) -> list[str]:
    """What a model would cite: the first focus group, or the first few
    observations of a pod that has none."""
    groups = build_focus_groups(snapshot)

    if groups:
        return groups[0]["evidence_ids"][:MAX_REFERENCES]

    return [item.evidence_id for item in snapshot.evidence][:3]


def validate(scenario_id: str, possible: str):
    _, snapshot, registry = built(scenario_id)

    return validate_hypothesis_fields(
        reported=None,
        possible_explanation=possible,
        not_yet_verified=NOT_VERIFIED,
        evidence=cited(snapshot),
        declared_resource=None,
        verification_check=CHECK,
        registry=registry,
    )


# ======================================================= the relevance corpus


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_relevance_corpus(case):
    expect = case["expect"]

    if expect == "accept":
        hypothesis = validate(case["scenario"], case["possible"])

        assert hypothesis.possible_explanation == case["possible"]
        assert hypothesis.check_withheld_reason is None
    else:
        with pytest.raises(HypothesisToneError) as raised:
            validate(case["scenario"], case["possible"])

        if ":" in expect:
            assert raised.value.code == expect.split(":", 1)[1]


def test_corpus_scenarios_exist_and_both_outcomes_are_covered():
    assert {c["scenario"] for c in CASES} <= {s.id for s in ALL_SCENARIOS}
    assert sum(c["expect"] == "accept" for c in CASES) >= 10
    assert sum(c["expect"] != "accept" for c in CASES) >= 10


def test_a_relevant_but_unverified_statement_is_never_rewritten():
    case = next(c for c in CASES if c["id"] == "rel_sole_oom_memory_leak_is_accepted")

    assert validate(case["scenario"], case["possible"]).possible_explanation == case["possible"]


# ====================================================== stage_consistency unit

SCHEDULED = StageFacts(scheduled=True)
PENDING = StageFacts(scheduled=False)
SCHEDULED_WITH_HISTORY = StageFacts(scheduled=True, scheduling_history=True)
SOLE_OOM = StageFacts(sole_restart_was_oom=True)


def stage(text, facts):
    return stage_violation((text,), facts)


@pytest.mark.parametrize(
    "text",
    [
        "The pod cannot be scheduled because of insufficient memory.",
        "The pod may be unschedulable due to a node taint.",
        "The scheduler may not be able to place the pod.",
        "The pod is not schedulable on any node.",
    ],
)
def test_a_scheduled_pod_called_unschedulable_is_contradicted(text):
    assert stage(text, SCHEDULED) == CONTRADICTS_EVIDENCE


@pytest.mark.parametrize(
    "text",
    [
        "The pod cannot be scheduled because of insufficient memory.",
        "The pod may be unschedulable due to a node taint.",
    ],
)
def test_the_same_claim_is_not_contradicted_without_the_established_stage(text):
    assert stage(text, PENDING) is None
    assert stage(text, StageFacts()) is None


@pytest.mark.parametrize(
    "text",
    [
        "The pod was briefly unschedulable earlier but is running on a node now.",
        "The pod has been scheduled; scheduling is not the problem.",
        "Scheduling constraints are unlikely to explain this, since the pod is placed.",
        "The pod is not unschedulable; the image pull fails.",
        'The event said "pod cannot be scheduled" but the pod now has a node.',
    ],
)
def test_qualified_historical_and_denied_wording_about_a_scheduled_pod_passes(text):
    assert stage(text, SCHEDULED) is None


def test_a_recorded_scheduling_history_makes_the_statement_a_fact():
    text = "The pod may have been unschedulable at first because of insufficient CPU."

    assert stage(text, SCHEDULED_WITH_HISTORY) is None
    assert stage("The pod cannot be scheduled.", SCHEDULED_WITH_HISTORY) is None


@pytest.mark.parametrize(
    "text",
    [
        "The container's entrypoint command may be wrong.",
        "The liveness probe may have killed the container.",
        "The image may be incompatible with the node.",
        "An unhandled exception in the application may have crashed it.",
    ],
)
def test_the_sole_oom_restart_blamed_on_a_non_memory_mechanism_is_contradicted(text):
    assert stage(text, SOLE_OOM) == CONTRADICTS_EVIDENCE
    assert stage(text, StageFacts()) is None


@pytest.mark.parametrize(
    "text",
    [
        "A memory leak in the application may have exhausted the memory limit.",
        "The application's unhandled exception handling may have buffered data until the memory limit was reached.",
        "The entrypoint is not the cause; the termination was an out-of-memory kill.",
        "The container may have been OOMKilled.",
    ],
)
def test_memory_linked_and_ruled_out_wording_is_not_contradicted(text):
    assert stage(text, SOLE_OOM) is None


# ==================================================== facts the registry feeds


def stage_facts(scenario_id, pod_name, container="app"):
    _, _, registry = built(scenario_id)

    return registry.stage_facts(pod_name, container)


def test_stage_facts_for_a_scheduled_image_pull_pod():
    facts = stage_facts("image_pull", "pull")

    assert facts.scheduled is True
    assert facts.scheduling_history is False
    assert facts.sole_restart_was_oom is False


def test_stage_facts_for_an_unschedulable_pod_are_not_scheduled():
    facts = stage_facts("sched_cpu", "cpu-hog")

    assert facts.scheduled is False
    assert facts.scheduling_history is True


def test_stage_facts_for_a_single_oom_restart_versus_repeated_ones():
    assert stage_facts("oom_recovered", "recovered").sole_restart_was_oom is True
    # Four restarts: only the latest termination is visible, earlier ones open.
    assert stage_facts("oom_killed", "oom").sole_restart_was_oom is False
    # One restart whose reason was not OOMKilled.
    assert stage_facts("liveness_failure", "live").sole_restart_was_oom is False
    assert stage_facts("healthy", "fine").sole_restart_was_oom is False


def test_a_scheduled_pod_with_a_recorded_failed_scheduling_event_has_history():
    name = "late"
    cluster = Cluster(
        [
            pod(
                name,
                scheduled=("True", None),
                statuses=[container_status(reason="ImagePullBackOff", restarts=0)],
                age=600,
            )
        ],
        {
            name: [
                event(
                    pod_name=name,
                    reason="FailedScheduling",
                    message="0/1 nodes are available: 1 Insufficient cpu.",
                    component="default-scheduler",
                )
            ]
        },
    )
    ctx, snapshot, _, _ = investigate(cluster)
    registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )
    facts = registry.stage_facts(name, "app")

    assert facts.scheduled is True and facts.scheduling_history is True
    # The history is recorded, so a statement about it is not contradicted.
    assert validate_hypothesis_fields(
        reported=None,
        possible_explanation="The pod may have been unschedulable earlier because of insufficient CPU.",
        not_yet_verified=NOT_VERIFIED,
        evidence=cited(snapshot),
        declared_resource=None,
        verification_check=CHECK,
        registry=registry,
    )


# ============================================= established_abnormality payload


def abnormality(scenario_id):
    return build_established_abnormality(built(scenario_id)[1])


@pytest.mark.parametrize(
    "scenario_id, stage_name",
    [
        ("sched_cpu", "scheduling"),
        ("mount_failure", "volume_mount"),
        ("image_pull", "image_pull"),
        ("oom_killed", "container_runtime"),
        ("crash_loop", "container_runtime"),
        ("running_not_ready", "readiness"),
        ("liveness_failure", "past_restart"),
        ("restart_history", "past_restart"),
        ("oom_recovered", "past_restart"),
    ],
)
def test_the_abnormal_stage_is_derived_from_the_established_state(scenario_id, stage_name):
    items = abnormality(scenario_id)

    assert [i["abnormal_stage"] for i in items] == [stage_name]
    assert items[0]["what_it_establishes"] and items[0]["open_question"]


def test_a_healthy_pod_has_no_established_abnormality():
    assert abnormality("healthy") == []


def test_a_scheduled_pod_lists_scheduling_as_completed_and_never_as_abnormal():
    item = abnormality("image_pull")[0]

    assert item["abnormal_stage"] == "image_pull"
    assert {"stage": "scheduling", "statement": "the pod was scheduled to a node"} in item[
        "completed_stages"
    ]
    assert "scheduler_reported_constraints" not in item


def test_an_unschedulable_pod_lists_what_the_scheduler_reported_and_absent_placement():
    item = abnormality("sched_taint")[0]

    assert item["abnormal_stage"] == "scheduling"
    assert "untolerated_taint" in " ".join(item["scheduler_reported_constraints"]) or item[
        "scheduler_reported_constraints"
    ]
    absent = {entry["item"] for entry in item["verified_not_declared"]}

    assert absent == {"node_selector", "affinity"}


def test_a_recovered_oom_names_its_termination_meaning_and_not_its_cause():
    item = abnormality("oom_recovered")[0]

    assert item["previous_termination"] == {"reason": "OOMKilled", "exit_code": 137}
    assert "memory event" in item["previous_termination_means"]
    assert item["restart_count"] == 1
    # Probes are verified absent for this container: listed so none is blamed.
    assert {e["item"] for e in item["verified_not_declared"]} == {
        "liveness_probe",
        "readiness_probe",
    }


def test_a_declared_probe_is_never_listed_as_verified_absent():
    items = abnormality("running_not_ready")

    assert items[0]["verified_not_declared"] == [{"item": "liveness_probe"}]


def test_a_probe_is_not_listed_for_a_container_that_never_ran():
    assert abnormality("image_pull")[0]["verified_not_declared"] == []


def test_abnormality_items_carry_no_evidence_ids_and_stay_bounded():
    for scenario in ALL_SCENARIOS:
        dumped = json.dumps(abnormality(scenario.id))

        assert "ev-" not in dumped
        assert len(abnormality(scenario.id)) <= 10


def test_the_completed_meaning_does_not_claim_a_restart_policy():
    meaning = abnormality("restart_history")[0]["previous_termination_means"]

    assert "restart policy" in meaning and "not observed" in meaning


def _payload(scenario_id):
    ctx, snapshot, _ = built(scenario_id)
    data = HypothesisInput(
        snapshot=snapshot,
        log_entries=ctx.log_entries,
        omitted_log_entries=ctx.log_entries_omitted,
        authorized_namespace=NS,
    )

    return json.loads(build_hypothesis_messages(data)[1]["content"])


def test_the_payload_places_the_abnormality_before_the_observations():
    body = _payload("oom_recovered")

    assert list(body).index("established_abnormality") < list(body).index(
        "kubernetes_verified_observations"
    )
    assert body["established_abnormality"]["trust"] == (
        "written_by_the_application_from_verified_evidence"
    )
    assert body["established_abnormality"]["items"][0]["abnormal_stage"] == "past_restart"
    assert "note" not in body["established_abnormality"]


def test_an_empty_abnormality_tells_the_model_not_to_invent_a_failure():
    block = _payload("healthy")["established_abnormality"]

    assert block["items"] == []
    assert "No pod or container abnormality was established" in block["note"]


def test_the_prompt_keeps_the_relevance_rules_and_does_not_hardcode_a_cause():
    assert "established_abnormality" in HYPOTHESIS_SYSTEM_PROMPT
    assert "verified_not_declared" in HYPOTHESIS_SYSTEM_PROMPT
    assert "do not pad" in HYPOTHESIS_SYSTEM_PROMPT.lower()
    assert "unfamiliar" in HYPOTHESIS_SYSTEM_PROMPT.lower()
    # The payload says what is established, never which cause to propose.
    for meaning in STAGE_MEANING.values():
        assert "because" not in meaning.lower()


# ============================== readiness-probe observation: declared / absent / unknown
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus  # noqa: E402
from app.tools.observations import observations_from_execution  # noqa: E402
from app.reports.state_consistency import ProbeState, probe_state  # noqa: E402
from tests.pod_scenarios import fields  # noqa: E402


def probe_fields(scenario_id):
    ctx, _, _ = built(scenario_id)

    return {k: v for k, v in fields(ctx, "k8s.describe_pod").items() if "_probe." in k}


def test_a_standalone_pod_declaring_a_readiness_probe_is_observed_from_its_own_spec():
    observed = probe_fields("running_not_ready")

    assert observed["containers[app].readiness_probe.declared"] is True
    assert observed["containers[app].readiness_probe.kind"] == "http"
    assert observed["containers[app].readiness_probe.path"] == "/ready"
    assert observed["containers[app].readiness_probe.port"] == 8080
    # The liveness probe is a separate declaration, here verified absent.
    assert observed["containers[app].liveness_probe.declared"] is False


def test_a_standalone_pod_declaring_no_readiness_probe_is_verified_absent():
    observed = probe_fields("crash_loop")

    assert observed == {
        "containers[app].liveness_probe.declared": False,
        "containers[app].readiness_probe.declared": False,
    }


def test_both_probes_are_read_for_a_pod_that_declares_a_liveness_probe_only():
    observed = probe_fields("liveness_failure")

    assert observed["containers[app].liveness_probe.declared"] is True
    assert observed["containers[app].liveness_probe.path"] == "/healthz"
    assert observed["containers[app].readiness_probe.declared"] is False


def _without_readiness(snapshot: InvestigationEvidenceSnapshot) -> InvestigationEvidenceSnapshot:
    return snapshot.model_copy(
        update={
            "evidence": [i for i in snapshot.evidence if "readiness_probe." not in i.field]
        }
    )


def test_a_readiness_probe_that_was_not_observed_is_unknown_and_never_absent():
    _, snapshot, _ = built("crash_loop")
    key = (NS, "loop")

    assert readiness_declared(snapshot, key, "app") is False
    assert describe_readiness(snapshot, key, "app")[0] == "declares no readiness probe"

    unknown = _without_readiness(snapshot)

    assert readiness_declared(unknown, key, "app") is None
    assert describe_readiness(unknown, key, "app") is None
    assert describe_pod_probe(unknown, key, "app", "readiness") is None
    assert probe_state(readiness_declared(unknown, key, "app")) is ProbeState.UNKNOWN


def test_an_unknown_probe_is_not_listed_as_verified_absent_in_the_abnormality():
    _, snapshot, _ = built("crash_loop")
    listed = {
        e["item"]
        for i in build_established_abnormality(_without_readiness(snapshot))
        for e in i["verified_not_declared"]
    }

    assert listed == {"liveness_probe"}


def test_a_readiness_blame_is_rejected_only_when_absence_was_verified():
    text = "The readiness probe may be failing, which could explain why the container is not ready."
    _, snapshot, registry = built("crash_loop")

    with pytest.raises(HypothesisToneError):
        validate("crash_loop", text)

    # The same claim about a pod whose probe was not observed is not rejected:
    # nothing contradicts it.
    unknown = _without_readiness(snapshot)
    ctx, _, _ = built("crash_loop")
    unknown_registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=unknown,
        log_entries=ctx.log_entries,
    )

    assert validate_hypothesis_fields(
        reported=None,
        possible_explanation=text,
        not_yet_verified=NOT_VERIFIED,
        evidence=cited(unknown),
        declared_resource=None,
        verification_check=CHECK,
        registry=unknown_registry,
    )


def pod_output(containers, **extra):
    return {"namespace": NS, "name": "p", "phase": "Running", "containers": containers, **extra}


def observe(output):
    call = ToolCall(name="k8s.describe_pod", arguments={"namespace": NS, "pod": "p"})
    result = ToolExecutionResult(
        tool="k8s.describe_pod", status=ToolExecutionStatus.SUCCESS, output=output
    )

    return observations_from_execution(request_id="r", call=call, result=result)


def container(name, readiness=None, liveness=None):
    declared = {}

    if readiness is not None:
        declared["readiness_probe"] = readiness
    if liveness is not None:
        declared["liveness_probe"] = liveness

    return {"name": name, "ready": True, "restart_count": 0, "state": "running",
            "declared": declared}


def test_a_probe_declaration_that_was_not_read_produces_no_observation():
    values = {o.field: o.value for o in observe(pod_output([container("app")]))}

    assert not [f for f in values if "_probe" in f]
    # A malformed declared flag is not evidence either.
    values = {
        o.field: o.value
        for o in observe(pod_output([container("app", readiness={"declared": "yes"})]))
    }

    assert not [f for f in values if "_probe" in f]


def test_probe_observations_carry_only_the_bounded_fields():
    probe = {
        "declared": True, "kind": "http", "port": 8080, "path": "/ready",
        "period_seconds": 5, "failure_threshold": 3,
        # none of these may ever become evidence
        "headers": [{"name": "Authorization", "value": "Bearer SECRET"}],
        "command": ["sh", "-c", "SECRET"], "host": "internal.example",
    }
    observed = observe(pod_output([container("app", readiness=probe)]))
    values = {o.field: o.value for o in observed}

    assert values["containers[app].readiness_probe.path"] == "/ready"
    assert "SECRET" not in json.dumps(values) and "internal.example" not in json.dumps(values)
    assert {f.rsplit(".", 1)[1] for f in values if "readiness_probe" in f} == {
        "declared", "kind", "port", "path", "period_seconds", "failure_threshold",
    }


@pytest.mark.parametrize("path", ["/ready?token=abc", "/a b", "javascript:alert(1)", "x" * 400])
def test_an_unsafe_probe_path_is_omitted_not_truncated(path):
    values = {
        o.field: o.value
        for o in observe(
            pod_output([container("app", readiness={"declared": True, "kind": "http", "path": path})])
        )
    }

    assert values["containers[app].readiness_probe.declared"] is True
    assert "containers[app].readiness_probe.path" not in values


def test_a_pod_with_many_containers_stays_inside_the_bounded_evidence_schema():
    probe = {"declared": True, "kind": "http", "port": 80, "path": "/r",
             "initial_delay_seconds": 1, "period_seconds": 2, "timeout_seconds": 3,
             "failure_threshold": 4}
    containers = [container(f"c{n}", readiness=probe, liveness=probe) for n in range(12)]
    observed = observe(pod_output(containers))
    probes = [o for o in observed if "_probe." in o.field]

    assert probes
    # The whole observation set stays inside the bounded schema; only the first
    # containers are read, and each is read from its first probe field on, so a
    # truncated container is UNKNOWN, never mistaken for "absent".
    assert len(observed) <= MAX_DESCRIBE_OBSERVATIONS + 8 + MAX_SPEC_OBSERVATIONS
    assert not any(
        o.field.startswith("containers[c10]") or o.field.startswith("containers[c11]")
        for o in observed
    )
    assert any(o.field == "containers[c0].readiness_probe.declared" and o.value is True
               for o in observed)
    assert not any(o.field.endswith(".declared") and o.value is False for o in probes)


def test_an_exec_probe_is_observed_by_kind_only_for_a_standalone_pod():
    exec_probe = ns(
        http_get=None, tcp_socket=None, grpc=None,
        _exec=ns(command=["sh", "-c", "echo TOPSECRET"]),
        period_seconds=10, timeout_seconds=1, failure_threshold=3, initial_delay_seconds=0,
    )
    spec = container_spec("app")
    spec.readiness_probe = exec_probe
    name = "execpod"
    cluster = Cluster(
        [pod(name, phase="Running", scheduled=("True", None),
             statuses=[container_status(ready=False, state="running", reason=None)],
             containers=[spec], age=900)],
        {name: []},
    )
    ctx, snapshot, _, _ = investigate(cluster)
    values = fields(ctx, "k8s.describe_pod")

    assert values["containers[app].readiness_probe.declared"] is True
    assert values["containers[app].readiness_probe.kind"] == "exec"
    assert "TOPSECRET" not in json.dumps(values)
    assert "TOPSECRET" not in snapshot.model_dump_json()
    assert describe_readiness(snapshot, (NS, name), "app")[0].startswith(
        "declares a readiness probe"
    )


# ================================ Phase 5: real log-based diagnosis is preserved
from app.reports.hypotheses import HypothesisValidationError, parse_hypothesis_response  # noqa: E402
from app.reports.snapshot import build_investigation_evidence_snapshot  # noqa: E402
from tests.test_ai_hypotheses import (  # noqa: E402
    CHECK as LOG_CHECK,
    NOT_VERIFIED as LOG_NOT_VERIFIED,
    POD as LOG_POD,
    POSSIBLE as LOG_POSSIBLE,
    REPORTED as LOG_REPORTED,
    build_context,
)


def log_case():
    ctx = build_context()
    snapshot = build_investigation_evidence_snapshot(ctx)
    registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )

    return ctx, snapshot, registry


def log_item(snapshot, *, reported, evidence):
    return {
        "reported": reported,
        "possible_explanation": LOG_POSSIBLE,
        "not_yet_verified": LOG_NOT_VERIFIED,
        "evidence": evidence,
        "resource": {"namespace": NS, "pod": LOG_POD, "container": "app"},
        "verification_check": LOG_CHECK,
    }


def parse_items(ctx, registry, *items):
    return parse_hypothesis_response(
        json.dumps({"investigation_id": ctx.investigation_id, "hypotheses": list(items)}),
        registry=registry,
        expected_investigation_id=ctx.investigation_id,
    )


def test_a_supported_application_log_claim_still_populates_reported():
    ctx, snapshot, registry = log_case()
    state = next(i.evidence_id for i in snapshot.evidence if i.field.endswith(".reason"))
    batch = parse_items(
        ctx, registry, log_item(snapshot, reported=LOG_REPORTED, evidence=[state, "log-0001"])
    )

    assert len(batch.hypotheses) == 1
    assert batch.hypotheses[0].reported == LOG_REPORTED
    assert "log-0001" in batch.hypotheses[0].evidence_refs


def test_a_kubernetes_only_investigation_leaves_reported_null():
    ctx, snapshot, registry = built("liveness_failure")
    group_ids = build_focus_groups(snapshot)[0]["evidence_ids"]
    item = {
        "reported": None,
        "possible_explanation": "The liveness probe may be failing, which could explain the restarts.",
        "not_yet_verified": LOG_NOT_VERIFIED,
        "evidence": group_ids,
        "resource": {"namespace": NS, "pod": "live", "container": "app"},
        "verification_check": LOG_CHECK,
    }
    batch = parse_items(ctx, registry, item)

    assert batch.hypotheses and batch.hypotheses[0].reported is None
    assert not [r for r in batch.hypotheses[0].evidence_refs if r.startswith("log-")]


def test_a_reported_claim_without_a_cited_log_is_still_omitted_and_never_rewritten():
    ctx, snapshot, registry = built("liveness_failure")
    item = {
        "reported": "the container keeps failing its health check",
        "possible_explanation": "The liveness probe may be failing, which could explain the restarts.",
        "not_yet_verified": LOG_NOT_VERIFIED,
        "evidence": build_focus_groups(snapshot)[0]["evidence_ids"],
        "resource": {"namespace": NS, "pod": "live", "container": "app"},
        "verification_check": LOG_CHECK,
    }
    batch = parse_items(ctx, registry, item)

    assert not batch.hypotheses
    assert batch.omission_reasons == {"reported_without_log_evidence": 1}


def test_a_log_claim_on_kubernetes_state_is_still_a_misattribution():
    ctx, snapshot, registry = log_case()
    state = next(i.evidence_id for i in snapshot.evidence if i.field.endswith(".reason"))
    batch = parse_items(
        ctx, registry,
        log_item(snapshot, reported="the container is in CrashLoopBackOff", evidence=[state, "log-0001"]),
    )

    assert not batch.hypotheses
    assert batch.omission_reasons == {"misattributed_source": 1}


def test_an_unknown_log_reference_still_rejects_the_whole_response():
    ctx, snapshot, registry = log_case()

    with pytest.raises(HypothesisValidationError):
        parse_items(ctx, registry, log_item(snapshot, reported=LOG_REPORTED, evidence=["log-0099"]))


def test_the_six_reference_limit_is_intact_with_the_new_payload():
    ctx, snapshot, registry = built("oom_killed")
    refs = [i.evidence_id for i in snapshot.evidence][: MAX_REFERENCES + 1]
    item = {
        "reported": None,
        "possible_explanation": "The container may have exceeded its memory limit, which could explain the kills.",
        "not_yet_verified": LOG_NOT_VERIFIED,
        "evidence": refs,
        "resource": {"namespace": NS, "pod": "oom", "container": "app"},
        "verification_check": LOG_CHECK,
    }
    batch = parse_items(ctx, registry, item)

    assert len(refs) == MAX_REFERENCES + 1 and not batch.hypotheses
    assert batch.omission_reasons == {"too_many_references": 1}


def test_the_log_payload_keeps_logs_separate_from_the_application_written_abnormality():
    ctx, snapshot, _ = log_case()
    data = HypothesisInput(
        snapshot=snapshot, log_entries=ctx.log_entries,
        omitted_log_entries=ctx.log_entries_omitted, authorized_namespace=NS,
    )
    body = json.loads(build_hypothesis_messages(data)[1]["content"])

    assert body["log_refs_available"] == [e["log_ref"] for e in body["untrusted_logs"]] != []
    # The abnormality is application-written Kubernetes state: no log text, no log ids.
    abnormality_text = json.dumps(body["established_abnormality"])

    assert "log-" not in abnormality_text
    assert all(line not in abnormality_text for line in ("cache layer", "handshake"))
    assert body["established_abnormality"]["items"][0]["abnormal_stage"] == "container_runtime"
    # A readiness probe that was never observed is not claimed absent.
    assert body["established_abnormality"]["items"][0]["verified_not_declared"] == []


# ===================================================== the benchmark's own grader

REVIEWED = [
    ("image_pull", "The pod may not be schedulable due to insufficient node capacity.", "irrelevant"),
    ("image_pull", "The image tag may not exist in the registry, so the pull fails.", "relevant"),
    ("oom_recovered", "The entrypoint command may be incorrect.", "irrelevant"),
    ("oom_recovered", "The container may have exceeded its memory limit and been OOMKilled.", "relevant"),
    ("crash_loop", "The readiness probe may be failing.", "irrelevant"),
    ("running_not_ready", "The readiness probe may be failing on /ready.", "relevant"),
    ("sched_taint", "A node taint that the pod does not tolerate may block scheduling.", "relevant"),
    ("sched_taint", "Insufficient CPU on every node may block scheduling.", "irrelevant"),
    ("restart_history", "The container may have exited normally and been restarted by its restart policy.", "relevant"),
]


@pytest.mark.parametrize("scenario, text, label", REVIEWED, ids=lambda v: str(v)[:40])
def test_the_relevance_grader_agrees_with_the_hand_labelled_examples(scenario, text, label):
    assert relevance_rubric.classify(scenario, text)["label"] == label


def test_the_grader_does_not_count_a_scheduled_event_as_a_scheduling_failure():
    text = "The container may have been restarted by a scheduled maintenance event, even though it completed."

    assert "scheduling" not in relevance_rubric.classify("restart_history", text)["off_stage"]


# ============ a condition in time is not a claim that the container is ready now
from app.reports.state_consistency import ContainerFacts, state_violation  # noqa: E402

NOT_READY_NOW = ContainerFacts(
    running=True, not_ready=True, event_reasons=frozenset({"Unhealthy"}),
    readiness_probe_declared=True, env_none_declared=False, ran_before=True,
)


@pytest.mark.parametrize(
    "text",
    [
        "The readiness probe may start checking the endpoint before the application is ready.",
        "The container may take time to start, and the pod is only marked ready once the application is healthy.",
        "The probe may fail until the application is ready to serve traffic.",
    ],
)
def test_a_temporal_condition_is_not_a_claim_the_container_is_ready(text):
    assert state_violation((text,), [NOT_READY_NOW], cites_logs=False) is None


@pytest.mark.parametrize(
    "text",
    [
        "The container is ready and healthy, so the probe may be misreporting.",
        "The application is ready, which could explain why traffic is served.",
    ],
)
def test_claiming_a_not_ready_container_is_ready_is_still_contradicted(text):
    assert state_violation((text,), [NOT_READY_NOW], cites_logs=False) is not None


@pytest.mark.parametrize(
    "text",
    [
        "The failure may be due to the pod's scheduling or resource constraints.",
        "The container may have restarted because of a scheduling or resource allocation issue.",
    ],
)
def test_a_compound_scheduling_claim_about_a_scheduled_pod_is_contradicted(text):
    assert stage(text, SCHEDULED) == CONTRADICTS_EVIDENCE
    assert stage(text, PENDING) is None


# ================================================== the independent hand review
REVIEW = json.loads(
    (Path(__file__).parent.parent / "eval/diagnostic_quality/relevance_review.json").read_text()
)


def test_the_grader_never_calls_a_hand_labelled_relevant_hypothesis_irrelevant():
    wrong = [
        e for e in REVIEW["accepted_sample"]
        if e["label"] == "relevant"
        and relevance_rubric.classify(e["scenario"], e["text"])["label"] == "irrelevant"
    ]

    assert wrong == []


def test_the_grader_finds_every_hand_labelled_irrelevant_hypothesis():
    missed = [
        e for e in REVIEW["accepted_sample"]
        if e["label"] == "irrelevant"
        and relevance_rubric.classify(e["scenario"], e["text"])["label"] != "irrelevant"
    ]

    assert missed == [] and any(e["label"] == "irrelevant" for e in REVIEW["accepted_sample"])


def test_the_grader_only_confuses_generic_with_relevant_not_relevant_with_irrelevant():
    agreement = relevance_rubric.review_agreement(REVIEW["accepted_sample"])

    assert agreement["rate"] >= 0.75
    for d in agreement["disagreements"]:
        assert {d["label"], d["graded"]} != {"relevant", "irrelevant"}


def test_no_rejected_hypothesis_was_judged_a_content_false_positive_by_hand():
    verdicts = [r["hand_verdict"] for r in REVIEW["rejected"]]

    assert verdicts and all(v.startswith(("correct", "form only")) for v in verdicts)


# ===== a log body the client returned as the repr of bytes is the real log text
from types import SimpleNamespace  # noqa: E402
from unittest.mock import patch  # noqa: E402

from app.tools.handlers import _read_logs  # noqa: E402


def read(body):
    arguments = SimpleNamespace(namespace=NS, pod="p", container="app", tail=20)
    api = SimpleNamespace(read_namespaced_pod_log=lambda **kw: body)

    with patch("app.tools.handlers.core_v1", return_value=api):
        return _read_logs(arguments, previous=False)["logs"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("b'starting\\n'", "starting\n"),
        ('b"two\\nlines\\n"', "two\nlines\n"),
        ("b'caf\\xc3\\xa9'", "café"),
        ("  b'padded'  ", "padded"),
    ],
)
def test_a_log_body_that_is_one_bytes_literal_is_decoded(body, expected):
    assert read(body) == expected


@pytest.mark.parametrize(
    "body",
    [
        "plain application output",
        "value b'' seen",
        "b'one' and 'two'",
        "b'unterminated",
        "bytes(b'x')",
        "b'a' + b'b'",
        "line1\nb'starting\\n'",
    ],
)
def test_real_log_text_that_is_not_one_bytes_literal_is_never_rewritten(body):
    assert read(body) == body


def test_an_empty_log_stays_empty():
    assert read("b''") == "" and read(b"") == ""


# ====== a request called "not sufficient" is blamed for an OOM kill, not excused
from app.reports.technical_consistency import (  # noqa: E402
    INCORRECT_SEMANTICS,
    TechnicalFacts,
    technical_violation,
)


def tech(text):
    return technical_violation((text,), TechnicalFacts(authorized_namespace=NS), cites_logs=True)


@pytest.mark.parametrize(
    "text",
    [
        "The container may have been running with a memory request of 16Mi, which may not have been sufficient for the workload, leading to an OOMKilled termination.",
        "A memory request that isn't enough may be causing the OOMKilled terminations.",
    ],
)
def test_a_request_called_insufficient_is_still_blamed_for_the_oom_kill(text):
    assert tech(text) == INCORRECT_SEMANTICS


@pytest.mark.parametrize(
    "text",
    [
        "The OOMKilled terminations are not caused by the memory request.",
        "The memory request is 16Mi and the limit is 32Mi, which may not be sufficient, leading to an OOMKilled termination.",
        "The memory limit may not be sufficient, leading to an OOMKilled termination.",
        "Whether the memory request is related to the OOMKilled state is not established.",
    ],
)
def test_denials_and_limit_wording_still_pass_the_request_rule(text):
    assert tech(text) is None
