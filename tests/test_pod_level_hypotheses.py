"""Hypothesis handling for pod-level failures and focused evidence selection.

Pod-level state is established by the application. A hypothesis may interpret
possible causes, but it must not contradict that state, must not cite events
that were not tied to the pod, and should be supportable by one focus group of
at most MAX_REFERENCES ids. Focus selection grants no trust.
"""

import json

import pytest

from app.reports.evidence_focus import MAX_GROUPS, STRUCTURAL_FIELDS, build_focus_groups, is_structural
from app.reports.hypotheses import (
    MAX_REFERENCES,
    HypothesisEvidenceRegistry,
    HypothesisInput,
    HypothesisValidationError,
    parse_hypothesis_response,
)
from app.reports.hypothesis_ranking import rank_hypotheses
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT, build_hypothesis_messages
from app.reports.state_consistency import PodState, pod_state_violation
from tests.pod_scenarios import NS, OTHER_UID, Cluster, container_spec, event, investigate, pod
from tests.test_pod_level_health import (
    SCHED_MESSAGE,
    mount_failure,
    restarted,
    unschedulable,
)

CHECK = "Review the pod's declared requirements through read-only describe output."
NOT_VERIFIED = "The underlying cause has not been verified."
SCHEDULING_CAUSE = (
    "The requested memory may exceed what any node can offer, which could "
    "explain why the pod is Pending."
)
OFF_TOPIC = (
    "A network policy may be blocking traffic to the pod, which could "
    "explain the problem."
)
IMAGE_PULL = (
    "The image may not be pullable from the registry, which could explain "
    "why the pod is stuck."
)
CRASH = "The container may be crashing repeatedly, which could explain the failure."
LIVENESS_CLAIM = (
    "The liveness probe may be failing because its path is wrong, which could "
    "explain the restarts."
)
MOUNT_CAUSE = (
    "A ConfigMap referenced by the volume may not exist in the namespace, "
    "which could explain the mount failure."
)


def build(cluster):
    ctx, snapshot, report, _ = investigate(cluster)
    registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )

    return ctx, snapshot, registry


def response(ctx, *items):
    return json.dumps({"investigation_id": ctx.investigation_id, "hypotheses": list(items)})


def hyp(pod_name, evidence, possible, *, container=None):
    return {
        "reported": None,
        "possible_explanation": possible,
        "not_yet_verified": NOT_VERIFIED,
        "evidence": evidence,
        "resource": {"namespace": NS, "pod": pod_name, "container": container},
        "verification_check": CHECK,
    }


def parse(ctx, registry, *items):
    return parse_hypothesis_response(
        response(ctx, *items), registry=registry, expected_investigation_id=ctx.investigation_id
    )


def group(snapshot, focus):
    return next(g for g in build_focus_groups(snapshot) if g["focus"] == focus)


# ============================================================== focus groups


@pytest.mark.parametrize(
    "cluster",
    [unschedulable(), mount_failure(), restarted(), restarted(ready=False)],
    ids=["unschedulable", "mount", "restarted", "not-ready"],
)
def test_every_focus_group_is_bounded_same_pod_and_made_of_existing_ids(cluster):
    _, snapshot, _ = build(cluster)
    groups = build_focus_groups(snapshot)
    by_id = {item.evidence_id: item for item in snapshot.evidence}

    assert groups and len(groups) <= MAX_GROUPS

    for entry in groups:
        ids = entry["evidence_ids"]

        assert 1 <= len(ids) <= MAX_REFERENCES == 6
        assert len(set(ids)) == len(ids)
        assert all(i in by_id for i in ids)
        assert all(by_id[i].pod == entry["pod"] for i in ids)


def test_a_focus_group_alone_supports_a_valid_hypothesis_within_the_limit():
    ctx, snapshot, registry = build(unschedulable())
    ids = group(snapshot, "scheduling_status")["evidence_ids"]

    batch = parse(ctx, registry, hyp("big", ids, SCHEDULING_CAUSE))

    assert len(batch.hypotheses) == 1 and batch.omitted == 0
    assert batch.hypotheses[0].evidence_refs == ids


@pytest.mark.parametrize(
    "cluster, pod_name, focus",
    [
        (unschedulable(), "big", "scheduler_events"),
        (unschedulable(), "big", "declared_placement_requirements"),
        (mount_failure(), "vol", "volume_mount_events"),
        (mount_failure(), "vol", "declared_volumes"),
    ],
)
def test_each_pod_level_topic_group_is_usable_without_exceeding_the_limit(
    cluster, pod_name, focus
):
    ctx, snapshot, registry = build(cluster)
    ids = group(snapshot, focus)["evidence_ids"]
    possible = SCHEDULING_CAUSE if pod_name == "big" else MOUNT_CAUSE

    batch = parse(ctx, registry, hyp(pod_name, ids, possible))

    assert len(batch.hypotheses) == 1 and batch.omitted == 0


def test_restarted_container_offers_termination_and_liveness_probe_groups():
    _, snapshot, _ = build(restarted())
    focuses = {g["focus"] for g in build_focus_groups(snapshot)}

    assert {"current_container_state", "previous_termination",
            "liveness_probe_configuration", "kubernetes_events"} <= focuses
    assert "readiness_probe_configuration" not in focuses


def test_healthy_pods_get_no_focus_groups():
    healthy = pod("fine", phase="Running", scheduled=("True", None), statuses=None,
                  containers=[container_spec()])
    _, snapshot, _ = build(Cluster([healthy]))

    assert build_focus_groups(snapshot) == []


def test_focus_groups_do_not_make_other_references_uncitable_or_citable_wrongly():
    ctx, snapshot, registry = build(unschedulable())
    every = [item.evidence_id for item in snapshot.evidence if item.pod == "big"]

    # More than the limit is still a per-hypothesis omission, with no trimming.
    batch = parse(ctx, registry, hyp("big", every[: MAX_REFERENCES + 1], SCHEDULING_CAUSE))
    assert batch.hypotheses == [] and batch.omission_reasons == {"too_many_references": 1}

    # An id that exists in no group but is genuine remains citable.
    outside = [i for i in every if i not in {
        r for g in build_focus_groups(snapshot) for r in g["evidence_ids"]}]

    if outside:
        assert len(parse(ctx, registry, hyp("big", outside[:1], SCHEDULING_CAUSE)).hypotheses) == 1

    # An invented id is still a provenance failure that rejects the response.
    with pytest.raises(HypothesisValidationError):
        parse(ctx, registry, hyp("big", ["ev-9999"], SCHEDULING_CAUSE))


def test_structural_observations_are_withheld_from_the_models_list_but_stay_citable():
    ctx, snapshot, registry = build(unschedulable())
    data = HypothesisInput(snapshot=snapshot, log_entries=(), omitted_log_entries=0,
                           authorized_namespace=NS)
    payload = json.loads(build_hypothesis_messages(data)[1]["content"])
    listed = {item["field"] for item in payload["kubernetes_verified_observations"]["items"]}

    assert STRUCTURAL_FIELDS and all(is_structural(f) for f in STRUCTURAL_FIELDS)
    assert not (listed & STRUCTURAL_FIELDS)
    assert "pod.uid" not in json.dumps(payload["kubernetes_verified_observations"])

    uid_ref = next(i.evidence_id for i in snapshot.evidence if i.field == "pod.uid")

    assert len(parse(ctx, registry, hyp("big", [uid_ref], SCHEDULING_CAUSE)).hypotheses) == 1


def test_payload_labels_focus_as_relevance_only_and_classifies_the_pod():
    _, snapshot, _ = build(unschedulable())
    data = HypothesisInput(snapshot=snapshot, log_entries=(), omitted_log_entries=0,
                           authorized_namespace=NS)
    payload = json.loads(build_hypothesis_messages(data)[1]["content"])

    assert payload["evidence_focus_groups"]["trust"] == "selected_by_the_application_for_relevance_only"
    assert payload["evidence_focus_groups"]["items"]
    assert any(
        item["pod"] == "big" and item["category"] == "unschedulable" and item["ever_ran"] is False
        for item in payload["application_failure_classification"]["items"]
    )
    assert "evidence_focus_groups" in HYPOTHESIS_SYSTEM_PROMPT
    assert "unschedulable" in HYPOTHESIS_SYSTEM_PROMPT
    assert "volume_mount_failure" in HYPOTHESIS_SYSTEM_PROMPT
    assert "restarted_running" in HYPOTHESIS_SYSTEM_PROMPT


def test_the_payload_never_carries_event_messages():
    cluster = unschedulable(message=SCHED_MESSAGE + " MARKER-MESSAGE-8891")
    _, snapshot, _ = build(cluster)
    data = HypothesisInput(snapshot=snapshot, log_entries=(), omitted_log_entries=0,
                           authorized_namespace=NS)
    content = build_hypothesis_messages(data)[1]["content"]

    assert "MARKER-MESSAGE-8891" not in content and "No preemption victims" not in content


# ================================================== state-consistency rules


def test_unschedulable_pod_rejects_image_pull_and_crash_explanations():
    ctx, snapshot, registry = build(unschedulable())
    ids = group(snapshot, "scheduling_status")["evidence_ids"]

    for wording in (IMAGE_PULL, CRASH):
        batch = parse(ctx, registry, hyp("big", ids, wording))

        assert batch.hypotheses == [] and batch.omitted == 1


def test_volume_blocked_pod_rejects_image_pull_and_crash_explanations():
    ctx, snapshot, registry = build(mount_failure())
    ids = group(snapshot, "volume_mount_events")["evidence_ids"]

    for wording in (IMAGE_PULL, CRASH):
        assert parse(ctx, registry, hyp("vol", ids, wording)).hypotheses == []


def test_liveness_claim_is_rejected_when_no_liveness_probe_is_declared():
    ctx, snapshot, registry = build(restarted(liveness=False, events=False))
    ids = group(snapshot, "previous_termination")["evidence_ids"]

    batch = parse(ctx, registry, hyp("live", ids, LIVENESS_CLAIM, container="app"))

    assert batch.hypotheses == [] and batch.omitted == 1


OWNER_PHRASED_LIVENESS = (
    "The application's liveness probe or readiness probe configuration may be "
    "incorrect, which could explain the restarts."
)


def test_owner_phrased_probe_blame_is_rejected_when_no_liveness_probe_is_declared():
    ctx, snapshot, registry = build(restarted(liveness=False, events=False))
    ids = group(snapshot, "previous_termination")["evidence_ids"]

    batch = parse(ctx, registry, hyp("live", ids, OWNER_PHRASED_LIVENESS, container="app"))

    assert batch.hypotheses == [] and batch.omitted == 1


def test_uncollected_probe_configuration_is_unknown_not_absent():
    from app.reports.state_consistency import ProbeState

    _, _, registry = build(restarted(liveness=False, events=False))

    assert registry.pod_state("live", "app").liveness_probe is ProbeState.ABSENT

    registry._liveness_declared.clear()  # the pod spec was never collected

    assert registry.pod_state("live", "app").liveness_probe is ProbeState.UNKNOWN


def test_liveness_claim_is_accepted_when_a_probe_is_declared_and_failed():
    ctx, snapshot, registry = build(restarted())
    ids = group(snapshot, "liveness_probe_configuration")["evidence_ids"]

    batch = parse(ctx, registry, hyp("live", ids, LIVENESS_CLAIM, container="app"))

    assert len(batch.hypotheses) == 1


def test_pod_state_rules_are_inert_without_established_pod_state():
    assert pod_state_violation([IMAGE_PULL], None) is None
    assert pod_state_violation(
        [IMAGE_PULL], PodState(blocked_before_start=False, liveness_probe_declared=None)
    ) is None
    assert pod_state_violation(
        [LIVENESS_CLAIM], PodState(blocked_before_start=False, liveness_probe_declared=None)
    ) is None
    assert pod_state_violation(
        [LIVENESS_CLAIM], PodState(blocked_before_start=False, liveness_probe_declared=True)
    ) is None


def test_denying_a_claim_is_not_asserting_it():
    state = PodState(blocked_before_start=True, liveness_probe_declared=False)

    assert pod_state_violation(
        ["This does not involve an image pull."], state
    ) is None


def test_events_tied_to_a_different_pod_uid_are_not_citable():
    p = pod("big", scheduler_message=SCHED_MESSAGE,
            containers=[container_spec(memory_request="900Gi")])
    cluster = Cluster([p], {"big": [event(pod_name="big", reason="FailedScheduling",
                                          message=SCHED_MESSAGE, component="default-scheduler",
                                          uid=OTHER_UID)]})
    ctx, snapshot, registry = build(cluster)
    event_ids = [i.evidence_id for i in snapshot.evidence if i.field.startswith("events[")]

    # Mismatched events were never observed as evidence at all.
    assert event_ids == []


# ================================================================ ranking


def test_unschedulable_pod_hypotheses_rank_topical_over_off_topic_in_a_stable_way():
    ctx, snapshot, registry = build(unschedulable())
    ids = group(snapshot, "scheduling_status")["evidence_ids"]

    batch = parse(ctx, registry, hyp("big", ids, OFF_TOPIC), hyp("big", ids, SCHEDULING_CAUSE))
    ranked = rank_hypotheses(batch.hypotheses, registry)

    assert len(ranked) == 2
    assert "memory" in ranked[0].explanation
    assert rank_hypotheses(ranked, registry) == ranked


def test_pod_level_failures_outrank_hypotheses_about_a_healthy_pod():
    healthy = pod("fine", phase="Running", scheduled=("True", None), statuses=None,
                  containers=[container_spec(memory_request="64Mi")])
    broken = pod("big", scheduler_message=SCHED_MESSAGE,
                 containers=[container_spec(memory_request="900Gi")])
    cluster = Cluster([healthy, broken], {"big": [event(pod_name="big", reason="FailedScheduling",
                                                       message=SCHED_MESSAGE,
                                                       component="default-scheduler")]})
    ctx, snapshot, registry = build(cluster)
    fine_ids = [i.evidence_id for i in snapshot.evidence if i.pod == "fine" and
                i.field == "pod.phase"]
    big_ids = group(snapshot, "scheduling_status")["evidence_ids"]

    batch = parse(ctx, registry, hyp("fine", fine_ids, OFF_TOPIC), hyp("big", big_ids,
                                                                      SCHEDULING_CAUSE))
    ranked = rank_hypotheses(batch.hypotheses, registry)

    assert ranked[0].resource.pod == "big"


@pytest.mark.parametrize(
    "wording",
    [
        IMAGE_PULL,
        "The image pull may be failing because the registry is unreachable.",
        "The container may be unable to pull its image, which could explain the state.",
    ],
)
def test_blocked_pods_reject_every_hedged_image_pull_phrasing(wording):
    assert pod_state_violation(
        [wording], PodState(blocked_before_start=True, liveness_probe_declared=None)
    ) == "contradicts_container_state"


@pytest.mark.parametrize(
    "cluster",
    [unschedulable(), mount_failure(), restarted(), restarted(ready=False)],
    ids=["unschedulable", "mount", "restarted", "not-ready"],
)
def test_each_focus_group_states_the_resource_the_registry_will_derive(cluster):
    ctx, snapshot, registry = build(cluster)

    for entry in build_focus_groups(snapshot):
        # Never rejected as a resource mismatch when the group's own pod and
        # container are declared (wording may still be omitted, never rejected).
        batch = parse(
            ctx, registry, hyp(entry["pod"], entry["evidence_ids"], SCHEDULING_CAUSE,
                               container=entry["container"])
        )

        assert batch.omitted + len(batch.hypotheses) == 1


def test_declaring_a_container_that_no_cited_id_names_is_still_a_resource_mismatch():
    ctx, snapshot, registry = build(unschedulable())
    ids = group(snapshot, "scheduling_status")["evidence_ids"]

    assert group(snapshot, "scheduling_status")["container"] is None

    with pytest.raises(HypothesisValidationError) as error:
        parse(ctx, registry, hyp("big", ids, SCHEDULING_CAUSE, container="app"))

    assert error.value.code == "resource_mismatch"


@pytest.mark.parametrize(
    "source, expected",
    [("config_map", True), ("secret", True), ("projected", True),
     ("empty_dir", False), ("persistent_volume_claim", False)],
)
def test_a_config_object_volume_counts_as_a_reference_to_that_object(source, expected):
    _, _, registry = build(mount_failure(source=source))

    assert registry.references_config_objects("vol") is expected
    assert registry.references_config_objects("other") is False
    assert registry.references_config_objects(None) is False
