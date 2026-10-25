"""Source-aware hypothesis claims.

A hypothesis may draw on application logs, structured Kubernetes observations
and Kubernetes events, and each needs evidence of its own kind. These tests
cover Kubernetes-native hypotheses without any log, relabelled sources, event
claims without event evidence, specific probe details no cited evidence
supplies, cross-resource references and image-pull explanations. None of the
checks verifies an explanation; they only stop a claim borrowing provenance.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.reports.evidence_focus import build_focus_groups
from app.reports.hypotheses import (
    HypothesisEvidenceRegistry,
    HypothesisValidationError,
    parse_hypothesis_response,
)
from app.reports.hypothesis_ranking import rank_hypotheses
from app.reports.models import OMISSION_REASON_CODES
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT
from app.reports.source_claims import (
    MISATTRIBUTED_SOURCE,
    UNSUPPORTED_SPECIFIC_CLAIM,
    reported_violation,
    unsupported_claim,
)
from app.tools.event_signals import (
    IMAGE_PULL_SIGNALS,
    NOT_PULL_SIGNALS,
    classify_event,
)
from app.tools.handlers import _read_logs
from tests.pod_scenarios import (
    NS,
    Cluster,
    container_spec,
    container_status,
    event,
    http_probe,
    investigate,
    pod,
)
from tests.test_pod_level_health import LIVENESS_MESSAGE, crash_looping, restarted
from tests.test_pod_level_hypotheses import build, group, hyp, parse

KUBELET = "kubelet"
PULL_MESSAGE = 'Failed to pull image "registry.invalid/app:1": not found'
BACKOFF_MESSAGE = "Back-off restarting failed container app in pod live"
PULL_BACKOFF_MESSAGE = 'Back-off pulling image "registry.invalid/app:1"'

IMAGE_PULL = "The image may not be pullable from the registry, which could explain the failure."
LIVENESS_CAUSE = (
    "The liveness probe may be failing, which could explain why the container "
    "was restarted."
)


def ids_of(snapshot, *wanted):
    by_field = {i.field: i.evidence_id for i in snapshot.evidence}

    return [by_field[w] for w in wanted]


def fields_like(snapshot, prefix):
    return [i.evidence_id for i in snapshot.evidence if i.field.startswith(prefix)]


def never_started(*, events=True, reason="ImagePullBackOff", restarts=0):
    p = pod(
        "pull",
        scheduled=("True", None),
        statuses=[container_status(reason=reason, restarts=restarts)],
        age=600,
    )
    evts = (
        [event(pod_name="pull", reason="Failed", message=PULL_MESSAGE, component=KUBELET)]
        if events
        else []
    )

    return Cluster([p], {"pull": evts})


# ===================================== Kubernetes-native hypotheses, no logs


@pytest.mark.parametrize("cluster", [restarted(), crash_looping(liveness=True)], ids=["restarted", "crashloop"])
def test_liveness_hypothesis_is_accepted_without_any_application_log(cluster):
    ctx, snapshot, registry = build(cluster)
    name = snapshot.evidence[0].pod
    history = group(snapshot, "liveness_failure_history")

    batch = parse(ctx, registry, hyp(name, history["evidence_ids"], LIVENESS_CAUSE, container="app"))

    assert not ctx.log_entries
    assert len(batch.hypotheses) == 1 and batch.omitted == 0
    assert list(batch.hypotheses[0].evidence_refs) == history["evidence_ids"]


def test_liveness_failure_history_group_is_one_pod_one_container_and_bounded():
    _, snapshot, _ = build(restarted())
    entry = group(snapshot, "liveness_failure_history")
    by_id = {i.evidence_id: i for i in snapshot.evidence}
    cited = [by_id[i] for i in entry["evidence_ids"]]

    assert 1 <= len(cited) <= 6 and len({i.pod for i in cited}) == 1
    assert entry["container"] == "app"
    assert any(i.field.startswith("events[") for i in cited)
    assert any(i.field.endswith("restart_count") for i in cited)
    assert any("liveness_probe" in i.field for i in cited)


def test_liveness_history_group_is_absent_without_a_declared_probe_or_events():
    for cluster in (restarted(liveness=False), restarted(events=False)):
        _, snapshot, _ = build(cluster)

        assert all(g["focus"] != "liveness_failure_history" for g in build_focus_groups(snapshot))


def test_liveness_hypothesis_names_no_endpoint_without_cited_probe_target():
    ctx, snapshot, registry = build(restarted())
    history = group(snapshot, "liveness_failure_history")["evidence_ids"]

    for claim in (
        "The liveness probe may be failing because /healthz does not respond, which could explain the restarts.",
        "The liveness probe may target port 9090, which could explain the restarts.",
        "The liveness probe may be returning status 503, which could explain the restarts.",
    ):
        batch = parse(ctx, registry, hyp("live", history, claim, container="app"))

        assert not batch.hypotheses
        assert batch.omission_reasons == {UNSUPPORTED_SPECIFIC_CLAIM: 1}


def test_probe_target_may_be_named_when_the_matching_probe_observation_is_cited():
    ctx, snapshot, registry = build(restarted())
    path = ids_of(snapshot, "containers[app].liveness_probe.path")
    port = ids_of(snapshot, "containers[app].liveness_probe.port")
    history = group(snapshot, "liveness_failure_history")["evidence_ids"][:4]
    claim = (
        "The liveness probe may be failing on /nonexistent port 80, which "
        "could explain the restarts."
    )

    batch = parse(ctx, registry, hyp("live", [*history, *path, *port][:6], claim, container="app"))

    assert len(batch.hypotheses) == 1

    wrong = claim.replace("/nonexistent", "/other")
    assert parse(
        ctx, registry, hyp("live", [*history, *path, *port][:6], wrong, container="app")
    ).omission_reasons == {UNSUPPORTED_SPECIFIC_CLAIM: 1}


def test_declared_probe_evidence_is_a_verified_observation_not_a_model_claim():
    ctx, snapshot, _ = build(restarted())
    probe = {i.field: i.value for i in snapshot.evidence if "liveness_probe" in i.field}

    assert probe["containers[app].liveness_probe.path"] == "/nonexistent"
    assert probe["containers[app].liveness_probe.port"] == 80


def test_liveness_events_stay_associated_with_the_pod_not_a_container():
    _, snapshot, _ = build(restarted())
    event_fields = [i for i in snapshot.evidence if i.field.startswith("events[")]

    assert event_fields
    assert all(not hasattr(i, "container") or i.container is None for i in event_fields)
    assert all(i.field.startswith("events[") or i.field == "events.identity" for i in event_fields)


# ============================================ inaccurate log attribution


@pytest.mark.parametrize(
    "reported",
    [
        "The logs report CrashLoopBackOff for the container.",
        "The application logs show the container is in ImagePullBackOff.",
        "The logs say the container was OOMKilled.",
        "The log shows the restart count is 5.",
        "The logs report the container is waiting in ContainerCreating.",
    ],
)
def test_kubernetes_state_is_never_accepted_as_an_application_log_claim(reported):
    assert reported_violation(reported, cites_logs=True) == MISATTRIBUTED_SOURCE


def test_genuine_log_claims_and_absent_claims_are_not_misattribution():
    assert reported_violation("PAYMENTS_DB_HOST is not set", cites_logs=True) is None
    assert reported_violation("connection refused to db:5432", cites_logs=True) is None
    assert reported_violation(None, cites_logs=True) is None
    # With no cited log the caller rejects it as reported_without_log_evidence.
    assert reported_violation("CrashLoopBackOff", cites_logs=False) is None


def test_a_log_claim_without_any_cited_log_is_rejected_and_never_mutated():
    ctx, snapshot, registry = build(restarted())
    item = hyp("live", group(snapshot, "liveness_failure_history")["evidence_ids"],
               LIVENESS_CAUSE, container="app")
    item["reported"] = "The container is in CrashLoopBackOff."

    batch = parse(ctx, registry, item)

    assert not batch.hypotheses
    assert batch.omission_reasons == {"reported_without_log_evidence": 1}


def test_empty_pod_log_is_empty_not_a_fake_log_line():
    arguments = SimpleNamespace(namespace=NS, pod="p", container="app", tail=20)

    for artifact in ("b''", 'b""', " b'' ", b""):
        api = SimpleNamespace(read_namespaced_pod_log=lambda **kw: artifact)

        with patch("app.tools.handlers.core_v1", return_value=api):
            assert _read_logs(arguments, previous=False)["logs"] == ""


def test_real_log_text_that_resembles_the_artifact_is_preserved():
    arguments = SimpleNamespace(namespace=NS, pod="p", container="app", tail=20)
    api = SimpleNamespace(read_namespaced_pod_log=lambda **kw: "value b'' seen")

    with patch("app.tools.handlers.core_v1", return_value=api):
        assert _read_logs(arguments, previous=False)["logs"] == "value b'' seen"


# ============================================== missing event evidence


def evidence(*fields):
    return {f"ev-{n:04d}": (field, True) for n, field in enumerate(fields, 1)}


@pytest.mark.parametrize(
    "text",
    [
        "The events show the container failing, which could explain the restarts.",
        "Warning events indicate a problem, which could explain the failure.",
        "The probe failure events are recorded, which could explain the restarts.",
    ],
)
def test_an_event_claim_needs_a_cited_event_observation(text):
    assert unsupported_claim([text], evidence("containers[app].restart_count")) == UNSUPPORTED_SPECIFIC_CLAIM
    assert unsupported_claim([text], evidence("events[Unhealthy].count")) is None


def test_liveness_and_readiness_event_claims_need_matching_signals():
    live = "The liveness events show repeated failures, which could explain the restarts."
    ready = "The readiness events show repeated failures, which could explain the pod being unready."

    assert unsupported_claim([live], evidence("events[Unhealthy].count")) == UNSUPPORTED_SPECIFIC_CLAIM
    assert unsupported_claim(
        [live], evidence("events[Unhealthy].count", "events[Unhealthy].signal[liveness_probe_failed]")
    ) is None
    assert unsupported_claim(
        [ready], evidence("events[Unhealthy].count", "events[Unhealthy].signal[liveness_probe_failed]")
    ) == UNSUPPORTED_SPECIFIC_CLAIM
    assert unsupported_claim(
        [ready], evidence("events[Unhealthy].count", "events[Unhealthy].signal[readiness_probe_failed]")
    ) is None


def test_event_claim_without_event_evidence_is_omitted_from_a_real_investigation():
    ctx, snapshot, registry = build(restarted())
    ids = ids_of(snapshot, "containers[app].restart_count")
    claim = "The liveness events show the probe failing, which could explain the restarts."

    batch = parse(ctx, registry, hyp("live", ids, claim, container="app"))

    assert not batch.hypotheses and batch.omission_reasons == {UNSUPPORTED_SPECIFIC_CLAIM: 1}


def test_ai_interpretation_stays_unverified_and_cannot_change_provenance():
    ctx, snapshot, registry = build(restarted())
    ids = group(snapshot, "liveness_failure_history")["evidence_ids"]
    item = hyp("live", ids, LIVENESS_CAUSE, container="app")
    batch = parse(ctx, registry, item)
    accepted = batch.hypotheses[0]

    assert accepted.reported is None
    assert accepted.explanation.startswith("Possible explanation (unverified):")
    assert accepted.independently_established is None and accepted.established_refs == []
    assert list(accepted.evidence_refs) == ids
    assert {i.evidence_id for i in snapshot.evidence} >= set(accepted.evidence_refs)


# ============================================ cross-resource references


def test_references_from_two_pods_are_never_combined():
    one = pod("a", phase="Running", scheduled=("True", None), age=900,
              statuses=[container_status(ready=True, restarts=3, state="running", reason=None,
                                         last_exit=137, last_reason="Error")],
              containers=[container_spec(liveness=http_probe())])
    two = pod("b", phase="Running", scheduled=("True", None), age=900,
              statuses=[container_status(ready=True, restarts=3, state="running", reason=None,
                                         last_exit=137, last_reason="Error")],
              containers=[container_spec(liveness=http_probe())],
              uid="9d8c7b6a-1f2e-4d3c-8b7a-6f5e4d3c2b1a")
    ctx, snapshot, registry = build(Cluster([one, two]))
    by_pod = {}

    for item in snapshot.evidence:
        by_pod.setdefault(item.pod, []).append(item.evidence_id)

    mixed = [by_pod["a"][0], by_pod["b"][0]]

    with pytest.raises(HypothesisValidationError) as caught:
        parse(ctx, registry, hyp("a", mixed, LIVENESS_CAUSE))

    assert caught.value.code == "resource_mismatch"


def test_a_declared_resource_that_disagrees_with_the_evidence_rejects_the_response():
    ctx, snapshot, registry = build(restarted())
    ids = group(snapshot, "liveness_failure_history")["evidence_ids"]
    item = hyp("someone-else", ids, LIVENESS_CAUSE, container="app")

    with pytest.raises(HypothesisValidationError) as caught:
        parse(ctx, registry, item)

    assert caught.value.code == "resource_mismatch"


def test_a_null_resource_is_derived_from_the_cited_evidence():
    ctx, snapshot, registry = build(restarted())
    ids = group(snapshot, "liveness_failure_history")["evidence_ids"]
    item = hyp("live", ids, LIVENESS_CAUSE, container="app")
    item["resource"] = None

    batch = parse(ctx, registry, item)

    assert len(batch.hypotheses) == 1
    assert batch.hypotheses[0].resource.pod == "live"


@pytest.mark.parametrize("bad", ["ev-9999", "log-0001", "not-an-id"])
def test_unknown_or_foreign_references_reject_the_whole_response(bad):
    ctx, snapshot, registry = build(restarted())
    good = group(snapshot, "liveness_failure_history")["evidence_ids"]

    with pytest.raises(HypothesisValidationError):
        parse(
            ctx,
            registry,
            hyp("live", good, LIVENESS_CAUSE, container="app"),
            hyp("live", [good[0], bad], LIVENESS_CAUSE, container="app"),
        )


def test_a_reference_set_over_the_limit_omits_only_that_hypothesis():
    ctx, snapshot, registry = build(restarted())
    everything = [i.evidence_id for i in snapshot.evidence if i.pod == "live"]
    good = group(snapshot, "liveness_failure_history")["evidence_ids"]

    batch = parse(
        ctx,
        registry,
        hyp("live", everything, LIVENESS_CAUSE, container="app"),
        hyp("live", good, LIVENESS_CAUSE, container="app"),
    )

    assert len(everything) > 6
    assert len(batch.hypotheses) == 1
    assert batch.omission_reasons == {"too_many_references": 1}


# ================================================ image-pull explanations


@pytest.mark.parametrize("reason", ["ImagePullBackOff", "ErrImagePull"])
def test_image_pull_explanation_is_allowed_for_a_container_that_never_started(reason):
    ctx, snapshot, registry = build(never_started(reason=reason))
    ids = [*ids_of(snapshot, "containers[app].reason")[:1], *fields_like(snapshot, "events[Failed]")[:2]]

    batch = parse(ctx, registry, hyp("pull", ids, IMAGE_PULL, container="app"))

    assert len(batch.hypotheses) == 1 and batch.omitted == 0


def test_image_pull_explanation_is_allowed_for_a_never_started_container_without_events():
    ctx, snapshot, registry = build(never_started(events=False))
    ids = ids_of(snapshot, "containers[app].reason")

    batch = parse(ctx, registry, hyp("pull", ids, IMAGE_PULL, container="app"))

    assert len(batch.hypotheses) == 1


def test_image_pull_explanation_is_contradicted_for_a_running_container():
    ctx, snapshot, registry = build(restarted(events=False))
    ids = ids_of(snapshot, "containers[app].restart_count", "containers[app].last_termination.reason")

    batch = parse(ctx, registry, hyp("live", ids, IMAGE_PULL, container="app"))

    assert not batch.hypotheses
    assert batch.omission_reasons == {"contradicts_container_state": 1}


def test_image_pull_explanation_is_contradicted_for_a_crash_looping_container_that_ran_before():
    ctx, snapshot, registry = build(crash_looping(liveness=True))
    ids = ids_of(snapshot, "containers[app].restart_count", "containers[app].last_termination.reason")

    batch = parse(ctx, registry, hyp("loop", ids, IMAGE_PULL, container="app"))

    assert not batch.hypotheses
    assert batch.omission_reasons == {"contradicts_container_state": 1}


def pull_event_cluster(message, reason):
    p = pod(
        "live", phase="Running", scheduled=("True", None), age=900,
        statuses=[container_status(ready=True, restarts=3, state="running", reason=None,
                                   last_exit=137, last_reason="Error")],
        containers=[container_spec(liveness=http_probe())],
    )

    return Cluster([p], {"live": [
        event(pod_name="live", reason=reason, message=message, component=KUBELET),
        event(pod_name="live", reason="Unhealthy", message=LIVENESS_MESSAGE, component=KUBELET),
    ]})


def test_image_pull_explanation_is_allowed_for_a_restarted_container_with_pull_event_evidence():
    ctx, snapshot, registry = build(pull_event_cluster(PULL_MESSAGE, "Failed"))
    ids = [*ids_of(snapshot, "containers[app].restart_count"), *fields_like(snapshot, "events[Failed].count")]

    batch = parse(ctx, registry, hyp("live", ids, IMAGE_PULL, container="app"))

    assert len(batch.hypotheses) == 1


def test_a_restart_backoff_event_is_not_image_pull_evidence():
    ctx, snapshot, registry = build(pull_event_cluster(BACKOFF_MESSAGE, "BackOff"))
    ids = [*ids_of(snapshot, "containers[app].restart_count"), *fields_like(snapshot, "events[BackOff].count")]

    batch = parse(ctx, registry, hyp("live", ids, IMAGE_PULL, container="app"))

    assert not batch.hypotheses
    assert batch.omission_reasons == {"contradicts_container_state": 1}


# ================================================ event signal vocabulary


@pytest.mark.parametrize(
    "reason, message, expected",
    [
        ("Failed", PULL_MESSAGE, "image_pull_failed"),
        ("Failed", "Error: ErrImagePull", "image_pull_failed"),
        ("Failed", "Error: ImagePullBackOff", "image_pull_failed"),
        ("BackOff", PULL_BACKOFF_MESSAGE, "image_pull_backoff"),
        ("BackOff", BACKOFF_MESSAGE, "container_restart_backoff"),
    ],
)
def test_image_and_backoff_events_map_to_fixed_signals(reason, message, expected):
    assert expected in classify_event(reason, message, KUBELET)


def test_restart_backoff_is_not_a_pull_signal():
    assert "container_restart_backoff" in NOT_PULL_SIGNALS
    assert not NOT_PULL_SIGNALS & IMAGE_PULL_SIGNALS


@pytest.mark.parametrize("source", ["some-controller", "default-scheduler", None])
def test_image_signals_require_the_kubelet_as_the_emitter(source):
    assert classify_event("Failed", PULL_MESSAGE, source) == ()
    assert classify_event("BackOff", PULL_BACKOFF_MESSAGE, source) == ()


def test_unrelated_failed_message_gets_no_pull_signal():
    assert classify_event("Failed", "Error: container create failed", KUBELET) == ()


# ================================================ ranking, prompt, contract


def test_liveness_hypothesis_ranks_above_unrelated_ones_for_a_restarted_probe_container():
    ctx, snapshot, registry = build(restarted())
    live = group(snapshot, "liveness_failure_history")["evidence_ids"]
    other = ids_of(snapshot, "containers[app].state")
    batch = parse(
        ctx,
        registry,
        hyp("live", other, "The container image may be wrong, which could explain the failure.",
            container="app"),
        hyp("live", live, LIVENESS_CAUSE, container="app"),
    )

    ranked = rank_hypotheses(batch.hypotheses, registry)

    assert list(ranked[0].evidence_refs) == live


def test_prompt_separates_the_three_sources_and_asks_for_a_null_resource():
    text = HYPOTHESIS_SYSTEM_PROMPT

    assert "Keep the three sources apart" in text
    assert 'never go in "reported"' in text
    assert '"resource": null' in text
    assert "Image pulls" in text
    assert "probe path/port" in text or "probe path" in text


def test_the_two_new_omission_codes_are_additive_vocabulary():
    assert {MISATTRIBUTED_SOURCE, UNSUPPORTED_SPECIFIC_CLAIM} <= set(OMISSION_REASON_CODES)
