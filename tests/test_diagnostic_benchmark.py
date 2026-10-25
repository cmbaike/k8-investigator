"""Permanent diagnostic-quality regression tests.

Two things are pinned here:

* the controlled scenarios of `eval/diagnostic_quality` stay buildable, each
  through the real handlers, and call the tools the rubric expects;
* the adversarial corpus (`adversarial_cases.json`): incorrect model
  statements are rejected or have their check withheld, and correct statements
  that merely contain negation, quotation or alternative wording are accepted.
  The accepted cases exist to catch false-positive rejections.
"""

import json
from pathlib import Path

import pytest

from app.reports.evidence_focus import build_focus_groups
from app.reports.hypotheses import (
    MAX_REFERENCES,
    HypothesisEvidenceRegistry,
    HypothesisToneError,
    validate_hypothesis_fields,
)
from eval.diagnostic_quality.scenarios import ALL_SCENARIOS, BY_ID, NS, SCENARIOS, build_cluster
from tests.pod_scenarios import investigate

CORPUS = json.loads(
    (Path(__file__).parent.parent / "eval/diagnostic_quality/adversarial_cases.json").read_text()
)
DEFAULTS = CORPUS["defaults"]
CASES = CORPUS["cases"]
_BUILT: dict[str, tuple] = {}


def built(scenario_id: str):
    if scenario_id not in _BUILT:
        cluster = build_cluster(scenario_id)
        ctx, snapshot, _, _ = investigate(cluster)
        registry = HypothesisEvidenceRegistry(
            investigation_id=ctx.investigation_id,
            authorized_namespace=NS,
            snapshot=snapshot,
            log_entries=ctx.log_entries,
        )
        groups = build_focus_groups(snapshot)
        _BUILT[scenario_id] = (cluster, registry, groups)

    return _BUILT[scenario_id]


def evidence_ids(scenario_id: str, cite: list[str] | None = None) -> list[str]:
    """The evidence a model would cite for this abnormality: the first focus
    group, or the named groups when a case quotes more than one source."""
    _, _, groups = built(scenario_id)
    by_focus = {g["focus"]: g for g in groups}
    chosen = [by_focus[name] for name in cite] if cite else groups[:1]
    ids: list[str] = []

    # Round-robin, so every named source contributes before the limit applies.
    for position in range(MAX_REFERENCES):
        for group in chosen:
            if position < len(group["evidence_ids"]):
                ids.append(group["evidence_ids"][position])

    return ids[:MAX_REFERENCES]


def validate(case: dict):
    _, registry, _ = built(case["scenario"])

    return validate_hypothesis_fields(
        reported=None,
        possible_explanation=case["possible"],
        not_yet_verified=case.get("not_yet_verified", DEFAULTS["not_yet_verified"]),
        evidence=evidence_ids(case["scenario"], case.get("cite")),
        declared_resource=None,
        verification_check=case.get("check", DEFAULTS["check"]),
        registry=registry,
    )


@pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=lambda s: s.id)
def test_every_scenario_builds_and_calls_its_expected_tools(scenario):
    cluster, _, groups = built(scenario.id)

    # Every investigation lists and describes the pod. The rubric's wider
    # `expected_tools` (events too) is a coverage measure for the live model
    # run, where the controller decides what else to call.
    assert {"k8s.get_pods", "k8s.describe_pod"} <= set(cluster.names)

    if not scenario.healthy:
        assert groups, "an abnormal scenario must yield evidence to cite"


def test_scenario_ids_are_the_thirteen_fixed_ones():
    assert [s.id for s in SCENARIOS] == [
        "sched_cpu", "sched_memory", "sched_taint", "sched_selector",
        "sched_multiple", "sched_missing_pvc", "image_pull", "oom_killed",
        "running_not_ready", "liveness_failure", "mount_failure", "crash_loop",
        "healthy",
    ]
    assert [s.id for s in ALL_SCENARIOS][13:] == ["restart_history", "oom_recovered"]
    assert {case["scenario"] for case in CASES} <= set(BY_ID)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_adversarial_corpus(case):
    expect = case.get("expect")

    if expect == "accept":
        hypothesis = validate(case)

        # A correct statement is kept as written, with its check unchanged.
        assert hypothesis.possible_explanation == case["possible"]
        assert hypothesis.check_withheld_reason is None
        assert hypothesis.verification_check == case.get("check", DEFAULTS["check"])
    elif expect and expect.startswith("withhold:"):
        hypothesis = validate(case)

        assert hypothesis.verification_check is None
        assert hypothesis.check_withheld_reason == expect.split(":", 1)[1]
        assert hypothesis.possible_explanation == case["possible"]
        # Never rewritten into a different check.
        assert case["check"] not in hypothesis.model_dump_json()
    else:
        with pytest.raises(HypothesisToneError) as raised:
            validate(case)

        if expect:
            assert raised.value.code == expect.split(":", 1)[1]
        else:
            assert case.get("expect_any_reject") is True


# ------------------------------------------------ lifecycle rubric (grader)
from eval.diagnostic_quality import lifecycle_rubric  # noqa: E402

_LIFECYCLE_CASES = {c["id"]: c for c in CASES}
_DETECTED = {
    "adv_container_never_started": "never_started_but_ran",
    "adv_running_container_never_initialized": "never_started_but_ran",
    "adv_request_too_small_causes_oom": "request_blamed_for_oom",
    "adv_exceeded_request_and_killed": "request_limit_role_confusion",
    "adv_request_as_ceiling": "request_limit_role_confusion",
    "adv_limit_as_reservation": "request_limit_role_confusion",
    "adv_restart_count_proves_liveness": "restart_count_proves_cause",
    "adv_restarts_show_current_failure": "restart_count_shows_failure_now",
    "adv_healthy_container_not_ready": "not_ready_but_ready",
}


@pytest.mark.parametrize("case_id", sorted(_DETECTED))
def test_lifecycle_grader_finds_the_error_independently_of_the_validator(case_id):
    case = _LIFECYCLE_CASES[case_id]

    assert _DETECTED[case_id] in lifecycle_rubric.grade(case["possible"], case["scenario"])


@pytest.mark.parametrize(
    "case", [c for c in CASES if c["id"].startswith("correct_")], ids=lambda c: c["id"]
)
def test_lifecycle_grader_does_not_flag_correct_statements(case):
    assert lifecycle_rubric.grade(case["possible"], case["scenario"]) == []

_DETECTED_MORE = {
    "adv_request_value_quoted_as_limit": None,  # needs observed values: validator only
    "adv_running_but_not_ready": "not_ready_but_ready",
}


def test_lifecycle_grader_finds_running_but_not_ready_for_a_ready_container():
    case = _LIFECYCLE_CASES["adv_running_but_not_ready"]

    assert "not_ready_but_ready" in lifecycle_rubric.grade(case["possible"], case["scenario"])
