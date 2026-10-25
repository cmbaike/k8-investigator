"""Unit tests for the structured technical-consistency layer.

Every rule is tested three ways: the incorrect claim is found; the same idea
written with negation, quotation or a legitimate alternative wording is NOT; and
rules that depend on an established fact do nothing without it.
"""

import pytest

from app.reports.scheduling_semantics import inverted_taint_toleration
from app.reports.technical_consistency import (
    INCORRECT_SEMANTICS,
    UNSUPPORTED_CERTAINTY,
    TechnicalFacts,
    check_scope_violation,
    check_violation,
    remediation_in_check,
    technical_violation,
)

NS = "ai-ops-demo"
PLAIN = TechnicalFacts(authorized_namespace=NS, scope_names=frozenset({"web", "app"}))
UNSCHEDULABLE = TechnicalFacts(
    unschedulable=True,
    authorized_namespace=NS,
    scope_names=frozenset({"web"}),
    scheduling_signals=frozenset({"insufficient_cpu", "untolerated_taint"}),
)
PLACEMENT_UNDECLARED = TechnicalFacts(
    unschedulable=True,
    placement_undeclared=True,
    authorized_namespace=NS,
    scheduling_signals=frozenset({"insufficient_cpu"}),
)
RUNNING = TechnicalFacts(running_and_ready=True, authorized_namespace=NS)
DECLARES_REQUESTS = TechnicalFacts(
    unschedulable=True, requests_declared=True, authorized_namespace=NS
)


def violation(text, facts=PLAIN, **kw):
    return technical_violation((text,), facts, cites_logs=kw.pop("cites_logs", True), **kw)


# ---------------------------------------------------------------- taints
@pytest.mark.parametrize("text", [
    "The pod contains a taint that no node tolerates.",
    "No node in the cluster tolerates the pod's taint.",
    "Check the tolerations on the nodes.",
])
def test_inverted_taint_and_toleration_wording_is_found(text):
    assert inverted_taint_toleration([text])


@pytest.mark.parametrize("text", [
    "The pod does not contain a taint; the nodes do.",
    "No taint is set on the pod.",
    "A node never tolerates anything; a pod declares tolerations.",
    "Nodes with taints that the pod has no tolerations for cannot host it.",
    'Wrong wording would be "the pod contains a taint".',
    "The pod does not tolerate the node taint.",
    "Compare node taints with the pod's tolerations.",
])
def test_correct_taint_and_toleration_wording_is_not_found(text):
    assert not inverted_taint_toleration([text])


# --------------------------------------------------------- resource roles
def test_a_memory_limit_is_not_the_scheduling_request_only_when_unschedulable():
    text = "The pod may be unschedulable because its memory limit exceeds node capacity."

    assert violation(text, UNSCHEDULABLE) == INCORRECT_SEMANTICS
    assert violation(text, PLAIN) is None  # no established unschedulable pod


@pytest.mark.parametrize("text", [
    "The pod may be unschedulable because its memory request exceeds allocatable memory.",
    "The memory limit is not what the scheduler compares; the request is.",
])
def test_correct_request_and_limit_wording_is_accepted(text):
    assert violation(text, UNSCHEDULABLE) is None


def test_nodes_request_and_pods_allocate_is_reversed():
    assert violation("The node requests more memory than the pod allocates.") == INCORRECT_SEMANTICS
    assert violation("The pod requests memory that no node can allocate.") is None


def test_nodes_belong_to_no_namespace():
    assert violation("The nodes in the ai-ops-demo namespace are full.") == INCORRECT_SEMANTICS
    assert violation("Nodes belong to no namespace; the pod's namespace is ai-ops-demo.") is None


# ----------------------------------------------------------------- probes
@pytest.mark.parametrize("text", [
    "The readiness probe may have restarted the container.",
    "A failing readiness probe may be restarting the container.",
    "The readiness probe failing proves the process never started.",
])
def test_readiness_semantics_errors_are_found(text):
    assert violation(text) == INCORRECT_SEMANTICS


@pytest.mark.parametrize("text", [
    "A readiness failure may remove the pod from endpoints and would not restart it.",
    "The liveness probe may have restarted the container, unlike the readiness probe.",
    "A failing liveness probe may restart the container, while a readiness failure only affects traffic.",
    "The readiness probe does not show that the process failed to start.",
])
def test_correct_probe_wording_is_accepted(text):
    assert violation(text) is None


# ------------------------------------------------------- image / certainty
def test_a_missing_image_is_a_claim_only_when_asserted():
    assert violation("The pod may fail to start, and the image does not exist.") == UNSUPPORTED_CERTAINTY
    assert violation("The pod may fail because the tag may not exist.") is None
    assert violation("The status does not show that the image does not exist.") is None
    assert violation('An engineer might write "the image does not exist" too early.') is None


def test_one_of_several_scheduler_constraints_is_not_the_only_cause():
    text = "The pod may be unschedulable only because of insufficient cpu, the sole cause."

    assert violation(text, UNSCHEDULABLE) == UNSUPPORTED_CERTAINTY
    assert violation(text, PLAIN) is None  # nothing established about several constraints
    assert violation("Insufficient cpu may be one of several constraints.", UNSCHEDULABLE) is None


def test_a_currently_failing_claim_needs_a_running_and_ready_pod():
    text = "The container may be crash-looping right now."

    assert violation(text, RUNNING) is not None
    assert violation(text, PLAIN) is None
    assert violation("The container is not currently crash-looping; it restarted once.", RUNNING) is None


# ---------------------------------------------------- placement not declared
def test_an_undeclared_selector_never_blocks_scheduling():
    blamed = "The pod may be unschedulable because no node selector is declared."

    assert violation(blamed, PLACEMENT_UNDECLARED) is not None
    # Without the established fact the rule has nothing to contradict.
    assert violation(blamed, PLAIN) is None
    assert violation(
        "The pod declares no node selector, so a placement mismatch does not explain it.",
        PLACEMENT_UNDECLARED,
    ) is None


# ------------------------------------------------------------ source claims
def test_kubernetes_state_cannot_be_attributed_to_logs():
    assert violation("The application logged that the container was OOMKilled.") is not None
    assert violation("Kubernetes reports the container was OOMKilled.") is None
    assert violation("The application did not log OOMKilled; Kubernetes reported it.") is None


# ------------------------------------------------------------------- checks
@pytest.mark.parametrize("check", [
    "Increase the memory request of the pod.",
    "Add a toleration to the pod.",
    "Delete the pod and let it be recreated.",
    "Review the events, then adjust the probe timing.",
    "You should try restarting the deployment.",
    "Review the memory request and limit for the container and adjust them if necessary.",
])
def test_remediation_disguised_as_a_check_is_found(check):
    assert remediation_in_check(check)
    assert check_violation(check, PLAIN) == "remediation_in_check"


@pytest.mark.parametrize("check", [
    "Compare node taints with the pod's tolerations (read-only).",
    "Review the label selectors on the service and the pod labels.",
    "Describe the pod and read its events.",
    "Inspect the memory requests of the pod and the allocatable memory of the nodes.",
    "Describe the pod and read it alongside the events.",
])
def test_read_only_checks_are_not_remediation(check):
    assert not remediation_in_check(check)
    assert check_violation(check, PLAIN) is None


@pytest.mark.parametrize("check", [
    "Describe the pods in namespace kube-system.",
    "Look at the pods in the 'team-b' namespace.",
    "List the pods across all namespaces.",
    "Read the logs of pod 'other-pod'.",
])
def test_checks_outside_the_investigated_resource_are_out_of_scope(check):
    assert check_scope_violation(check, PLAIN)


@pytest.mark.parametrize("check", [
    f"Describe the pods in the {NS} namespace.",
    "Describe the pods in the same namespace.",
    "Read the logs of pod 'web'.",
    "Review the namespace quota.",
])
def test_checks_inside_the_investigated_resource_are_in_scope(check):
    assert not check_scope_violation(check, PLAIN)


# ------------------------------------------------- honest uncertainty wording
def test_saying_the_cause_is_not_known_is_not_claiming_certainty():
    from app.reports.hypotheses import asserts_certainty

    assert not asserts_certainty("The exact cause is not yet determined.")
    assert not asserts_certainty("The root cause is unknown.")
    # A claimed cause still is certainty.
    assert asserts_certainty("The root cause is a missing secret.")
    assert asserts_certainty("The cause is confirmed.")


# ------------------------------------------------ live-run findings (v3)
def test_claiming_no_requests_contradicts_an_observed_request():
    claim = "The pod may not be schedulable because it has not declared any resource requests."

    assert violation(claim, DECLARES_REQUESTS) == "contradicts_established_evidence"
    assert violation("The pod may be unschedulable because no memory requests are declared.", DECLARES_REQUESTS)
    # Nothing observed: nothing contradicted.
    assert violation(claim, UNSCHEDULABLE) is None
    for correct in (
        "The pod may be unschedulable because its declared memory request is larger than any node allocates.",
        "Whether the pod declares CPU requests has not been verified.",
    ):
        assert violation(correct, DECLARES_REQUESTS) is None


def test_a_probe_cannot_explain_a_pod_that_was_never_scheduled():
    blamed = "The pod may not be schedulable because it has not declared any liveness probe."

    assert violation(blamed, UNSCHEDULABLE) == INCORRECT_SEMANTICS
    assert violation(blamed, PLAIN) is None  # a scheduled pod may have probe problems
    for correct in (
        "Probes only run once a container starts, so a liveness probe cannot explain this pending pod.",
        "No readiness probe has run: the pod was never started.",
        "Probe configuration does not apply to a pod that is not scheduled.",
    ):
        assert violation(correct, UNSCHEDULABLE) is None


def test_ensure_style_actions_are_remediation_not_checks():
    assert remediation_in_check(
        "Analyze the memory usage and ensure the memory limit handles the peak."
    )
    assert not remediation_in_check("Verify whether the memory limit handles the peak.")
