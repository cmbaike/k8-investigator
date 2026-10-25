"""Phase 2 and 3 of the diagnostic-correctness increment.

Lifecycle and resource-semantics rules, and the probe tri-state (declared /
verified absent / unknown). Every rule is tested three ways: the incorrect claim
is found; legitimate, qualified or negated wording is NOT; and a rule that needs
an established fact does nothing without it.
"""

import pytest

from app.reports.state_consistency import (
    CONTRADICTS_EVIDENCE,
    CONTRADICTS_STATE,
    ContainerFacts,
    PodState,
    ProbeState,
    pod_state_violation,
    probe_state,
    state_violation,
)
from app.reports.technical_consistency import (
    CONTRADICTS_EVIDENCE as TECH_CONTRADICTS_EVIDENCE,
    INCORRECT_SEMANTICS,
    UNSUPPORTED_CERTAINTY,
    TechnicalFacts,
    technical_violation,
)

NS = "ai-ops-demo"
PLAIN = TechnicalFacts(authorized_namespace=NS)
RUNNING = TechnicalFacts(running_and_ready=True, authorized_namespace=NS)


def tech(text, facts=PLAIN):
    return technical_violation((text,), facts, cites_logs=True)


# ------------------------------------------------- memory request vs OOMKilled
@pytest.mark.parametrize("text", [
    "The container may have been OOMKilled due to an insufficient memory request.",
    "A memory request that is too low may be causing the out-of-memory kills.",
    "The OOMKilled terminations could result from the memory request being set too small.",
])
def test_request_blamed_for_oom_is_found(text):
    assert tech(text) == INCORRECT_SEMANTICS


@pytest.mark.parametrize("text", [
    "The container may have exceeded its memory limit and been OOMKilled.",
    "The memory request and limit may both be too low, leading to OOMKilled terminations.",
    "A low memory request makes the pod an earlier victim under node memory pressure.",
    "The OOMKilled terminations are not caused by the memory request.",
    "Whether the memory request is related to the OOMKilled state is not established.",
    "The memory request is 64Mi. Separately, the last termination was OOMKilled.",
])
def test_legitimate_oom_wording_is_accepted(text):
    assert tech(text) is None


# ------------------------------------------------ request and limit confusion
@pytest.mark.parametrize("text", [
    "The memory request caps how much memory the container may use.",
    "The container may have exceeded its memory request and been killed.",
    "The memory limit is what the scheduler reserves on the node.",
])
def test_request_limit_role_confusion_is_found(text):
    assert tech(text) == INCORRECT_SEMANTICS


@pytest.mark.parametrize("text", [
    "The container may have exceeded its memory limit and been killed.",
    "The scheduler reserves the memory request, not the memory limit.",
    "The memory request is what the scheduler reserves on the node.",
])
def test_correct_request_limit_roles_are_accepted(text):
    assert tech(text) is None


# ------------------------------------------------------ restart-history claims
@pytest.mark.parametrize("text", [
    "The restart count proves the liveness probe failed.",
    "The container restarted, which confirms an out-of-memory kill.",
])
def test_restarts_proving_a_cause_is_unsupported(text):
    assert tech(text) == UNSUPPORTED_CERTAINTY


@pytest.mark.parametrize("text", [
    "The container may be unhealthy, and the restarts show the liveness probe failed.",
])
def test_restarts_asserting_a_cause_outside_the_hedge_is_unsupported(text):
    assert tech(text) == UNSUPPORTED_CERTAINTY


@pytest.mark.parametrize("text", [
    "The restart count does not prove why the container restarted.",
    "The restarts may indicate a liveness probe failure; this is not yet verified.",
    "The container restarted before and is running now; the cause is not established.",
    "Restarts are history: the container restarted once and is currently ready.",
])
def test_qualified_restart_history_is_accepted(text):
    assert tech(text) is None
    assert tech(text, RUNNING) is None


def test_restarts_showing_current_failure_contradicts_a_ready_container():
    text = "The restart count shows the container is still crash-looping."

    assert tech(text, RUNNING) == TECH_CONTRADICTS_EVIDENCE
    # Without the established fact the rule does nothing.
    assert tech(text, PLAIN) is None or tech(text, PLAIN) != TECH_CONTRADICTS_EVIDENCE


# ---------------------------------------------------------------- lifecycle
RUNNING_CONTAINER = ContainerFacts(
    running=True, not_ready=False, event_reasons=frozenset(),
    readiness_probe_declared=None, env_none_declared=False, ran_before=True,
)
RESTARTED_NOT_RUNNING = ContainerFacts(
    running=False, not_ready=True, event_reasons=frozenset(),
    readiness_probe_declared=None, env_none_declared=False, ran_before=True,
)
PRE_START = ContainerFacts(
    running=False, not_ready=True, event_reasons=frozenset(),
    readiness_probe_declared=None, env_none_declared=False, pre_start=True,
)


def lifecycle(text, *facts):
    return state_violation((text,), facts, cites_logs=True)


@pytest.mark.parametrize("text", [
    "The container may have failed to initialize and never started.",
    "The container did not start.",
    "The container may be unable to come up.",
    "The container never began running.",
])
def test_running_container_never_started_is_contradicted(text):
    assert lifecycle(text, RUNNING_CONTAINER) == CONTRADICTS_STATE


@pytest.mark.parametrize("text", [
    "The container never started.",
    "The container has not started at all.",
])
def test_container_with_history_never_started_is_contradicted(text):
    assert lifecycle(text, RESTARTED_NOT_RUNNING) == CONTRADICTS_STATE


@pytest.mark.parametrize("text", [
    "The container started, ran, and was later restarted.",
    "The application does not stay up: it exits shortly after it starts.",
    "The container is running and ready now; it restarted earlier.",
])
def test_legitimate_lifecycle_wording_is_accepted(text):
    assert lifecycle(text, RUNNING_CONTAINER) is None
    assert lifecycle(text, RESTARTED_NOT_RUNNING) is None


def test_failing_to_start_after_restarts_is_fine_for_a_container_not_running_now():
    text = "The container may be failing to start cleanly after each restart."

    assert lifecycle(text, RESTARTED_NOT_RUNNING) is None


def test_never_started_is_not_contradicted_for_a_container_stuck_before_start():
    assert lifecycle("The container never started.", PRE_START) is None


# ------------------------------------------------------------- probe tri-state
@pytest.mark.parametrize(("observed", "expected"), [
    (True, ProbeState.DECLARED),
    (False, ProbeState.ABSENT),
    (None, ProbeState.UNKNOWN),
    ("true", ProbeState.UNKNOWN),
    (0, ProbeState.UNKNOWN),
])
def test_probe_state_maps_only_real_booleans(observed, expected):
    assert probe_state(observed) is expected


def readiness_facts(declared):
    return ContainerFacts(
        running=True, not_ready=True, event_reasons=frozenset(),
        readiness_probe_declared=declared, env_none_declared=False, ran_before=True,
    )


READINESS_BLAME = [
    "The pod may not be ready because its readiness probe is failing.",
    "The application's readiness probe may be misconfigured.",
    "There may be an issue with the readiness probe configuration.",
]


@pytest.mark.parametrize("text", READINESS_BLAME)
def test_verified_absent_readiness_probe_rejects_blame(text):
    assert lifecycle(text, readiness_facts(False)) == CONTRADICTS_EVIDENCE


@pytest.mark.parametrize("text", READINESS_BLAME)
@pytest.mark.parametrize("declared", [True, None])
def test_declared_or_unknown_readiness_probe_does_not_reject(text, declared):
    assert lifecycle(text, readiness_facts(declared)) is None


@pytest.mark.parametrize("text", [
    "No readiness probe is declared for the container.",
    "The container does not declare a readiness probe, so readiness follows the process.",
    "The readiness probe is not failing; none is declared.",
    "The readiness probe isn't misconfigured because it does not exist.",
])
def test_correct_absence_statements_are_accepted(text):
    assert lifecycle(text, readiness_facts(False)) is None


LIVENESS_BLAME = [
    "The container may have been restarted because its liveness probe failed.",
    "The application's liveness probe or readiness probe configuration may be wrong.",
]


@pytest.mark.parametrize("text", LIVENESS_BLAME)
def test_verified_absent_liveness_probe_rejects_blame(text):
    state = PodState(blocked_before_start=False, liveness_probe_declared=False)

    assert pod_state_violation((text,), state) == CONTRADICTS_EVIDENCE


@pytest.mark.parametrize("text", LIVENESS_BLAME)
@pytest.mark.parametrize("declared", [True, None])
def test_declared_or_unknown_liveness_probe_does_not_reject(text, declared):
    state = PodState(blocked_before_start=False, liveness_probe_declared=declared)

    assert pod_state_violation((text,), state) is None


def test_no_probe_state_means_no_probe_rule():
    assert pod_state_violation((LIVENESS_BLAME[0],), None) is None


# ------------------------------------------- "not ready" for a ready container
@pytest.mark.parametrize("text", [
    "The container may be healthy but not ready because of a missing probe.",
    "The pod may be marked not ready, which could explain missing traffic.",
    "The container may be unready.",
])
def test_not_ready_claim_contradicts_a_container_that_is_ready_now(text):
    assert tech(text, RUNNING) == TECH_CONTRADICTS_EVIDENCE
    # Fact-gated: without established readiness the rule does nothing.
    assert tech(text, PLAIN) != TECH_CONTRADICTS_EVIDENCE


@pytest.mark.parametrize("text", [
    "The container may have been not ready earlier, during startup, and is ready now.",
    "The container may not be the cause: it is ready and the earlier restarts are history.",
    "No readiness failure may be present, since the container is ready.",
])
def test_history_and_denial_keep_not_ready_wording_acceptable(text):
    assert tech(text, RUNNING) is None


# ------------------------------------- quantities quoted in the wrong role
WITH_VALUES = TechnicalFacts(
    authorized_namespace=NS,
    memory_requests=frozenset({"64mi"}),
    memory_limits=frozenset({"128mi"}),
)


@pytest.mark.parametrize("text", [
    "The container may have exceeded the requested 64Mi limit.",
    "The memory limit of 64Mi may have been exceeded.",
    "The container may need more than its 128Mi memory request.",
    "The memory request may be 128 MiB, which could explain the kill.",
])
def test_observed_request_quoted_as_limit_and_the_reverse_is_found(text):
    assert tech(text, WITH_VALUES) == INCORRECT_SEMANTICS


@pytest.mark.parametrize("text", [
    "The container may have exceeded its 128Mi memory limit.",
    "The memory request of 64Mi is below the 128Mi limit, which may be unrelated.",
    "The container may have exceeded its 128 MiB limit although it requested 64Mi.",
    "The limit may not be the 64Mi that was requested.",
    "The container may have exceeded a 256Mi limit.",
])
def test_correct_quantity_roles_and_unobserved_values_are_accepted(text):
    assert tech(text, WITH_VALUES) is None


def test_quantity_rule_is_inert_without_observed_values():
    assert tech("The memory limit of 64Mi may have been exceeded.", PLAIN) is None


# ------------------------- "restarting" for a container that restarted before
RESTARTED_READY = TechnicalFacts(
    running_and_ready=True, restart_history=True, authorized_namespace=NS
)


def test_restarting_is_consistent_with_a_restarted_ready_container():
    text = "The container may be restarting due to liveness probe failures."

    assert tech(text, RESTARTED_READY) is None
    # Without recorded restart history the claim still contradicts a ready container.
    assert tech(text, RUNNING) == TECH_CONTRADICTS_EVIDENCE


@pytest.mark.parametrize("text", [
    "The container may be crash-looping.",
    "The container may be failing right now.",
    "The pod is still crashing.",
])
def test_current_failure_is_still_contradicted_for_a_restarted_ready_container(text):
    assert tech(text, RESTARTED_READY) == TECH_CONTRADICTS_EVIDENCE


# ----------------------- "running properly" described as what is NOT happening
NOT_READY_CONTAINER = ContainerFacts(
    running=False, not_ready=True, event_reasons=frozenset(),
    readiness_probe_declared=None, env_none_declared=False, ran_before=True,
)


@pytest.mark.parametrize("text", [
    "A missing dependency may prevent it from running properly.",
    "An incorrect configuration could stop the application from running normally.",
    "The container may be unable to keep working correctly.",
])
def test_running_properly_as_a_described_failure_is_not_a_healthy_claim(text):
    assert lifecycle(text, NOT_READY_CONTAINER) is None


@pytest.mark.parametrize("text", [
    "The application is running properly.",
    "The container is working correctly.",
])
def test_a_plain_healthy_claim_for_a_not_ready_container_is_still_contradicted(text):
    assert lifecycle(text, NOT_READY_CONTAINER) == CONTRADICTS_EVIDENCE
