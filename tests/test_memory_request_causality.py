"""A memory REQUEST in the causal role of an OOM kill.

Kubernetes kills a container that exceeds its memory LIMIT (or, under node
memory pressure, evicts or kills pods in an order that depends on requests and
QoS). A request is what the scheduler reserves; an insufficient request is not
by itself what terminates a container. Mentioning the limit in the same
sentence does not change the role the request is given.

Every rule is tested four ways: the incorrect attribution is found (also with
the limit named, and historically phrased); coordinated, valued, negated,
"whether" and node-pressure wording is NOT; a request-only story with no kill
is untouched; and the rule needs the recorded fact only for sentences that do
not themselves mention an OOM.
"""

import pytest

from app.reports.technical_consistency import (
    INCORRECT_SEMANTICS,
    TechnicalFacts,
    technical_violation,
)

NS = "ai-ops-demo"
PLAIN = TechnicalFacts(authorized_namespace=NS)
OOM_RECORDED = TechnicalFacts(authorized_namespace=NS, oom_recorded=True)


def tech(text, facts=PLAIN):
    return technical_violation((text,), facts, cites_logs=True)


# ---------------------------------------------------- the request as the cause
@pytest.mark.parametrize(
    "text",
    [
        # the limit is named, which used to excuse the sentence
        "The container may have been OOMKilled due to an insufficient memory request, despite the 128Mi limit.",
        "An insufficient memory request may be leading to frequent OOMKilled events despite the limit being set to 128Mi.",
        "The memory request of 64Mi is too low, which may explain the OOMKilled termination, even though a limit of 128Mi is set.",
        "The OOMKilled events may result from the memory request being set too small, while the limit is 128Mi.",
        "A memory request that isn't enough may have caused the OOMKilled restart, with the limit at 128Mi.",
        # historical wording does not excuse a wrong attribution
        "The container was OOMKilled earlier, which may have been caused by an insufficient memory request.",
        "The earlier out-of-memory kill may have come from a misconfigured memory request.",
        # no limit mentioned at all
        "The container may have been OOMKilled due to an insufficient memory request.",
        "A memory request that is too low may be causing the out-of-memory kills.",
    ],
)
def test_a_request_made_the_cause_of_an_oom_kill_is_found(text):
    assert tech(text) == INCORRECT_SEMANTICS


@pytest.mark.parametrize(
    "text",
    [
        "The container may have been restarted due to a resource request mismatch.",
        "The container may have been terminated because of an insufficient memory request.",
        "The restart may have been caused by a mismatch between the memory request and the workload's needs.",
    ],
)
def test_the_recorded_oomkilled_fact_covers_a_sentence_that_never_says_oom(text):
    assert tech(text, OOM_RECORDED) == INCORRECT_SEMANTICS
    # Without the recorded fact the sentence is not about an OOM kill.
    assert tech(text, PLAIN) is None


# ----------------------------------------------------------- legitimate wording
@pytest.mark.parametrize(
    "text",
    [
        # the limit is the cause
        "The container may have exceeded its 128Mi memory limit and been OOMKilled.",
        "The memory limit may be too low for the workload, which could explain the OOMKilled termination.",
        # request and limit coordinated: the limit carries the claim
        "The memory request and limit may both be too low, leading to OOMKilled terminations.",
        "The memory request or limit may be misconfigured, which could explain the OOMKilled termination.",
        "An insufficient memory request and limit may be causing the OOMKilled events.",
        "A misconfigured memory limit or request may have led to the OOMKilled restart.",
        # values, not roles
        "The memory request is 64Mi and the limit is 128Mi; the OOMKilled termination may mean the limit was exceeded.",
        # negation, "whether", rule-out
        "The OOMKilled termination is not caused by an insufficient memory request; the limit is what the kernel enforces.",
        "Whether an insufficient memory request contributed to the OOMKilled event has not been established.",
        "An insufficient memory request is unrelated to this OOMKilled termination.",
        # node pressure, eviction, QoS: where requests legitimately matter
        "A low memory request may make this pod an earlier eviction victim under node memory pressure.",
        "A memory request that is too low gives the pod a Burstable class, so it may be killed before others when the node is short of memory.",
        "Overcommitting memory requests on the node may make an OOMKilled event more likely.",
        # historical, and correct
        "The container was OOMKilled earlier, which may have happened because its memory use exceeded the 128Mi limit.",
        "The pod was OOMKilled once; its memory request may have been raised since, which is not shown by the observations.",
        # a request with no kill in the story (scheduling)
        "The pod may be unschedulable because its memory request of 900Gi exceeds node capacity.",
        "The memory request may be too large for any node, which could explain why the pod is Pending.",
    ],
)
def test_legitimate_request_limit_oom_and_pressure_wording_is_accepted(text):
    assert tech(text) is None
    assert tech(text, OOM_RECORDED) is None


@pytest.mark.parametrize(
    "text",
    [
        "The container may have been restarted because the application leaked memory beyond its limit.",
        "The container may have been terminated by the kernel after exceeding its memory limit.",
        "The restart may have followed an OOM event, which is a memory event and not a probe event.",
    ],
)
def test_a_recorded_oom_alone_does_not_make_a_limit_explanation_wrong(text):
    assert tech(text, OOM_RECORDED) is None


def test_the_rule_only_adds_a_rejection_it_never_rewrites_anything():
    text = "The container may have been OOMKilled due to an insufficient memory request, despite the 128Mi limit."

    assert technical_violation((text,), PLAIN, cites_logs=True) == INCORRECT_SEMANTICS
    # A recommended check is not a statement of fact about the container.
    assert technical_violation((text,), PLAIN, cites_logs=True, is_check=True) is None


@pytest.mark.parametrize(
    "text",
    [
        "The memory request is 64Mi, which may not be sufficient, leading to OOMKilled terminations.",
        "The memory request of 64Mi may be too low, which could explain the OOMKilled event.",
    ],
)
def test_a_valued_request_called_insufficient_on_its_own_is_found(text):
    assert tech(text) == INCORRECT_SEMANTICS


def test_a_value_statement_that_names_both_roles_stays_accepted():
    text = (
        "The memory request is 64Mi and the limit is 128Mi, which may not be "
        "sufficient, leading to an OOMKilled termination."
    )

    assert tech(text) is None
