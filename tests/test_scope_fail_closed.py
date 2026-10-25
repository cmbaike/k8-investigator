"""Scope fails closed: a namespace-wide run needs EXPLICIT broad intent.

A question must either resolve to one named resource (which is then verified
against the namespace listing), or explicitly ask about the namespace as a
whole. Anything else is refused with a fixed clarification, and a named
resource that cannot be found is a limitation, never a wider investigation.
"""

import pytest

from app.tools.investigation_scope import (
    SCOPE_REJECTION_MESSAGES,
    InvestigationScopeCreationError,
    create_bound_investigation_context,
)
from app.tools.workload_target import WorkloadTarget
from tests.test_target_binding_and_readiness import BAD, Cluster, NS, investigate


def bind(question):
    return create_bound_investigation_context(question, namespace=NS)


def refused(question):
    with pytest.raises(InvestigationScopeCreationError) as caught:
        bind(question)

    return caught.value.code


# ------------------------------------------------------------- explicit names


@pytest.mark.parametrize(
    "question, name",
    [
        ("Why is payments-api failing?", "payments-api"),
        ("Investigate payments-api", "payments-api"),
        ("Diagnose memory-hog", "memory-hog"),
        ("Why is bad-readiness not ready?", "bad-readiness"),
    ],
)
def test_explicit_workload_names_bind_a_target(question, name):
    ctx = bind(question)

    assert ctx.target == WorkloadTarget(name, None)


@pytest.mark.parametrize(
    "question, name",
    [
        ("memory-hog keeps crashing", "memory-hog"),
        ("Check checkout", "checkout"),
        ("Why is checkout down?", "checkout"),
    ],
)
def test_resource_names_without_type_nouns_bind_a_target(question, name):
    assert bind(question).target == WorkloadTarget(name, None)


@pytest.mark.parametrize(
    "question",
    [
        "Why is 'payments-api' failing?",
        'Check "payments-api"',
        "Investigate `payments-api`",
    ],
)
def test_quoted_resource_names_bind_the_unquoted_target(question):
    assert bind(question).target == WorkloadTarget("payments-api", None)


@pytest.mark.parametrize(
    "question, name, kind",
    [
        ("Why is deployment/payments-api failing?", "payments-api", "Deployment"),
        ("Investigate statefulset/db-0", "db-0", "StatefulSet"),
        ("Check daemonset/node-agent", "node-agent", "DaemonSet"),
        ("Why is pod/web-1 not ready?", "web-1", "Pod"),
    ],
)
def test_kind_qualified_resource_names_keep_their_kind(question, name, kind):
    assert bind(question).target == WorkloadTarget(name, kind)


# ------------------------------------------------------------- unknown names


def test_an_unknown_workload_name_is_a_limitation_and_inspects_nothing():
    run = investigate("Why is orders-api failing?")

    assert run.snapshot.scope.mode == "workload"
    assert run.snapshot.scope.status == "not_found"
    assert run.cluster.inspected_pods() == set()
    assert any("could not be found" in u for u in run.report.uncertainties)


def test_an_unknown_kind_qualified_name_is_also_a_limitation():
    run = investigate("Why is deployment/orders-api failing?")

    assert run.snapshot.scope.status == "not_found"
    assert run.cluster.inspected_pods() == set()


def test_a_known_name_with_the_wrong_kind_does_not_fall_back_to_the_name():
    run = investigate("Why is statefulset/bad-readiness failing?")

    assert run.snapshot.scope.status == "not_found"
    assert BAD not in run.cluster.inspected_pods()


def test_listing_failure_never_widens_the_scope():
    # An empty namespace listing leaves a named target unresolved.
    run = investigate("Why is payments-api failing?", Cluster([]))

    assert run.snapshot.scope.mode == "workload"
    assert run.snapshot.scope.status in {"unresolved", "not_found"}
    assert run.cluster.inspected_pods() == set()


# ------------------------------------------------------ ambiguous plain language


@pytest.mark.parametrize(
    "question",
    [
        "Why is it failing?",
        "What is wrong?",
        "Any problems?",
        "Why is the pod failing?",
        "What is wrong with this deployment",
        "Check the app",
        "Summarise the problems you can find",
        "Why do I keep seeing errors?",
    ],
)
def test_ambiguous_plain_language_is_refused_with_a_clarification(question):
    assert refused(question) == "scope_unspecified"


def test_the_clarification_is_fixed_text_that_does_not_echo_the_question():
    message = SCOPE_REJECTION_MESSAGES["scope_unspecified"]

    assert "namespace as a whole" in message and "name one workload" in message


# ------------------------------------------------------ explicit platform health


@pytest.mark.parametrize(
    "question",
    [
        "Investigate the health of the platform",
        "Investigate the health of the namespace",
        "Why are the pods failing?",
        "Is anything broken?",
        "Is everything healthy?",
        "Review all workloads",
        "Why is the namespace failing?",
    ],
)
def test_explicit_platform_health_requests_are_namespace_wide(question):
    ctx = bind(question)

    assert ctx.target is None and ctx.broad_scope_explicit is True


def test_an_explicit_broad_run_still_covers_the_namespace_and_says_so():
    run = investigate("Investigate the health of the platform", max_steps=4)

    assert run.snapshot.scope.mode == "namespace"
    assert run.snapshot.scope.broad_explicit is True
    assert len(run.cluster.inspected_pods()) >= 2


# ------------------------------------------------------------- multiple names


@pytest.mark.parametrize(
    "question",
    [
        "Compare payments-api and orders-api",
        "Why are payments-api and orders-api failing?",
        "Check deployment/payments-api and 'orders-api'",
    ],
)
def test_multiple_resource_names_are_refused(question):
    assert refused(question) == "multiple_targets"


def test_a_name_plus_a_request_for_the_rest_is_ambiguous_scope():
    assert refused("Why is payments-api failing, and is everything else ok?") == (
        "ambiguous_scope"
    )


@pytest.mark.parametrize("question", ["Why is payments_api failing?", "Check 'payments.api'"])
def test_names_that_cannot_be_kubernetes_names_are_refused(question):
    assert refused(question) == "invalid_target_name"
